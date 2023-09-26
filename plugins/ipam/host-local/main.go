// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
)

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("host-local"))
}

func cmdCheck(args *skel.CmdArgs) error {
	ipamConf, _, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Look to see if there is at least one IP address allocated to the container
	// in the data dir, irrespective of what that address actually is
	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	containerIPFound := store.FindByID(args.ContainerID, args.IfName)
	if !containerIPFound {
		return fmt.Errorf("host-local: Failed to find address added by container %v", args.ContainerID)
	}

	return nil
}

const (
	defaultFixedIPBaseDir      = "/var/lib/cni/networks"
	fixedIPLogFile             = "fixed_ip.log"
	fixedIPSubDir              = "fixed_ip"
	defaultFixedIPDuration     = time.Hour
	enableFixedIPAnnotations   = "enable-fixed-ip"
	fixedIPDurationAnnotations = "fixed-ip-duration"
)

type podMeta struct {
	Namespace string
	Name      string
}

func getPodMeta(args string) *podMeta {
	podMeta := &podMeta{}
	items := strings.Split(args, ";")
	for _, item := range items {
		if strings.Contains(item, "K8S_POD_NAMESPACE=") {
			parts := strings.Split(item, "=")
			podMeta.Namespace = parts[1]
			continue
		}
		if strings.Contains(item, "K8S_POD_NAME=") {
			parts := strings.Split(item, "=")
			podMeta.Name = parts[1]
		}
	}
	return podMeta
}

type fixedIPInfo struct {
	ID         string              `json:"ID"`
	IfName     string              `json:"ifName"`
	IPs        []*current.IPConfig `json:"ips"`
	Duration   time.Duration       `json:"duration"`
	ReleasedAt *time.Time          `json:"released_at"`
}

func getFixedIPInfoFromFile(file string) (*fixedIPInfo, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	fixedIPInfo := &fixedIPInfo{}
	if err := json.Unmarshal(data, fixedIPInfo); err != nil {
		return nil, err
	}
	return fixedIPInfo, nil
}

func setFixedIPInfoToFile(file string, fixedIPInfo *fixedIPInfo) error {
	data, err := json.Marshal(fixedIPInfo)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, data, 0644)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0644); err != nil {
		return err
	}
	err = ioutil.WriteFile(file, data, 0644)
	return err
}

func fixedIPLog(file string, format string, args ...interface{}) {
	osFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0644); err != nil {
			return
		}
		osFile, err = os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return
		}
	}
	defer osFile.Close()
	msg := fmt.Sprintf(format+"\r\n", args...)
	osFile.WriteString(msg)
}

func releaseExpiredFixedIP(baseDir string, conf *allocator.IPAMConfig) {
	dir := filepath.Join(baseDir, fixedIPSubDir)
	fixedIPLogFile := filepath.Join(baseDir, fixedIPLogFile)
	now := time.Now()
	if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		fixedIPInfo, err := getFixedIPInfoFromFile(info.Name())
		if err != nil {
			fixedIPLog(fixedIPLogFile, "[releaseExpiredFixedIP] failed to getFixedIPInfoFromFile, got err:%+v for name:%s", err, info.Name())
			return nil
		}
		if fixedIPInfo == nil {
			return nil
		}
		if fixedIPInfo.ReleasedAt == nil || fixedIPInfo.ReleasedAt.Add(fixedIPInfo.Duration).After(now) {
			return nil
		}
		if err := doRelease(fixedIPInfo.ID, fixedIPInfo.IfName, conf); err != nil {
			fixedIPLog(fixedIPLogFile, "[releaseExpiredFixedIP] failed to doRelease,got err:%+v for name:%s id:%s ifName:%s", err, info.Name(), fixedIPInfo.ID, fixedIPInfo.IfName)
		}
		return nil
	}); err != nil {
		fixedIPLog(fixedIPLogFile, "[releaseExpiredFixedIP] failed to Walk,got err:%+v for dir:%s", err, dir)
	}
}

func doRelease(id, ifName string, conf *allocator.IPAMConfig) error {
	store, err := disk.New(conf.Name, conf.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	// Loop through all ranges, releasing all IPs, even if an error occurs
	for idx, rangeset := range conf.Ranges {
		ipAllocator := allocator.NewIPAllocator(&rangeset, store, idx)
		err = ipAllocator.Release(id, ifName)
		if err != nil {
			return err
		}
	}
	return nil

}

func cmdAdd(args *skel.CmdArgs) error {
	ipamConf, confVersion, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}

	if ipamConf.ResolvConf != "" {
		dns, err := parseResolvConf(ipamConf.ResolvConf)
		if err != nil {
			return err
		}
		result.DNS = *dns
	}
	fixedIPDir := ipamConf.DataDir
	if fixedIPDir == "" {
		fixedIPDir = defaultFixedIPBaseDir
	}

	podMeta := getPodMeta(args.Args)
	podFixedIPDir := filepath.Join(fixedIPDir, fixedIPSubDir, podMeta.Namespace)
	podFixedIPFile := filepath.Join(podFixedIPDir, podMeta.Name)
	var enableFixedIP bool
	var fixedIPDuration time.Duration

	releaseExpiredFixedIP(fixedIPDir, ipamConf)

	if ipamConf.PodAnnotations != nil {
		enableFixedIPStr := ipamConf.PodAnnotations[enableFixedIPAnnotations]
		fixedIPDurationStr := ipamConf.PodAnnotations[fixedIPDurationAnnotations]
		fixedIPDuration, _ = time.ParseDuration(fixedIPDurationStr)
		if fixedIPDuration <= 0 {
			fixedIPDuration = defaultFixedIPDuration
		}
		enableFixedIP, _ = strconv.ParseBool(enableFixedIPStr)

		if enableFixedIP && podMeta.Namespace != "" && podMeta.Name != "" {
			fixedIPInfo, err := getFixedIPInfoFromFile(podFixedIPFile)
			if err != nil {
				return err
			}
			if fixedIPInfo != nil {
				result.IPs = fixedIPInfo.IPs
				result.Routes = ipamConf.Routes
				fixedIPInfo.ReleasedAt = nil
				if err := setFixedIPInfoToFile(podFixedIPFile, fixedIPInfo); err != nil {
					return err
				}
				return types.PrintResult(result, confVersion)
			}
		}
	}

	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	// Keep the allocators we used, so we can release all IPs if an error
	// occurs after we start allocating
	allocs := []*allocator.IPAllocator{}

	// Store all requested IPs in a map, so we can easily remove ones we use
	// and error if some remain
	requestedIPs := map[string]net.IP{} // net.IP cannot be a key

	for _, ip := range ipamConf.IPArgs {
		requestedIPs[ip.String()] = ip
	}

	for idx, rangeset := range ipamConf.Ranges {
		allocator := allocator.NewIPAllocator(&rangeset, store, idx)

		// Check to see if there are any custom IPs requested in this range.
		var requestedIP net.IP
		for k, ip := range requestedIPs {
			if rangeset.Contains(ip) {
				requestedIP = ip
				delete(requestedIPs, k)
				break
			}
		}

		ipConf, err := allocator.Get(args.ContainerID, args.IfName, requestedIP)
		if err != nil {
			// Deallocate all already allocated IPs
			for _, alloc := range allocs {
				_ = alloc.Release(args.ContainerID, args.IfName)
			}
			return fmt.Errorf("failed to allocate for range %d: %v", idx, err)
		}

		allocs = append(allocs, allocator)

		result.IPs = append(result.IPs, ipConf)
	}

	// If an IP was requested that wasn't fulfilled, fail
	if len(requestedIPs) != 0 {
		for _, alloc := range allocs {
			_ = alloc.Release(args.ContainerID, args.IfName)
		}
		errstr := "failed to allocate all requested IPs:"
		for _, ip := range requestedIPs {
			errstr = errstr + " " + ip.String()
		}
		return fmt.Errorf(errstr)
	}
	if enableFixedIP && podMeta.Namespace != "" && podMeta.Name != "" {
		fixedIPInfo := &fixedIPInfo{IPs: result.IPs, Duration: fixedIPDuration, ID: args.ContainerID, IfName: args.IfName}
		if err := setFixedIPInfoToFile(podFixedIPFile, fixedIPInfo); err != nil {
			return err
		}
	}

	result.Routes = ipamConf.Routes

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	ipamConf, _, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	fixedIPDir := ipamConf.DataDir
	if fixedIPDir == "" {
		fixedIPDir = defaultFixedIPBaseDir
	}
	podMeta := getPodMeta(args.Args)
	podFixedIPDir := path.Join(fixedIPDir, fixedIPSubDir, podMeta.Namespace)
	podFixedIPFile := path.Join(podFixedIPDir, podMeta.Name)
	var enableFixedIP bool
	var fixedIPDuration time.Duration

	if ipamConf.PodAnnotations != nil {
		enableFixedIPStr := ipamConf.PodAnnotations[enableFixedIPAnnotations]
		fixedIPDurationStr := ipamConf.PodAnnotations[fixedIPDurationAnnotations]
		fixedIPDuration, _ = time.ParseDuration(fixedIPDurationStr)
		if fixedIPDuration <= 0 {
			fixedIPDuration = defaultFixedIPDuration
		}
		enableFixedIP, _ = strconv.ParseBool(enableFixedIPStr)

		if enableFixedIP && podMeta.Namespace != "" && podMeta.Name != "" {
			fixedIPInfo, err := getFixedIPInfoFromFile(podFixedIPFile)
			if err != nil {
				return err
			}
			if fixedIPInfo != nil {
				now := time.Now()
				fixedIPInfo.ReleasedAt = &now
				if err := setFixedIPInfoToFile(podFixedIPFile, fixedIPInfo); err != nil {
					return err
				}
				return nil
			}
		}
	}

	store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	// Loop through all ranges, releasing all IPs, even if an error occurs
	var errors []string
	for idx, rangeset := range ipamConf.Ranges {
		ipAllocator := allocator.NewIPAllocator(&rangeset, store, idx)

		err := ipAllocator.Release(args.ContainerID, args.IfName)
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	if errors != nil {
		return fmt.Errorf(strings.Join(errors, ";"))
	}
	return nil
}
