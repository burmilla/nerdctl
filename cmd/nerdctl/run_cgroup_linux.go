/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/docker/go-units"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type customMemoryOptions struct {
	MemoryReservation *int64
	MemorySwappiness  *uint64
	disableOOMKiller  *bool
}

func generateCgroupOpts(cmd *cobra.Command, globalOptions types.GlobalCommandOptions, id string) ([]oci.SpecOpts, error) {
	cpus, err := cmd.Flags().GetFloat64("cpus")
	if err != nil {
		return nil, err
	}
	memStr, err := cmd.Flags().GetString("memory")
	if err != nil {
		return nil, err
	}
	memSwap, err := cmd.Flags().GetString("memory-swap")
	if err != nil {
		return nil, err
	}

	memSwappiness64, err := cmd.Flags().GetInt64("memory-swappiness")
	if err != nil {
		return nil, err
	}
	kernelMemStr, err := cmd.Flags().GetString("kernel-memory")
	if err != nil {
		return nil, err
	}
	if kernelMemStr != "" && cmd.Flag("kernel-memory").Changed {
		logrus.Warnf("The --kernel-memory flag is no longer supported. This flag is a noop.")
	}

	memReserve, err := cmd.Flags().GetString("memory-reservation")
	if err != nil {
		return nil, err
	}

	okd, err := cmd.Flags().GetBool("oom-kill-disable")
	if err != nil {
		return nil, err
	}
	if memStr == "" && okd {
		logrus.Warn("Disabling the OOM killer on containers without setting a '-m/--memory' limit may be dangerous.")
	}

	pidsLimit, err := cmd.Flags().GetInt64("pids-limit")
	if err != nil {
		return nil, err
	}

	parent, err := cmd.Flags().GetString("cgroup-parent")
	if err != nil {
		return nil, err
	}

	if globalOptions.CgroupManager == "none" {
		return nil, errors.New(`cgroup-manager "none" is only supported for rootless`)
	}

	var opts []oci.SpecOpts // nolint: prealloc
	path, err := generateCgroupPath(cmd, globalOptions.CgroupManager, parent, id)
	if err != nil {
		return nil, err
	}
	if path != "" {
		opts = append(opts, oci.WithCgroup(path))
	}

	// cpus: from https://github.com/containerd/containerd/blob/v1.4.3/cmd/ctr/commands/run/run_unix.go#L187-L193
	if cpus > 0.0 {
		var (
			period = uint64(100000)
			quota  = int64(cpus * 100000.0)
		)
		opts = append(opts, oci.WithCPUCFS(quota, period))
	}

	shares, err := cmd.Flags().GetUint64("cpu-shares")
	if err != nil {
		return nil, err
	}
	if shares != 0 {
		opts = append(opts, oci.WithCPUShares(shares))
	}

	cpuset, err := cmd.Flags().GetString("cpuset-cpus")
	if err != nil {
		return nil, err
	}
	if cpuset != "" {
		opts = append(opts, oci.WithCPUs(cpuset))
	}
	cpuQuota, err := cmd.Flags().GetInt64("cpu-quota")
	if err != nil {
		return nil, err
	}
	cpuPeriod, err := cmd.Flags().GetUint64("cpu-period")
	if err != nil {
		return nil, err
	}
	if cpuQuota != -1 || cpuPeriod != 0 {
		if cpus > 0.0 {
			return nil, errors.New("cpus and quota/period should be used separately")
		}
		opts = append(opts, oci.WithCPUCFS(cpuQuota, cpuPeriod))
	}
	cpusetMems, err := cmd.Flags().GetString("cpuset-mems")
	if err != nil {
		return nil, err
	}
	if cpusetMems != "" {
		opts = append(opts, oci.WithCPUsMems(cpusetMems))
	}

	var mem64 int64
	if memStr != "" {
		mem64, err = units.RAMInBytes(memStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse memory bytes %q: %w", memStr, err)
		}
		opts = append(opts, oci.WithMemoryLimit(uint64(mem64)))
	}

	var memReserve64 int64
	if memReserve != "" {
		memReserve64, err = units.RAMInBytes(memReserve)
		if err != nil {
			return nil, fmt.Errorf("failed to parse memory bytes %q: %w", memReserve, err)
		}
	}
	var memSwap64 int64
	if memSwap != "" {
		if memSwap == "-1" {
			memSwap64 = -1
		} else {
			memSwap64, err = units.RAMInBytes(memSwap)
			if err != nil {
				return nil, fmt.Errorf("failed to parse memory-swap bytes %q: %w", memSwap, err)
			}
			if mem64 > 0 && memSwap64 > 0 && memSwap64 < mem64 {
				return nil, fmt.Errorf("minimum memoryswap limit should be larger than memory limit, see usage")
			}
		}
	} else {
		// if `--memory-swap` is unset, the container can use as much swap as the `--memory` setting.
		memSwap64 = mem64 * 2
	}
	if memSwap64 == 0 {
		// if --memory-swap is set to 0, the setting is ignored, and the value is treated as unset.
		memSwap64 = mem64 * 2
	}
	if memSwap64 != 0 {
		opts = append(opts, oci.WithMemorySwap(memSwap64))
	}
	if mem64 > 0 && memReserve64 > 0 && mem64 < memReserve64 {
		return nil, fmt.Errorf("minimum memory limit can not be less than memory reservation limit, see usage")
	}
	if memSwappiness64 > 100 || memSwappiness64 < -1 {
		return nil, fmt.Errorf("invalid value: %v, valid memory swappiness range is 0-100", memSwappiness64)
	}

	var customMemRes customMemoryOptions
	if memReserve64 >= 0 && cmd.Flags().Changed("memory-reservation") {
		customMemRes.MemoryReservation = &memReserve64
	}
	if memSwappiness64 >= 0 && cmd.Flags().Changed("memory-swappiness") {
		memSwapinessUint64 := uint64(memSwappiness64)
		customMemRes.MemorySwappiness = &memSwapinessUint64
	}
	if okd {
		customMemRes.disableOOMKiller = &okd
	}
	opts = append(opts, withCustomMemoryResources(customMemRes))

	if pidsLimit > 0 {
		opts = append(opts, oci.WithPidsLimit(pidsLimit))
	}

	cgroupConf, err := cmd.Flags().GetStringSlice("cgroup-conf")
	if err != nil {
		return nil, err
	}

	unifieds := make(map[string]string)
	for _, unified := range cgroupConf {
		splitUnified := strings.SplitN(unified, "=", 2)
		if len(splitUnified) < 2 {
			return nil, errors.New("--cgroup-conf must be formatted KEY=VALUE")
		}
		unifieds[splitUnified[0]] = splitUnified[1]
	}
	opts = append(opts, withUnified(unifieds))

	blkioWeight, err := cmd.Flags().GetUint16("blkio-weight")
	if err != nil {
		return nil, err
	}
	if blkioWeight > 0 && blkioWeight < 10 || blkioWeight > 1000 {
		return nil, errors.New("range of blkio weight is from 10 to 1000")
	}
	opts = append(opts, withBlkioWeight(blkioWeight))

	cgroupns, err := cmd.Flags().GetString("cgroupns")
	if err != nil {
		return nil, err
	}
	switch cgroupns {
	case "private":
		ns := specs.LinuxNamespace{
			Type: specs.CgroupNamespace,
		}
		opts = append(opts, oci.WithLinuxNamespace(ns))
	case "host":
		opts = append(opts, oci.WithHostNamespace(specs.CgroupNamespace))
	default:
		return nil, fmt.Errorf("unknown cgroupns mode %q", cgroupns)
	}

	device, err := cmd.Flags().GetStringSlice("device")
	if err != nil {
		return nil, err
	}
	for _, f := range device {
		devPath, mode, err := parseDevice(f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse device %q: %w", f, err)
		}
		opts = append(opts, oci.WithLinuxDevice(devPath, mode))
	}
	return opts, nil
}

func generateCgroupPath(cmd *cobra.Command, cgroupManager, parent, id string) (string, error) {
	var (
		path         string
		usingSystemd = cgroupManager == "systemd"
		slice        = "system.slice"
		scopePrefix  = ":nerdctl:"
	)

	if parent == "" {
		if usingSystemd {
			// "slice:prefix:name"
			path = slice + scopePrefix + id
		}
		// Nothing to do for the non-systemd case if a parent wasn't supplied,
		// containerd already sets a default cgroup path as /<namespace>/<containerID>
		return path, nil
	}

	// If the user asked for a cgroup parent and we're using systemd,
	// Docker uses the following:
	// parent + prefix (in our case, nerdctl) + containerID.
	//
	// In the non systemd case, it's just /parent/containerID
	if usingSystemd {
		if len(parent) <= 6 || !strings.HasSuffix(parent, ".slice") {
			return "", errors.New(`cgroup-parent for systemd cgroup should be a valid slice named as "xxx.slice"`)
		}
		path = parent + scopePrefix + id
	} else {
		path = filepath.Join(parent, id)
	}

	return path, nil
}

func parseDevice(s string) (hostDevPath string, mode string, err error) {
	mode = "rwm"
	split := strings.Split(s, ":")
	var containerDevPath string
	switch len(split) {
	case 1: // e.g. "/dev/sda1"
		hostDevPath = split[0]
		containerDevPath = hostDevPath
	case 2: // e.g., "/dev/sda1:rwm", or "/dev/sda1:/dev/sda1
		hostDevPath = split[0]
		if !strings.Contains(split[1], "/") {
			containerDevPath = hostDevPath
			mode = split[1]
		} else {
			containerDevPath = split[1]
		}
	case 3: // e.g., "/dev/sda1:/dev/sda1:rwm"
		hostDevPath = split[0]
		containerDevPath = split[1]
		mode = split[2]
	default:
		return "", "", errors.New("too many `:` symbols")
	}

	if containerDevPath != hostDevPath {
		return "", "", errors.New("changing the path inside the container is not supported yet")
	}

	if !filepath.IsAbs(hostDevPath) {
		return "", "", fmt.Errorf("%q is not an absolute path", hostDevPath)
	}

	if err := validateDeviceMode(mode); err != nil {
		return "", "", err
	}
	return hostDevPath, mode, nil
}

func validateDeviceMode(mode string) error {
	for _, r := range mode {
		switch r {
		case 'r', 'w', 'm':
		default:
			return fmt.Errorf("invalid mode %q: unexpected rune %v", mode, r)
		}
	}
	return nil
}

func withUnified(unified map[string]string) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) (err error) {
		if unified == nil {
			return nil
		}
		s.Linux.Resources.Unified = make(map[string]string)
		for k, v := range unified {
			s.Linux.Resources.Unified[k] = v
		}
		return nil
	}
}

func withBlkioWeight(blkioWeight uint16) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if blkioWeight == 0 {
			return nil
		}
		s.Linux.Resources.BlockIO = &specs.LinuxBlockIO{Weight: &blkioWeight}
		return nil
	}
}

func withCustomMemoryResources(memoryOptions customMemoryOptions) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux != nil {
			if s.Linux.Resources == nil {
				s.Linux.Resources = &specs.LinuxResources{}
			}
			if s.Linux.Resources.Memory == nil {
				s.Linux.Resources.Memory = &specs.LinuxMemory{}
			}
			if memoryOptions.disableOOMKiller != nil {
				s.Linux.Resources.Memory.DisableOOMKiller = memoryOptions.disableOOMKiller
			}
			if memoryOptions.MemorySwappiness != nil {
				s.Linux.Resources.Memory.Swappiness = memoryOptions.MemorySwappiness
			}
			if memoryOptions.MemoryReservation != nil {
				s.Linux.Resources.Memory.Reservation = memoryOptions.MemoryReservation
			}
		}
		return nil
	}
}
