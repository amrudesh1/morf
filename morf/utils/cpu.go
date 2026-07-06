/*
Copyright [2023] [Amrudesh Balakrishnan]

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

package utils

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// cgroupV2Path is the cgroup v2 cpu.max file. Overridable in tests.
var cgroupV2Path = "/sys/fs/cgroup/cpu.max"

// cgroupV1QuotaPath is the cgroup v1 quota file. Overridable in tests.
var cgroupV1QuotaPath = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"

// cgroupV1PeriodPath is the cgroup v1 period file. Overridable in tests.
var cgroupV1PeriodPath = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"

// EffectiveCPUs returns the CPU limit the process is actually allowed to use,
// honoring Linux cgroup quotas. Returns a float (e.g. 2.5). Falls back to
// runtime.NumCPU() when no cgroup limit is found or not on Linux.
func EffectiveCPUs() float64 {
	if runtime.GOOS != "linux" {
		return float64(runtime.NumCPU())
	}

	// Try cgroup v2 first.
	if cpus, ok := readCgroupV2(); ok {
		return cpus
	}

	// Fall back to cgroup v1.
	if cpus, ok := readCgroupV1(); ok {
		return cpus
	}

	return float64(runtime.NumCPU())
}

// readCgroupV2 parses /sys/fs/cgroup/cpu.max (or the test override).
// Format: "<quota> <period>" where quota may be "max" (unlimited).
func readCgroupV2() (float64, bool) {
	data, err := os.ReadFile(cgroupV2Path)
	if err != nil {
		return 0, false
	}

	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 2 {
		return 0, false
	}

	if fields[0] == "max" {
		// Unlimited — no cgroup constraint.
		return 0, false
	}

	quota, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || quota <= 0 {
		return 0, false
	}

	period, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || period <= 0 {
		return 0, false
	}

	return quota / period, true
}

// readCgroupV1 parses the cgroup v1 quota and period files.
// quota <= 0 means unlimited.
func readCgroupV1() (float64, bool) {
	quotaData, err := os.ReadFile(cgroupV1QuotaPath)
	if err != nil {
		return 0, false
	}

	periodData, err := os.ReadFile(cgroupV1PeriodPath)
	if err != nil {
		return 0, false
	}

	quota, err := strconv.ParseFloat(strings.TrimSpace(string(quotaData)), 64)
	if err != nil || quota <= 0 {
		return 0, false
	}

	period, err := strconv.ParseFloat(strings.TrimSpace(string(periodData)), 64)
	if err != nil || period <= 0 {
		return 0, false
	}

	return quota / period, true
}

// MaxProcs sets runtime.GOMAXPROCS to max(1, round(EffectiveCPUs())) and
// returns the value set. Safe to call once at startup. Honors an explicit
// GOMAXPROCS env override (if set, do nothing / respect it).
func MaxProcs() int {
	if val := os.Getenv("GOMAXPROCS"); val != "" {
		// An explicit override is set; leave GOMAXPROCS as-is.
		n, err := strconv.Atoi(val)
		if err == nil && n >= 1 {
			return runtime.GOMAXPROCS(0) // return current value without changing it
		}
	}

	cpus := EffectiveCPUs()
	n := int(math.Round(cpus))
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
	return n
}
