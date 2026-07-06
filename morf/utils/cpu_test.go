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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeTempFile writes content to a temp file and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	return path
}

// withCgroupV2 temporarily replaces cgroupV2Path for the duration of f.
func withCgroupV2(path string, f func()) {
	orig := cgroupV2Path
	cgroupV2Path = path
	defer func() { cgroupV2Path = orig }()
	f()
}

// withCgroupV1 temporarily replaces both cgroup v1 paths for the duration of f.
func withCgroupV1(quotaPath, periodPath string, f func()) {
	origQ := cgroupV1QuotaPath
	origP := cgroupV1PeriodPath
	cgroupV1QuotaPath = quotaPath
	cgroupV1PeriodPath = periodPath
	defer func() {
		cgroupV1QuotaPath = origQ
		cgroupV1PeriodPath = origP
	}()
	f()
}

// resetPaths forces both cgroup path vars to a nonexistent file so neither
// v2 nor v1 fire (simulating "no cgroup limit").
func resetPaths(t *testing.T) (restore func()) {
	t.Helper()
	origV2 := cgroupV2Path
	origQ := cgroupV1QuotaPath
	origP := cgroupV1PeriodPath
	cgroupV2Path = "/does/not/exist/cpu.max"
	cgroupV1QuotaPath = "/does/not/exist/cpu.cfs_quota_us"
	cgroupV1PeriodPath = "/does/not/exist/cpu.cfs_period_us"
	return func() {
		cgroupV2Path = origV2
		cgroupV1QuotaPath = origQ
		cgroupV1PeriodPath = origP
	}
}

// TestCgroupV2_Normal: "200000 100000" → 2.0
func TestCgroupV2_Normal(t *testing.T) {
	path := writeTempFile(t, "cpu.max", "200000 100000\n")
	withCgroupV2(path, func() {
		got, ok := readCgroupV2()
		if !ok {
			t.Fatal("expected ok=true, got false")
		}
		if got != 2.0 {
			t.Fatalf("expected 2.0, got %f", got)
		}
	})
}

// TestCgroupV2_Max: "max 100000" → falls back (ok=false)
func TestCgroupV2_Max(t *testing.T) {
	path := writeTempFile(t, "cpu.max", "max 100000\n")
	withCgroupV2(path, func() {
		_, ok := readCgroupV2()
		if ok {
			t.Fatal("expected ok=false for 'max' quota, got true")
		}
	})
}

// TestCgroupV2_Fractional: "50000 100000" → 0.5
func TestCgroupV2_Fractional(t *testing.T) {
	path := writeTempFile(t, "cpu.max", "50000 100000\n")
	withCgroupV2(path, func() {
		got, ok := readCgroupV2()
		if !ok {
			t.Fatal("expected ok=true, got false")
		}
		if got != 0.5 {
			t.Fatalf("expected 0.5, got %f", got)
		}
	})
}

// TestEffectiveCPUs_V2: EffectiveCPUs reads v2 when available.
func TestEffectiveCPUs_V2(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cgroup paths only relevant on linux")
	}
	path := writeTempFile(t, "cpu.max", "400000 100000\n")
	withCgroupV2(path, func() {
		got := EffectiveCPUs()
		if got != 4.0 {
			t.Fatalf("expected 4.0, got %f", got)
		}
	})
}

// TestEffectiveCPUs_FallbackToNumCPU: when no cgroup files exist, returns NumCPU.
func TestEffectiveCPUs_FallbackToNumCPU(t *testing.T) {
	if runtime.GOOS != "linux" {
		// On non-Linux EffectiveCPUs always returns NumCPU.
		got := EffectiveCPUs()
		if got != float64(runtime.NumCPU()) {
			t.Fatalf("expected %d, got %f", runtime.NumCPU(), got)
		}
		return
	}
	restore := resetPaths(t)
	defer restore()

	got := EffectiveCPUs()
	if got != float64(runtime.NumCPU()) {
		t.Fatalf("expected %d, got %f", runtime.NumCPU(), got)
	}
}

// TestEffectiveCPUs_V1: falls back to v1 when v2 is absent.
func TestEffectiveCPUs_V1(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cgroup paths only relevant on linux")
	}

	quotaPath := writeTempFile(t, "cpu.cfs_quota_us", "300000\n")
	periodPath := writeTempFile(t, "cpu.cfs_period_us", "100000\n")

	// v2 path deliberately missing.
	withCgroupV2("/does/not/exist/cpu.max", func() {
		withCgroupV1(quotaPath, periodPath, func() {
			got := EffectiveCPUs()
			if got != 3.0 {
				t.Fatalf("expected 3.0, got %f", got)
			}
		})
	})
}

// TestMaxProcs_RespectsEnvOverride: when GOMAXPROCS is set, MaxProcs does not change it.
func TestMaxProcs_RespectsEnvOverride(t *testing.T) {
	t.Setenv("GOMAXPROCS", "3")
	before := runtime.GOMAXPROCS(0)
	got := MaxProcs()
	after := runtime.GOMAXPROCS(0)

	// The value returned must equal the current GOMAXPROCS (unchanged).
	if got != before {
		t.Fatalf("MaxProcs returned %d but GOMAXPROCS was %d before call", got, before)
	}
	if after != before {
		t.Fatalf("MaxProcs changed GOMAXPROCS from %d to %d when env was set", before, after)
	}
}

// TestMaxProcs_ClampToOne: even with a fractional limit, MaxProcs returns >=1.
func TestMaxProcs_ClampToOne(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cgroup override only meaningful on linux")
	}
	t.Setenv("GOMAXPROCS", "")

	// 50000/100000 = 0.5 → rounds to 1.
	path := writeTempFile(t, "cpu.max", "50000 100000\n")
	withCgroupV2(path, func() {
		got := MaxProcs()
		if got < 1 {
			t.Fatalf("MaxProcs returned %d, want >=1", got)
		}
	})
}

// TestMaxProcs_AtLeastOne: always returns >=1 regardless of platform.
func TestMaxProcs_AtLeastOne(t *testing.T) {
	// Unset any env override so MaxProcs runs its logic.
	t.Setenv("GOMAXPROCS", "")
	restore := resetPaths(t)
	defer restore()

	got := MaxProcs()
	if got < 1 {
		t.Fatalf("MaxProcs returned %d, want >=1", got)
	}
	_ = fmt.Sprintf("MaxProcs=%d", got) // avoid import error
}
