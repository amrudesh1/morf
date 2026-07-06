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
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// Default APK safety limits used by CheckAPKSafe.
	// They are tuned for pre-decompilation gate use (tighter, env-overridable).
	defaultAPKMaxEntries          = 100_000
	defaultAPKMaxTotalUncompBytes = 4 * 1024 * 1024 * 1024 // 4 GiB
	defaultAPKMaxRatio            = 200.0
	// defaultAPKMaxEntryUncompBytes bounds the declared uncompressed size of any
	// SINGLE central-directory entry, independent of the cumulative total. A single
	// entry larger than this is treated as a zip bomb even if the running total has
	// not yet tripped the aggregate cap.
	defaultAPKMaxEntryUncompBytes = 500 * 1024 * 1024 // 500 MiB
)

// APKMaxEntries is the maximum number of zip central-directory entries allowed
// in an APK before CheckAPKSafe rejects it. Override via MORF_ZIP_MAX_ENTRIES.
var APKMaxEntries int64 = defaultAPKMaxEntries

// APKMaxTotalUncompressed is the maximum allowed sum of UncompressedSize64
// across all central-directory entries (bytes). Override via MORF_ZIP_MAX_TOTAL_UNCOMPRESSED.
var APKMaxTotalUncompressed int64 = defaultAPKMaxTotalUncompBytes

// APKMaxRatio is the maximum allowed compression ratio (uncompressed/compressed),
// checked both per-entry and overall. Override via MORF_ZIP_MAX_RATIO.
var APKMaxRatio float64 = defaultAPKMaxRatio

// APKMaxEntryUncompressed is the maximum allowed declared UncompressedSize64 for a
// single entry (bytes). Override via MORF_ZIP_MAX_ENTRY_UNCOMPRESSED.
var APKMaxEntryUncompressed int64 = defaultAPKMaxEntryUncompBytes

func init() {
	if v := os.Getenv("MORF_ZIP_MAX_ENTRIES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			APKMaxEntries = n
		}
	}
	if v := os.Getenv("MORF_ZIP_MAX_TOTAL_UNCOMPRESSED"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			APKMaxTotalUncompressed = n
		}
	}
	if v := os.Getenv("MORF_ZIP_MAX_RATIO"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			APKMaxRatio = f
		}
	}
	if v := os.Getenv("MORF_ZIP_MAX_ENTRY_UNCOMPRESSED"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			APKMaxEntryUncompressed = n
		}
	}
}

// CheckAPKSafe is the pre-decompilation zip-bomb guard for APK files.
//
// An APK is a zip archive; this function opens it via archive/zip and inspects
// the central directory only — NO actual decompression is performed, so it is
// safe to call on arbitrarily large (or malicious) inputs.
//
// It rejects the file with a descriptive error when any of these bounds are
// exceeded (all three limits are package-level vars overridable via env):
//
//   - Entry count  > APKMaxEntries       (env: MORF_ZIP_MAX_ENTRIES,          default 100 000)
//   - Total uncompressed size > APKMaxTotalUncompressed
//     (env: MORF_ZIP_MAX_TOTAL_UNCOMPRESSED, default 4 GiB)
//   - Compression ratio (uncompressed/compressed) > APKMaxRatio, checked both
//     per-entry and overall  (env: MORF_ZIP_MAX_RATIO,               default 200×)
//   - Single-entry uncompressed size > APKMaxEntryUncompressed
//     (env: MORF_ZIP_MAX_ENTRY_UNCOMPRESSED, default 500 MiB)
//   - Entry names that are absolute or contain a ".." traversal segment (Zip-Slip)
//
// Returns nil when the file passes all checks and is considered safe to hand
// to the decompiler.  Returns a non-nil error for invalid/missing files too.
func CheckAPKSafe(apkPath string) error {
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("CheckAPKSafe: cannot open %q as zip: %w", apkPath, err)
	}
	defer r.Close()

	entryCount := int64(len(r.File))
	if entryCount > APKMaxEntries {
		return fmt.Errorf("CheckAPKSafe: entry count %d exceeds limit %d (zip bomb suspected)", entryCount, APKMaxEntries)
	}

	var totalUncomp, totalComp int64
	for _, f := range r.File {
		// Zip-Slip sanitization: reject entry names that are absolute or escape the
		// extraction root via a ".." segment, BEFORE any later stage trusts f.Name
		// to build an on-disk path. archive/zip stores forward-slash paths.
		if filepath.IsAbs(f.Name) || strings.HasPrefix(f.Name, "/") || strings.HasPrefix(f.Name, "\\") {
			return fmt.Errorf("CheckAPKSafe: entry %q has an absolute path (zip-slip suspected)", f.Name)
		}
		cleaned := filepath.ToSlash(filepath.Clean(f.Name))
		if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
			return fmt.Errorf("CheckAPKSafe: entry %q contains a parent-directory (\"..\") segment (zip-slip suspected)", f.Name)
		}

		unc := int64(f.UncompressedSize64)
		cmp := int64(f.CompressedSize64)

		// Per-entry absolute uncompressed-size cap: a single entry larger than the
		// limit is a zip bomb regardless of the cumulative total or its ratio.
		if unc > APKMaxEntryUncompressed {
			return fmt.Errorf(
				"CheckAPKSafe: entry %q declares uncompressed size %d bytes, exceeds per-entry limit %d bytes (zip bomb suspected)",
				f.Name, unc, APKMaxEntryUncompressed,
			)
		}

		// Per-entry ratio check (skip entries stored without compression or
		// with a zero compressed size to avoid divide-by-zero).
		if cmp > 0 && unc > 0 {
			ratio := float64(unc) / float64(cmp)
			if ratio > APKMaxRatio {
				return fmt.Errorf(
					"CheckAPKSafe: entry %q has compression ratio %.1f:1, exceeds limit %.1f:1 (zip bomb suspected)",
					f.Name, ratio, APKMaxRatio,
				)
			}
		}

		totalUncomp += unc
		totalComp += cmp

		// Running total size check (fail-fast).
		if totalUncomp > APKMaxTotalUncompressed {
			return fmt.Errorf(
				"CheckAPKSafe: cumulative uncompressed size %d bytes exceeds limit %d bytes (zip bomb suspected)",
				totalUncomp, APKMaxTotalUncompressed,
			)
		}
	}

	// Overall ratio check.
	if totalComp > 0 && totalUncomp > 0 {
		overallRatio := float64(totalUncomp) / float64(totalComp)
		if overallRatio > APKMaxRatio {
			return fmt.Errorf(
				"CheckAPKSafe: overall compression ratio %.1f:1 exceeds limit %.1f:1 (zip bomb suspected)",
				overallRatio, APKMaxRatio,
			)
		}
	}

	log.WithFields(log.Fields{
		"path":               apkPath,
		"entries":            entryCount,
		"total_uncompressed": totalUncomp,
		"total_compressed":   totalComp,
	}).Debug("CheckAPKSafe: APK passed all zip-bomb checks")

	return nil
}
