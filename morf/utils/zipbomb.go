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
	"io"
	"os"
	"path/filepath"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	// MaxDecompressedSize is the maximum total size of decompressed files (10GB)
	MaxDecompressedSize = 10 * 1024 * 1024 * 1024
	// MaxCompressionRatio is the maximum compression ratio (1000:1) to detect zip bombs
	MaxCompressionRatio = 1000

	// Default APK safety limits used by CheckAPKSafe.
	// These differ from the older CheckZipBomb constants intentionally:
	// they are tuned for pre-decompilation gate use (tighter, env-overridable).
	defaultAPKMaxEntries          = 100_000
	defaultAPKMaxTotalUncompBytes = 4 * 1024 * 1024 * 1024 // 4 GiB
	defaultAPKMaxRatio            = 200.0
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
		unc := int64(f.UncompressedSize64)
		cmp := int64(f.CompressedSize64)

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

// CheckZipBomb checks if a ZIP/APK file is a potential zip bomb
// Returns error if zip bomb is detected, nil otherwise
func CheckZipBomb(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer reader.Close()

	var totalDecompressedSize int64
	var totalCompressedSize int64

	for _, file := range reader.File {
		// Check compression ratio
		if file.UncompressedSize64 > 0 && file.CompressedSize64 > 0 {
			ratio := float64(file.UncompressedSize64) / float64(file.CompressedSize64)
			if ratio > MaxCompressionRatio {
				log.WithFields(log.Fields{
					"file":  file.Name,
					"ratio": ratio,
					"limit": MaxCompressionRatio,
				}).Warn("Suspicious compression ratio detected")
				return fmt.Errorf("zip bomb detected: suspicious compression ratio (%.2f:1) in file %s", ratio, file.Name)
			}
		}

		// Accumulate sizes
		totalDecompressedSize += int64(file.UncompressedSize64)
		totalCompressedSize += int64(file.CompressedSize64)

		// Check total decompressed size
		if totalDecompressedSize > MaxDecompressedSize {
			return fmt.Errorf("zip bomb detected: total decompressed size (%d bytes) exceeds limit (%d bytes)", totalDecompressedSize, MaxDecompressedSize)
		}
	}

	log.WithFields(log.Fields{
		"compressed_size":   totalCompressedSize,
		"decompressed_size": totalDecompressedSize,
		"ratio":             float64(totalDecompressedSize) / float64(totalCompressedSize+1),
	}).Debug("Zip file validation passed")

	return nil
}

// MonitorDecompression monitors decompression to prevent zip bombs
// Returns a function to check current decompressed size
func MonitorDecompression(maxSize int64) (func(int64) error, func()) {
	var currentSize int64
	var checkFunc = func(addSize int64) error {
		currentSize += addSize
		if currentSize > maxSize {
			return fmt.Errorf("decompressed size (%d bytes) exceeds limit (%d bytes)", currentSize, maxSize)
		}
		return nil
	}
	var resetFunc = func() {
		currentSize = 0
	}
	return checkFunc, resetFunc
}

// ValidateDecompressedPath validates that a decompressed path is within allowed directory
func ValidateDecompressedPath(destPath, allowedBase string) error {
	absDest, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %v", err)
	}

	absBase, err := filepath.Abs(allowedBase)
	if err != nil {
		return fmt.Errorf("failed to resolve base path: %v", err)
	}

	rel, err := filepath.Rel(absBase, absDest)
	if err != nil {
		return fmt.Errorf("path validation failed: %v", err)
	}

	if rel == ".." || len(rel) >= 3 && rel[:3] == "../" {
		return fmt.Errorf("path traversal detected: %s", destPath)
	}

	return nil
}

// SafeExtract extracts files from a zip with zip bomb protection
func SafeExtract(zipPath, destDir string) error {
	// Check zip bomb before extraction
	if err := CheckZipBomb(zipPath); err != nil {
		return err
	}

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer reader.Close()

	checkSize, resetSize := MonitorDecompression(MaxDecompressedSize)
	defer resetSize()

	for _, file := range reader.File {
		// Validate path
		destPath := filepath.Join(destDir, file.Name)
		if err := ValidateDecompressedPath(destPath, destDir); err != nil {
			return err
		}

		// Check size
		if err := checkSize(int64(file.UncompressedSize64)); err != nil {
			return err
		}

		// Extract file
		if err := extractFile(file, destPath); err != nil {
			return fmt.Errorf("failed to extract %s: %v", file.Name, err)
		}
	}

	return nil
}

func extractFile(file *zip.File, destPath string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// Create directory if needed
	if file.FileInfo().IsDir() {
		return os.MkdirAll(destPath, file.FileInfo().Mode())
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	// Create destination file
	outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Copy file contents
	_, err = io.Copy(outFile, rc)
	return err
}
