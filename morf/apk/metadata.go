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

package apk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"morf/metrics"
	"morf/models"
	"morf/utils"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

func StartMetaDataCollection(ctx context.Context, apkPath string, jobCtx *utils.JobContext) (models.MetaDataModel, error) {
	metadataStart := time.Now()
	log.WithFields(log.Fields{
		"job_id":   jobCtx.JobID,
		"apk_path": apkPath,
	}).Info("Starting metadata collection (using original APK path, no copy)")

	// Check cache first
	apkHash, _ := utils.HashFileCached(apkPath)
	if cachedMetadata, found := utils.GetMetadataFromCache(apkHash); found {
		log.WithFields(log.Fields{
			"job_id":   jobCtx.JobID,
			"apk_hash": apkHash,
		}).Info("Metadata retrieved from cache")
		metrics.RecordScanDuration("metadata", time.Since(metadataStart).Seconds())
		return cachedMetadata, nil
	}

	// MED-apkanalyzer-dir: apkanalyzer's --in scans EVERY APK in the directory it
	// is given. Pointing it at filepath.Dir(apkPath) would scan sibling APKs in a
	// shared upload directory. Instead stage ONLY this job's APK into a dedicated
	// per-job staging directory (symlink to avoid a copy; fall back to a copy if
	// the platform/filesystem rejects the symlink) and point --in at that.
	stagingDir := filepath.Join(jobCtx.GetInputDir(), "apkanalyzer")
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		metrics.RecordError("metadata_extraction")
		return models.MetaDataModel{}, fmt.Errorf("failed to create apkanalyzer staging dir: %w", err)
	}
	absAPK, absErr := filepath.Abs(apkPath)
	if absErr != nil {
		absAPK = apkPath
	}
	stagedAPK := filepath.Join(stagingDir, filepath.Base(apkPath))
	_ = os.Remove(stagedAPK) // clear any stale link/file from a previous attempt
	if linkErr := os.Symlink(absAPK, stagedAPK); linkErr != nil {
		if copyErr := copyFileForStaging(absAPK, stagedAPK); copyErr != nil {
			metrics.RecordError("metadata_extraction")
			return models.MetaDataModel{}, fmt.Errorf("failed to stage APK for apkanalyzer: %w", copyErr)
		}
	}

	// Derive a sub-context from the scan ctx so a job-level cancel/timeout also
	// kills the apkanalyzer JVM, capping it at 5 minutes for metadata extraction.
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	apkanalyzerStart := time.Now()
	// SC-3: -Xmx (jvmHeapFlag) bounds apkanalyzer's per-JVM heap/RSS.
	// MED-hardcoded-paths: apkanalyzerJar() resolves under MORF_TOOLS_DIR.
	_, metadata_error := utils.RunWithContext(cmdCtx, "java", jvmHeapFlag(), "-cp", apkanalyzerJar(), "sk.styk.martin.bakalarka.execute.Main", "-analyze", "--in", stagingDir, "--out", jobCtx.GetOutputDir())
	metrics.RecordToolExecution("apkanalyzer", time.Since(apkanalyzerStart).Seconds())

	if metadata_error != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  metadata_error.Error(),
		}).Error("Error while extracting metadata from the APK file")
		metrics.RecordError("metadata_extraction")
		return models.MetaDataModel{}, fmt.Errorf("apkanalyzer metadata extraction failed: %w", metadata_error)
	}

	metrics.RecordScanDuration("metadata", time.Since(metadataStart).Seconds())

	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
	}).Info("Metadata collection successful")

	file_name := filepath.Base(apkPath)
	jsonPath := filepath.Join(jobCtx.GetOutputDir(), strings.Replace(file_name, ".apk", ".json", -1))

	// Make the analyzer output JSON readable by the owner. Do NOT grant
	// write/execute to group/other (0777 was world-writable); check the error so a
	// failed chmod (e.g. apkanalyzer named the file differently) is not silently
	// swallowed before the downstream os.Open (finding 022).
	if err := os.Chmod(jsonPath, 0o644); err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"json_path": jsonPath,
			"job_id":    jobCtx.JobID,
		}).Warn("Failed to chmod analyzer output JSON")
	}

	return startFileParser(jsonPath, apkPath, jobCtx)
}

// copyFileForStaging copies src to dst byte-for-byte. It is the fallback used by
// the apkanalyzer staging step when a symlink cannot be created.
func copyFileForStaging(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func startFileParser(jsonPath string, apkPath string, jobCtx *utils.JobContext) (models.MetaDataModel, error) {
	log.WithFields(log.Fields{
		"json_path": jsonPath,
		"job_id":    jobCtx.JobID,
	}).Info("Starting file parser")
	jsonFile, err := os.Open(jsonPath)
	if err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"json_path": jsonPath,
			"job_id":    jobCtx.JobID,
		}).Error("Failed to open JSON file")
		return models.MetaDataModel{}, fmt.Errorf("failed to open metadata JSON %q: %w", jsonPath, err)
	}
	log.WithFields(log.Fields{
		"json_path": jsonPath,
		"job_id":    jobCtx.JobID,
	}).Info("Successfully opened JSON file")
	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"json_path": jsonPath,
			"job_id":    jobCtx.JobID,
		}).Error("Failed to read JSON file")
		return models.MetaDataModel{}, fmt.Errorf("failed to read metadata JSON %q: %w", jsonPath, err)
	}

	var metadata models.MetaDataModel
	if err := json.Unmarshal(byteValue, &metadata); err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"json_path": jsonPath,
			"job_id":    jobCtx.JobID,
		}).Error("Failed to unmarshal metadata JSON")
		return models.MetaDataModel{}, fmt.Errorf("failed to unmarshal metadata JSON %q: %w", jsonPath, err)
	}

	// Extract export information for components from the original APK
	ExtractComponentExportInfo(apkPath, &metadata)

	// Cache metadata for future use
	if apkHash, err := utils.HashFileCached(apkPath); err == nil && apkHash != "" {
		if err := utils.SetMetadataInCache(apkHash, metadata); err != nil {
			log.WithFields(log.Fields{
				"job_id":   jobCtx.JobID,
				"apk_hash": apkHash,
				"error":    err.Error(),
			}).Warn("Failed to cache metadata")
		}
	}

	return metadata, nil
}

// ExtractMetadataAndPackageData runs metadata and package extraction in parallel.
// R-1: the scan ctx is threaded into the metadata path so a job cancel/timeout
// kills the apkanalyzer JVM, and a metadata-extraction failure is RETURNED to the
// caller instead of being swallowed into an empty model.
func ExtractMetadataAndPackageData(ctx context.Context, apkPath string, jobCtx *utils.JobContext) (models.MetaDataModel, models.PackageDataModel, error) {
	log.WithFields(log.Fields{
		"job_id":   jobCtx.JobID,
		"apk_path": apkPath,
	}).Info("Starting parallel metadata and package data extraction")

	var wg sync.WaitGroup
	var metadata models.MetaDataModel
	var packageModel models.PackageDataModel
	var metaErr error

	// Run both extractions in parallel
	wg.Add(2)

	// Goroutine 1: Extract metadata using apkanalyzer
	go func() {
		defer wg.Done()
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Info("Extracting metadata (parallel)")
		metadata, metaErr = StartMetaDataCollection(ctx, apkPath, jobCtx)
	}()

	// Goroutine 2: Extract package data using aapt
	go func() {
		defer wg.Done()
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Info("Extracting package data (parallel)")
		packageModel = ExtractPackageData(apkPath)
	}()

	// Wait for both to complete
	wg.Wait()

	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
	}).Info("Parallel metadata and package data extraction completed")

	return metadata, packageModel, metaErr
}
