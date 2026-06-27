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
	"encoding/json"
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

func StartMetaDataCollection(apkPath string, jobCtx *utils.JobContext) models.MetaDataModel {
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
		return cachedMetadata
	}

	// Use original APK path directly - no copy needed
	// apkanalyzer expects --in to be a directory containing APK files
	// Pass the directory containing the original APK file
	apkDir := filepath.Dir(apkPath)

	// Use timeout for apkanalyzer (5 minutes should be enough for metadata extraction)
	apkanalyzerStart := time.Now()
	_, metadata_error := utils.ExecuteCommandWithTimeout(5*time.Minute, "java", "-cp", "/app/tools/apkanalyzer.jar", "sk.styk.martin.bakalarka.execute.Main", "-analyze", "--in", apkDir, "--out", jobCtx.GetOutputDir())
	metrics.RecordToolExecution("apkanalyzer", time.Since(apkanalyzerStart).Seconds())

	if metadata_error != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  metadata_error.Error(),
		}).Error("Error while extracting metadata from the APK file")
		metrics.RecordError("metadata_extraction")
		return models.MetaDataModel{}
	}

	metrics.RecordScanDuration("metadata", time.Since(metadataStart).Seconds())

	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
	}).Info("Metadata collection successful")

	file_name := filepath.Base(apkPath)
	jsonPath := filepath.Join(jobCtx.GetOutputDir(), strings.Replace(file_name, ".apk", ".json", -1))

	// Make file readable
	os.Chmod(jsonPath, 0777)

	return startFileParser(jsonPath, apkPath, jobCtx)
}

func startFileParser(jsonPath string, apkPath string, jobCtx *utils.JobContext) models.MetaDataModel {
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
		return models.MetaDataModel{}
	}
	log.WithFields(log.Fields{
		"json_path": jsonPath,
		"job_id":    jobCtx.JobID,
	}).Info("Successfully opened JSON file")
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var metadata models.MetaDataModel
	json.Unmarshal([]byte(byteValue), &metadata)

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

	return metadata
}

// ExtractMetadataAndPackageData runs metadata and package extraction in parallel
func ExtractMetadataAndPackageData(apkPath string, jobCtx *utils.JobContext) (models.MetaDataModel, models.PackageDataModel) {
	log.WithFields(log.Fields{
		"job_id":   jobCtx.JobID,
		"apk_path": apkPath,
	}).Info("Starting parallel metadata and package data extraction")

	var wg sync.WaitGroup
	var metadata models.MetaDataModel
	var packageModel models.PackageDataModel

	// Run both extractions in parallel
	wg.Add(2)

	// Goroutine 1: Extract metadata using apkanalyzer
	go func() {
		defer wg.Done()
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Info("Extracting metadata (parallel)")
		metadata = StartMetaDataCollection(apkPath, jobCtx)
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

	return metadata, packageModel
}
