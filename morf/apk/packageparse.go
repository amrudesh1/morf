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
*/package apk

import (
	"morf/metrics"
	"morf/models"
	"morf/utils"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Package-level compiled regexes (pp prefix to avoid collisions in the apk package).
var (
	ppPackageName       = regexp.MustCompile(`package:.*?name='([^']+)'`)
	ppVersionCode       = regexp.MustCompile(`package:.*?versionCode='([^']+)'`)
	ppVersionName       = regexp.MustCompile(`package:.*?versionName='([^']+)'`)
	ppCompileSdkVersion = regexp.MustCompile(`package:.*?compileSdkVersion='([^']+)'`)
	ppSdkVersion        = regexp.MustCompile(`sdkVersion:'([^']+)'`)
	ppTargetSdk         = regexp.MustCompile(`targetSdkVersion:'([^']+)'`)
	ppQuotedValue       = regexp.MustCompile(`'([^']+)'`)
)

func ExtractPackageData(apkPath string) models.PackageDataModel {
	packageStart := time.Now()

	// Check cache first
	apkHash, _ := utils.HashFileCached(apkPath)
	if cachedPackageData, found := utils.GetPackageDataFromCache(apkHash); found {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
		}).Info("Package data retrieved from cache")
		metrics.RecordScanDuration("package_extraction", time.Since(packageStart).Seconds())
		return cachedPackageData
	}

	// Try using system aapt first
	aapt_success := string("")
	aapt_error := error(nil)
	// Use timeout for aapt (2 minutes should be enough for package info extraction)
	aaptStart := time.Now()
	aapt_success, aapt_error = utils.ExecuteCommandWithTimeout(2*time.Minute, "aapt", "dump", "badging", apkPath)
	metrics.RecordToolExecution("aapt", time.Since(aaptStart).Seconds())

	if aapt_error != nil {
		log.Error("Error while getting APK version etc")
		log.Error(aapt_error)
		log.Error("AAPT output: " + aapt_success)
		metrics.RecordError("package_extraction")
		return models.PackageDataModel{} // Return empty model on error
	}

	metrics.RecordScanDuration("package_extraction", time.Since(packageStart).Seconds())

	log.Info("AAPT output length: ", len(aapt_success))
	log.Debug("AAPT raw output: " + aapt_success)

	// Initialize variables
	package_name := ""
	version_code := ""
	version_name := ""
	complie_sdk_version := ""
	sdk_version := ""
	target_sdk := ""
	support_screens := []string{}
	densities := []string{}
	native_code := []string{}

	// Parse the AAPT output line by line
	lines := strings.Split(aapt_success, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract package info
		if strings.HasPrefix(line, "package:") {
			// Extract package name
			nameMatch := ppPackageName.FindStringSubmatch(line)
			if len(nameMatch) > 1 {
				package_name = nameMatch[1]
				log.Debug("Found package name: " + package_name)
			} else {
				log.Warn("Package name not found in line: " + line)
			}

			// Extract version code
			versionCodeMatch := ppVersionCode.FindStringSubmatch(line)
			if len(versionCodeMatch) > 1 {
				version_code = versionCodeMatch[1]
				log.Debug("Found version code: " + version_code)
			} else {
				log.Warn("Version code not found in line: " + line)
			}

			// Extract version name
			versionNameMatch := ppVersionName.FindStringSubmatch(line)
			if len(versionNameMatch) > 1 {
				version_name = versionNameMatch[1]
				log.Debug("Found version name: " + version_name)
			} else {
				log.Warn("Version name not found in line: " + line)
			}

			// Extract compile SDK version
			compileSdkMatch := ppCompileSdkVersion.FindStringSubmatch(line)
			if len(compileSdkMatch) > 1 {
				complie_sdk_version = compileSdkMatch[1]
				log.Debug("Found compile SDK version: " + complie_sdk_version)
			} else {
				log.Warn("Compile SDK version not found in line: " + line)
			}
		}

		// Extract SDK version
		if strings.HasPrefix(line, "sdkVersion:") {
			sdkMatch := ppSdkVersion.FindStringSubmatch(line)
			if len(sdkMatch) > 1 {
				sdk_version = sdkMatch[1]
				log.Debug("Found SDK version: " + sdk_version)
			} else {
				log.Warn("SDK version not found in line: " + line)
			}
		}

		// Extract target SDK version
		if strings.HasPrefix(line, "targetSdkVersion:") {
			targetSdkMatch := ppTargetSdk.FindStringSubmatch(line)
			if len(targetSdkMatch) > 1 {
				target_sdk = targetSdkMatch[1]
				log.Debug("Found target SDK version: " + target_sdk)
			} else {
				log.Warn("Target SDK version not found in line: " + line)
			}
		}

		// Extract supported screens
		if strings.HasPrefix(line, "supports-screens:") {
			screensStr := strings.TrimPrefix(line, "supports-screens:")
			screens := []string{}
			screenMatches := ppQuotedValue.FindAllStringSubmatch(screensStr, -1)
			for _, match := range screenMatches {
				if len(match) > 1 {
					screens = append(screens, match[1])
				}
			}
			support_screens = screens
			log.Debug("Found supported screens: " + strings.Join(support_screens, ", "))
		}

		// Extract densities
		if strings.HasPrefix(line, "densities:") {
			densitiesStr := strings.TrimPrefix(line, "densities:")
			dens := []string{}
			densityMatches := ppQuotedValue.FindAllStringSubmatch(densitiesStr, -1)
			for _, match := range densityMatches {
				if len(match) > 1 {
					dens = append(dens, match[1])
				}
			}
			densities = dens
			log.Debug("Found densities: " + strings.Join(densities, ", "))
		}

		// Extract native code
		if strings.HasPrefix(line, "native-code:") {
			nativeCodeStr := strings.TrimPrefix(line, "native-code:")
			codes := []string{}
			codeMatches := ppQuotedValue.FindAllStringSubmatch(nativeCodeStr, -1)
			for _, match := range codeMatches {
				if len(match) > 1 {
					codes = append(codes, match[1])
				}
			}
			native_code = codes
			log.Debug("Found native code: " + strings.Join(native_code, ", "))
		}
	}

	log.Info("Extracted package info:")
	log.Info("Package name: ", package_name)
	log.Info("Version code: ", version_code)
	log.Info("Version name: ", version_name)
	log.Info("Compile SDK version: ", complie_sdk_version)
	log.Info("SDK version: ", sdk_version)
	log.Info("Target SDK: ", target_sdk)

	packageModel := models.PackageDataModel{
		PackageDataID:     0,
		APKHash:           apkHash,
		PackageName:       package_name,
		VersionCode:       version_code,
		VersionName:       version_name,
		CompileSdkVersion: complie_sdk_version,
		SdkVersion:        sdk_version,
		TargetSdk:         target_sdk,
		MinSDK:            sdk_version, // Use SDK version as min SDK for now
		SupportScreens:    models.JSONStringArray(support_screens),
		Densities:         models.JSONStringArray(densities),
		NativeCode:        models.JSONStringArray(native_code),
	}
	log.Infof("Package Data: %+v", packageModel)

	// Cache package data for future use
	if apkHash != "" {
		if err := utils.SetPackageDataInCache(apkHash, packageModel); err != nil {
			log.WithFields(log.Fields{
				"apk_hash": apkHash,
				"error":    err.Error(),
			}).Warn("Failed to cache package data")
		}
	}

	return packageModel
}
