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
	"morf/models"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	alf "github.com/spf13/afero"
	vip "github.com/spf13/viper"
)

// CreateReport generates a report from scan results
func CreateReport(fs alf.Fs, secret models.Secrets, json_data []byte, secret_data []byte, fileName string) error {
	// Ensure the results/ directory exists before writing into it.
	if err := fs.MkdirAll("results", 0755); err != nil {
		log.Error("Failed to create results directory: ", err)
		return err
	}

	backupPath := vip.GetString("backup_path")

	// fileName and version (the latter derived from the attacker-controlled aapt
	// manifest versionName) are concatenated directly into output paths below.
	// Strip any directory components so a value like "../../etc/passwd" or one
	// containing path separators cannot escape the intended report directories.
	fileName = filepath.Base(fileName)
	version := filepath.Base(secret.PackageDataModel.VersionName)

	reportPath := backupPath + fileName + "_" + version + ".json"
	resultsReportPath := "results" + "/" + fileName + "_" + version + ".json"
	secretsPath := backupPath + fileName + "_" + "Secrets_" + version + ".json"
	resultsSecretsPath := "results" + "/" + fileName + "_" + "Secrets_" + version + ".json"

	// Write full report
	if err := WriteToFile(fs, reportPath, string(json_data)); err != nil {
		log.Error("Failed to write report to "+reportPath+": ", err)
		return err
	}
	if err := WriteToFile(fs, resultsReportPath, string(json_data)); err != nil {
		log.Error("Failed to write report to "+resultsReportPath+": ", err)
		return err
	}

	// Write secrets report
	if err := WriteToFile(fs, secretsPath, string(secret_data)); err != nil {
		log.Error("Failed to write secrets report to "+secretsPath+": ", err)
		return err
	}
	if err := WriteToFile(fs, resultsSecretsPath, string(secret_data)); err != nil {
		log.Error("Failed to write secrets report to "+resultsSecretsPath+": ", err)
		return err
	}

	// Log the exact path that was written (matches reportPath above).
	log.Info("APK Data saved to: " + reportPath)
	return nil
}
