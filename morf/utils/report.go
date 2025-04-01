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

	log "github.com/sirupsen/logrus"
	alf "github.com/spf13/afero"
	vip "github.com/spf13/viper"
)

// CreateReport generates a report from scan results
func CreateReport(fs alf.Fs, secret models.Secrets, json_data []byte, secret_data []byte, fileName string) {
	// Write full report
	WriteToFile(fs, vip.GetString("backup_path")+fileName+"_"+secret.PackageDataModel.VersionName+".json", string(json_data))
	WriteToFile(fs, "results"+"/"+fileName+"_"+secret.PackageDataModel.VersionName+".json", string(json_data))

	// Write secrets report
	WriteToFile(fs, vip.GetString("backup_path")+fileName+"_"+"Secrets_"+secret.PackageDataModel.VersionName+".json", string(secret_data))
	WriteToFile(fs, "results"+"/"+fileName+"_"+"Secrets_"+secret.PackageDataModel.VersionName+".json", string(secret_data))

	log.Info("APK Data saved to: " + vip.GetString("backup_path") + "/" + fileName + "_" + secret.PackageDataModel.VersionName + ".json")
}
