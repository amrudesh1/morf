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
	"encoding/json"
	"fmt"
	database "morf/db"
	"morf/models"
	"morf/utils"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func StartCliExtraction(apkPath string, db *gorm.DB, is_db_req bool) {
	var fileName string

	fs := utils.GetAppFS()

	if is_db_req {
		apkFound, json_data := utils.CheckDuplicateInDB(db, apkPath)
		if apkFound {
			log.Info("APK already exists in the database")
			log.Info(json_data)
		}
	}

	packageModel := ExtractPackageData(apkPath)
	metadata := StartMetaDataCollection(apkPath)

	fmt.Println("Metadata: Completed")

	if apkPath[0] == '/' {
		fileName = filepath.Base(apkPath)
	} else {
		fileName = apkPath
	}

	scanner_data := StartSecScan(utils.GetInputDir()+fileName, packageModel)
	secret_data, secret_error := json.Marshal(scanner_data)

	utils.HandleError(secret_error, "Error while marshalling the secret data", false)

	secret := utils.CreateSecretModel(fileName, packageModel, metadata, scanner_data, secret_data)
	insertIntoDB(secret, db, false)

	json_data, json_error := json.MarshalIndent(secret, "", " ")
	utils.HandleError(json_error, "Error while marshalling the secret data", false)

	if !utils.CheckBackUpDirExists(fs) {
		utils.CreateBackUpDir(fs)
	}

	ParseResults(fs, fileName, json_data, secret, secret_data)
}

func StartJiraProcess(jiramodel models.JiraModel, db *gorm.DB, c *gin.Context) {
	apk_path := utils.DownloadFileUsingSlack(jiramodel, c)

	if apk_path == "" {
		return
	}

	apkFound, json_data := utils.CheckDuplicateInDB(db, apk_path)

	if apkFound {
		log.Info("APK already exists in the database")
		var secrets models.Secrets
		apk_data := json.Unmarshal([]byte(json_data), &secrets)
		if apk_data != nil {
			utils.HandleError(apk_data, "Error while unmarshalling the secret data", false)
		}
		utils.CookJiraComment(jiramodel, secrets, c)
		return
	}

	packageModel := ExtractPackageData(apk_path)
	metadata := StartMetaDataCollection(apk_path)
	scanner_data := StartSecScan(utils.GetInputDir()+apk_path, packageModel)
	secret_data, secret_error := json.Marshal(scanner_data)

	utils.HandleError(secret_error, "Error while marshalling the secret data", false)
	secret := utils.CreateSecretModel(apk_path, packageModel, metadata, scanner_data, secret_data)
	insertIntoDB(secret, db, true)

	utils.CookJiraComment(jiramodel, secret, c)

}

func StartExtractProcess(apkPath string, db *gorm.DB, c *gin.Context, isSlack bool, slackData models.SlackData) {
	fs := utils.GetAppFS()

	apkFound, json_data := utils.CheckDuplicateInDB(db, apkPath)
	if apkFound {
		if isSlack {
			utils.RespondSecretsToSlack(slackData, c, string(json_data))
		} else {

			c.JSON(http.StatusOK, gin.H{
				"status":  http.StatusOK,
				"message": "APK already in database",
				"data":    string(json_data),
			})
		}
		return
	}

	packageModel := ExtractPackageData(apkPath)
	metadata := StartMetaDataCollection(apkPath)
	scanner_data := StartSecScan(utils.GetInputDir()+apkPath, packageModel)
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	secret := utils.CreateSecretModel(apkPath, packageModel, metadata, scanner_data, secret_data)

	insertIntoDB(secret, db, true)

	json_data, json_error := json.MarshalIndent(secret, "", " ")
	utils.HandleError(json_error, "Error while marshalling the secret data", false)

	if !utils.CheckBackUpDirExists(fs) {
		utils.CreateBackUpDir(fs)
	}

	ParseResults(fs, apkPath, json_data, secret, secret_data)

	if !isSlack {
		c.JSON(http.StatusOK, gin.H{
			"message": "Success",
			"data":    string(json_data),
		})
	}

	if isSlack {
		utils.RespondSecretsToSlack(slackData, c, string(json_data))
	}

}

func insertIntoDB(secret models.Secrets, db *gorm.DB, is_db_req bool) {
	if is_db_req {
		database.InsertSecrets(secret, db)
	}
}
