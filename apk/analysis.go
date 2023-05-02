package apk

import (
	"encoding/json"
	"io/ioutil"
	database "morf/db"
	"morf/models"
	util "morf/utils"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	vip "github.com/spf13/viper"
	"gorm.io/gorm"
)

func StartCliExtraction(apkPath string, db *gorm.DB) {
	apkFound, json_data := util.CheckDuplicateInDB(db, apkPath)
	packageModel := ExtractPackageData(apkPath)
	metadata := StartMetaDataCollection(apkPath)
	scanner_data := StartSecScan("temp/input/" + apkPath)
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	if apkFound {
		log.Info("APK already exists in the database")
		log.Info(json_data)
	}

	secret := util.CreateSecretModel(apkPath, packageModel, metadata, scanner_data, secret_data)
	database.InsertSecrets(secret, db)

	json_data, json_error := json.MarshalIndent(secret, "", " ")

	if json_error != nil {
		log.Error(json_error)
	}

	//Check if backup folder exists
	_, err_ := os.Stat(vip.GetString("backup_path"))

	if os.IsNotExist(err_) {
		os.Mkdir(vip.GetString("backup_path"), 0755)
	}

	//Move the APK Data to backup folder
	err := ioutil.WriteFile(vip.GetString("backup_path")+"/"+apkPath+"_"+secret.APKVersion+".json", json_data, 0644)
	if err != nil {
		log.Error(err)
	}

	// Print File Path to the apk file.json
	log.Info("APK Data saved to: " + vip.GetString("backup_path") + "/" + apkPath + "_" + secret.APKVersion + ".json")
}

func StartExtractProcess(apkPath string, db *gorm.DB, c *gin.Context, isSlack bool, slackData models.SlackData) {

	apkFound, json_data := util.CheckDuplicateInDB(db, apkPath)
	if apkFound {
		if isSlack {
			util.RespondToSlack(slackData, c, string(json_data))
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
	scanner_data := StartSecScan("temp/input/" + apkPath)
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	secret := util.CreateSecretModel(apkPath, packageModel, metadata, scanner_data, secret_data)

	database.InsertSecrets(secret, db)

	json_data, json_error := json.MarshalIndent(secret, "", " ")

	if json_error != nil {
		log.Error("JSON ERROR: ", json_error)
		log.Error(json_error)
	}

	//Check if backup folder exists
	_, err_ := os.Stat(vip.GetString("backup_path"))

	if os.IsNotExist(err_) {
		os.Mkdir(vip.GetString("backup_path"), 0755)
	}

	// Check if file exists

	//Move the APK Data to backup folder
	backupPath := vip.GetString("backup_path") + apkPath + "_" + secret.APKVersion + ".json"
	log.Println("Backup Path: ", backupPath)
	err := ioutil.WriteFile(backupPath, json_data, 0644)

	if err != nil {
		log.Error(err)
	}

	if !isSlack {
		c.JSON(http.StatusOK, gin.H{
			"message": "Success",
			"data":    string(json_data),
		})
	}

	if isSlack {
		util.RespondToSlack(slackData, c, string(json_data))
	}

}
