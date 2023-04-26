package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"morf/db"
	"morf/models"
	"net/http"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
	"gorm.io/gorm"
)

func GetDownloadUrlFromSlack(slackData models.SlackData, ctx *gin.Context) string {
	slack_app := slack.New(slackData.SlackToken)

	_, err := slack_app.AuthTest()
	if err != nil {
		log.Error(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return ""
	}

	history, err := slack_app.GetConversationHistory(&slack.GetConversationHistoryParameters{
		ChannelID: slackData.SlackChannel,
	})

	if err != nil {
		log.Error(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	file_url := ""
	file_name := ""

	for _, value := range history.Messages {
		if value.Timestamp == slackData.TimeStamp {
			for _, file := range value.Files {
				file_url = file.URLPrivateDownload
				file_name = file.Name

			}
		}
	}

	file, err := os.Create(file_name)
	if err != nil {
		log.Error(err)
		return ""
	}

	defer file.Close()

	suc := slack_app.GetFile(file_url, file)
	if suc != nil {
		log.Error(suc)
		return ""
	}

	//Check if file ends with .apk
	if file_name[len(file_name)-4:] != ".apk" {
		log.Error("File is not an APK")
		ctx.JSON(http.StatusBadRequest, gin.H{
			"status":  http.StatusBadRequest,
			"message": "File is not an APK",
		})
		return ""
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status":  http.StatusOK,
		"message": "File downloaded",
	})

	return file_name

}

func CheckDuplicateInDB(startDB *gorm.DB, apkPath string) (bool, []byte) {
	secret := db.GetSecrets(startDB)
	for _, value := range secret {
		if value.APKHash == ExtractHash(apkPath) {
			log.Info("Duplicate found in DB")
			json_data, json_error := json.Marshal(value)
			if json_error != nil {
				log.Error(json_error)
			}
			return true, json_data
		}
	}
	return false, nil
}

func RespondToSlack(slackData models.SlackData, ctx *gin.Context, data string) {
	data_string := parseSlackData(data)
	slack_app := slack.New(slackData.SlackToken)
	_, _, err := slack_app.PostMessage(slackData.SlackChannel, slack.MsgOptionText("```"+data_string+"```", false), slack.MsgOptionTS(slackData.TimeStamp))
	if err != nil {
		log.Error("Error sending message to Slack:", err)
		return
	}
}

func parseSlackData(data string) string {
	var secrets models.Secrets

	apk_data := json.Unmarshal([]byte(data), &secrets)
	if apk_data != nil {
		log.Error(apk_data)
	}

	if secrets.SecretModel != "" {
		return parseSecretModel(secrets)
	}
	return "** No secrets found **"
}

func parseSecretModel(secrets models.Secrets) string {
	var secretModel []models.SecretModel

	err := json.Unmarshal([]byte(secrets.SecretModel), &secretModel)

	if err != nil {
		log.Error(err)
	}

	slack_message :=
		"APK Name: " + secrets.FileName + "\n" +
			"App Version:" + secrets.APKVersion + "\n" +
			"Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
			"SHA1: " + secrets.APKHash + "\n" +
			"\n" +
			"Secrets in APK: \n" +
			"----------------\n" +
			"" + strconv.Itoa(len(secretModel)) + " secrets found\n" +
			"----------------\n"

	for _, value := range secretModel {
		slack_message += "Secret Type: " + value.SecretType + "\n" +
			"Secret Value: " + value.SecretString + "\n" +
			"Secret Type: " + value.SecretType + "\n" +
			"Line No: " + strconv.Itoa(value.LineNo) + "\n" +
			"File Location: " + value.FileLocation + "\n" +
			"----------------\n"
	}

	return slack_message
}

func ExtractHash(apkPath string) string {
	file, err := os.Open(apkPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		log.Fatal(err)
	}
	hashInBytes := hash.Sum(nil)[:16]
	return hex.EncodeToString(hashInBytes)
}

func CreateSecretModel(apkPath string, packageModel models.PackageDataModel, metadata models.MetaDataModel, scanner_data []models.SecretModel, secretData []byte) models.Secrets {
	secretModel := models.Secrets{FileName: apkPath, APKHash: packageModel.APKHash, APKVersion: packageModel.VersionName, SecretModel: string(secretData), Metadata: metadata, PackageDataModel: packageModel}
	return secretModel
}
