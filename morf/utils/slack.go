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
	"encoding/json"
	"fmt"
	"morf/models"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

// GetDownloadURLFromSlack extracts the download URL from Slack command data
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

	fmt.Println(file_url)
	file, err := os.Create(file_name)
	if err != nil {
		log.Error(err)
		return ""
	}

	defer file.Close()

	log.Print(file_url)
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

	return file_name

}

// DownloadFileUsingSlack downloads a file from a URL provided in Slack
func DownloadFileUsingSlack(jiraModel models.JiraModel, ctx *gin.Context) string {

	slack_app := slack.New(jiraModel.SlackToken)
	_, err := slack_app.AuthTest()

	if err != nil {
		log.Error(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return ""
	}

	// Split URL and get the last part of the URL
	url := jiraModel.FileUrl
	url_split := strings.Split(url, "/")
	file_name := url_split[len(url_split)-1]

	file, err := os.Create(file_name)
	if err != nil {
		log.Error(err)
		return ""
	}

	defer file.Close()

	suc := slack_app.GetFile(jiraModel.FileUrl, file)
	if suc != nil {
		return ""
	}

	if file_name[len(file_name)-4:] != ".apk" {
		log.Error("File is not an APK")
		ctx.JSON(http.StatusBadRequest, gin.H{
			"status":  http.StatusBadRequest,
			"message": "File is not an APK",
		})
		return ""
	} else {
		log.Info("File is an APK")
		ctx.JSON(http.StatusOK, gin.H{
			"status":  http.StatusOK,
			"message": "Downloading of APK successful",
		})
	}

	return file_name

}

// RespondSecretsToSlack sends scan results back to Slack
func RespondSecretsToSlack(slackData models.SlackData, ctx *gin.Context, data string) {
	data_string := parseSlackData(data)
	slack_app := slack.New(slackData.SlackToken)
	for _, message := range data_string {
		_, _, err := slack_app.PostMessage(slackData.SlackChannel, slack.MsgOptionText("```"+message+"```", false), slack.MsgOptionTS(slackData.TimeStamp))
		if err != nil {
			log.Error("Error sending message to Slack:", err)
			return
		}
	}
}

func parseSlackData(data string) []string {
	var secrets models.Secrets

	apk_data := json.Unmarshal([]byte(data), &secrets)
	if apk_data != nil {
		log.Error(apk_data)
	}

	if len(secrets.SecretModel) > 0 {
		return parseSecretModel(secrets)
	}
	return []string{"** No secrets found **"}
}

func parseSecretModel(secrets models.Secrets) []string {
	var messages []string
	var currentMessage string

	currentMessage = "APK Name: " + secrets.FileName + "\n" +
		"App Version: " + secrets.PackageDataModel.VersionName + "\n" +
		"Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
		"SHA1: " + secrets.APKHash + "\n" +
		"\n" +
		"Secrets in APK: \n" +
		"----------------\n" +
		"" + strconv.Itoa(len(secrets.SecretModel)) + " secrets found\n" +
		"----------------\n"

	for _, value := range []models.SecretModel(secrets.SecretModel) {
		secretEntry := "Secret Type: " + value.Type + "\n" +
			"Secret Value: " + value.SecretString + "\n" +
			"Secret Type: " + value.SecretType + "\n" +
			"Line No: " + strconv.Itoa(value.LineNo) + "\n" +
			"File Location: " + value.FileLocation + "\n" +
			"----------------\n"

		if len(currentMessage)+len(secretEntry) > 4000 { // Slack has a 4000-character limit per message
			messages = append(messages, currentMessage)
			currentMessage = ""
		}

		currentMessage += secretEntry
	}

	if currentMessage != "" {
		messages = append(messages, currentMessage)
	}

	return messages
}
