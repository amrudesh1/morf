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
	"bytes"
	"encoding/json"
	"fmt"
	"morf/models"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"gorm.io/gorm"
)

// CheckDuplicateInDB checks if an APK has already been scanned
func CheckDuplicateInDB(db *gorm.DB, apkPath string) (bool, string) {
	// Check if database connection is valid
	if db == nil {
		log.Warn("Database connection is nil, skipping duplicate check")
		return false, ""
	}

	apkhash := ExtractHash(apkPath)

	var secret models.Secrets
	result := db.Where("apk_hash = ?", apkhash).First(&secret)
	if result.Error == nil {
		// APK found in database
		log.Infof("File %s found in database", secret.FileName)
		jsonData, err := json.Marshal(secret)
		if err != nil {
			log.Error("Error marshaling secret data:", err)
			return true, ""
		}
		return true, string(jsonData)
	}

	log.Infof("File %s not found in database", secret.FileName)
	return false, ""
}

func CreateSecretModel(apkPath string, packageModel models.PackageDataModel, metadata models.MetaDataModel, scanner_data []models.SecretModel, secretData []byte) models.Secrets {
	// Store component data in the database columns
	secretModel := models.Secrets{
		FileName:           apkPath,
		APKHash:            packageModel.APKHash,
		APKVersion:         packageModel.VersionName,
		SecretModel:        models.SecretModelArray(scanner_data),
		PackageDataModel:   packageModel,
		Activities:         metadata.AndroidManifest.Activities,
		Services:           metadata.AndroidManifest.Services,
		ContentProviders:   metadata.AndroidManifest.ContentProviders,
		BroadcastReceivers: metadata.AndroidManifest.BroadcastReceivers,
	}

	// Clear component arrays from metadata to avoid duplication
	metadata.AndroidManifest.Activities = nil
	metadata.AndroidManifest.Services = nil
	metadata.AndroidManifest.ContentProviders = nil
	metadata.AndroidManifest.BroadcastReceivers = nil
	secretModel.Metadata = metadata

	return secretModel
}

// CookJiraComment prepares a comment for a JIRA ticket
func CookJiraComment(jiraModel models.JiraModel, secret models.Secrets, ctx *gin.Context) string {
	if len(parseJiraMessage(secret)) == 0 {
		return ""
	} else {
		for _, message := range parseJiraMessage(secret) {
			commentToJira(jiraModel, message)
		}
	}

	return "Commented on Jira ticket"
}

func parseJiraMessage(secrets models.Secrets) []string {
	secretModel := secrets.SecretModel

	var messages []string
	var currentMessage string

	currentMessage = "h2. MORF - Mobile Reconnisance Framework\n" +
		"h4. APK Name: " + secrets.FileName + "\n" +
		"h4. App Version: " + secrets.PackageDataModel.VersionName + "\n" +
		"h4. Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
		"h4. SHA1: " + secrets.APKHash + "\n" +
		"h4. Secrets in APK:\n" +
		"----------------\n" +
		strconv.Itoa(len(secretModel)) + " secrets found\n" +
		"----------------\n"

	for _, value := range []models.SecretModel(secretModel) {
		heading := value.Type
		headingMarkup := fmt.Sprintf("\n === %s ===\n", heading)
		secretEntry := "{noformat}" +
			headingMarkup +
			"Secret Value: " + value.SecretString + "\n" +
			"Line No: " + strconv.Itoa(value.LineNo) + "\n" +
			"File Location: " + value.FileLocation + "\n" +
			"{noformat}"

		if len(currentMessage)+len(secretEntry) > 32767 { // Jira has a 32,767 character limit per comment
			messages = append(messages, currentMessage)
			currentMessage = secretEntry
		} else {
			currentMessage += secretEntry
		}
	}

	if currentMessage != "{noformat}" {
		messages = append(messages, currentMessage)
	}

	return messages
}

func commentToJira(jiraModel models.JiraModel, message string) string {
	jira_link := os.Getenv("JIRA_LINK")
	jira_url := jira_link + "/rest/api/2/issue/" + jiraModel.Ticket_id + "/comment"
	final_body := map[string]string{"body": message}
	final_body_json, _ := json.Marshal(final_body)
	log.Info(final_body)
	req, err := http.NewRequest("POST", jira_url, bytes.NewBuffer([]byte(final_body_json)))

	log.Print(jiraModel.JiraToken)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+jiraModel.JiraToken)

	if err != nil {
		log.Error(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		log.Error(err)
	}

	defer resp.Body.Close()

	log.Info("response Status:", resp.Status)
	log.Info("response Headers:", resp.Header)

	if resp.StatusCode == 201 {
		log.Info("Commented on Jira ticket")
		SlackRespond(jiraModel, models.SlackData{SlackToken: jiraModel.SlackToken, SlackChannel: ""})
	}

	return resp.Status

}

func SlackRespond(jiraModel models.JiraModel, slackData models.SlackData) {
	slack_app := slack.New(slackData.SlackToken)
	_, err := slack_app.AuthTest()
	HandleError(err, "Error while authenticating to Slack", false)

	_, _, err = slack_app.PostMessage("***REMOVED***", slack.MsgOptionText("```"+"MORF Scan has been completed successfully"+"```", false))
	HandleError(err, "Error while sending message to Slack", false)
}
