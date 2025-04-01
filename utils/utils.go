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
*/package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/amrudesh1/morf/db"
	"github.com/amrudesh1/morf/models"

	log "github.com/sirupsen/logrus"
	alf "github.com/spf13/afero"
	vip "github.com/spf13/viper"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
	"gorm.io/gorm"
)

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

func SlackRespond(jiraModel models.JiraModel, slackData models.SlackData) {
	slack_app := slack.New(slackData.SlackToken)
	_, err := slack_app.AuthTest()
	HandleError(err, "Error while authenticating to Slack", false)

	_, _, err = slack_app.PostMessage("***REMOVED***", slack.MsgOptionText("```"+"MORF Scan has been completed successfully"+"```", false))
	HandleError(err, "Error while sending message to Slack", false)
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

func CreateReport(fs alf.Fs, secret models.Secrets, json_data []byte, secret_data []byte, fileName string) {
	WriteToFile(fs, vip.GetString("backup_path")+fileName+"_"+secret.APKVersion+".json", string(json_data))
	WriteToFile(fs, vip.GetString("backup_path")+fileName+"_"+"Secrets_"+secret.APKVersion+".json", string(secret_data))
	WriteToFile(fs, "results"+"/"+fileName+"_"+secret.APKVersion+".json", string(json_data))
	WriteToFile(fs, "results"+"/"+fileName+"_"+"Secrets_"+secret.APKVersion+".json", string(secret_data))
	log.Info("APK Data saved to: " + vip.GetString("backup_path") + "/" + fileName + "_" + secret.APKVersion + ".json")
}

func CheckDuplicateInDB(startDB *gorm.DB, apkPath string) (bool, []byte) {
	secret := db.GetSecrets(startDB)
	for _, value := range secret {
		if value.APKHash == ExtractHash(apkPath) {
			log.Info("Duplicate found in DB")
			json_data, json_error := json.MarshalIndent(value, "", " ")
			if json_error != nil {
				log.Error(json_error)
			}
			return true, json_data
		}
	}
	return false, nil
}

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

	if secrets.SecretModel != "" {
		return parseSecretModel(secrets)
	}
	return []string{"** No secrets found **"}
}

func parseSecretModel(secrets models.Secrets) []string {
	var secretModel []models.SecretModel

	err := json.Unmarshal([]byte(secrets.SecretModel), &secretModel)

	if err != nil {
		log.Error(err)
	}

	var messages []string
	var currentMessage string

	currentMessage = "APK Name: " + secrets.FileName + "\n" +
		"App Version: " + secrets.APKVersion + "\n" +
		"Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
		"SHA1: " + secrets.APKHash + "\n" +
		"\n" +
		"Secrets in APK: \n" +
		"----------------\n" +
		"" + strconv.Itoa(len(secretModel)) + " secrets found\n" +
		"----------------\n"

	for _, value := range secretModel {
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

func parseJiraMessage(secrets models.Secrets) []string {
	var secretModel []models.SecretModel

	err := json.Unmarshal([]byte(secrets.SecretModel), &secretModel)

	if err != nil {
		log.Error(err)
	}

	var messages []string
	var currentMessage string

	currentMessage = "h2. MORF - Mobile Reconnisance Framework\n" +
		"h4. APK Name: " + secrets.FileName + "\n" +
		"h4. App Version: " + secrets.APKVersion + "\n" +
		"h4. Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
		"h4. SHA1: " + secrets.APKHash + "\n" +
		"h4. Secrets in APK:\n" +
		"----------------\n" +
		strconv.Itoa(len(secretModel)) + " secrets found\n" +
		"----------------\n"

	for _, value := range secretModel {
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

func ExtractHash(apkPath string) string {
	file, err := os.Open(apkPath)
	if err != nil {
		log.Error(err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		log.Error(err)
	}
	hashInBytes := hash.Sum(nil)[:16]
	return hex.EncodeToString(hashInBytes)
}

func CreateSecretModel(apkPath string, packageModel models.PackageDataModel, metadata models.MetaDataModel, scanner_data []models.SecretModel, secretData []byte) models.Secrets {
	secretModel := models.Secrets{FileName: apkPath, APKHash: packageModel.APKHash, APKVersion: packageModel.VersionName, SecretModel: string(secretData), Metadata: metadata, PackageDataModel: packageModel}
	return secretModel
}

func ExecuteCommand(command string, args []string, captureOutput bool, useOutputMode bool) (*bytes.Buffer, error) {
	cmd := exec.Command(command, args...)

	var stdout, stderr bytes.Buffer
	if captureOutput {
		cmd.Stdout = &stdout
	}
	cmd.Stderr = &stderr

	var err error
	if useOutputMode {
		_, err = cmd.Output()
	} else {
		err = cmd.Run()
	}

	HandleError(err, stderr.String(), true)

	return &stdout, nil
}

func HandleError(err error, msg string, exitCode1 bool) {
	if err != nil {
		if exitCode1 {
			if exitError, ok := err.(*exec.ExitError); ok {
				if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 1 {
					return
				}
			}
		}
	}
}

func SanitizeSecrets(scanner_data []models.SecretModel) []models.SecretModel {
	var sanitizedSecrets []models.SecretModel
	// Use a map to track unique SecretStrings
	uniqueSecrets := make(map[string]models.SecretModel)

	for _, secret := range scanner_data {
		// If the secret is not already in uniqueSecrets, add it
		if _, exists := uniqueSecrets[secret.SecretString]; !exists {
			uniqueSecrets[secret.SecretString] = secret
			sanitizedSecrets = append(sanitizedSecrets, secret) // Append the unique secret to the sanitized list
		}
	}
	for _, secret := range sanitizedSecrets {
		fmt.Printf("Type: %s\n", secret.Type)
		fmt.Printf("Secret: %s\n", secret.SecretString)
		fmt.Printf("File Name %s\n", secret.FileLocation)
		fmt.Println()
		fmt.Println("-----------------------------------")
	}
	return sanitizedSecrets
}

func RunAAPT(apkPath string) []byte {
	var aapt_success []byte
	aapt_error := error(nil)
	_, aapt_error = exec.LookPath("aapt")
	if aapt_error != nil {
		log.Error("AAPT not found in the system")
		log.Error("Please install AAPT or add it to the system path")
		aapt_success, aapt_error = exec.Command("tools/aapt", "dump", "badging", apkPath).Output()
	} else {
		aapt_success, aapt_error = exec.Command("aapt", "dump", "badging", apkPath).Output()
	}
	return aapt_success
}
