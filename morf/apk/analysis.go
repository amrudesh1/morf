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
	"morf/backup"
	database "morf/db"
	"morf/models"
	"morf/response"
	"morf/utils"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
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

	scanner_data := StartSecScan(utils.GetInputDir() + fileName)
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	secret := utils.CreateSecretModel(fileName, packageModel, metadata, scanner_data, secret_data)

	if is_db_req {
		database.InsertSecrets(secret, db)
	}

	json_data, json_error := json.MarshalIndent(secret, "", " ")

	if json_error != nil {
		log.Error(json_error)
	}

	//Check if backup folder exists
	if !utils.CheckBackUpDirExists(fs) {
		utils.CreateBackUpDir(fs)
	}

	utils.CreateReport(fs, secret, json_data, secret_data, fileName)
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
			log.Error(apk_data)
		}
		utils.CookJiraComment(jiramodel, secrets, c)
		return
	}

	packageModel := ExtractPackageData(apk_path)
	metadata := StartMetaDataCollection(apk_path)
	scanner_data := StartSecScan(utils.GetInputDir() + apk_path)
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	secret := utils.CreateSecretModel(apk_path, packageModel, metadata, scanner_data, secret_data)
	database.InsertSecrets(secret, db)

	// Comment the data to JIRA ticket
	utils.CookJiraComment(jiramodel, secret, c)
}

// Helper function to create metadata response
func createMetadataResponse(secret models.Secrets) gin.H {
	return gin.H{
		"activities":         secret.Activities,
		"services":           secret.Services,
		"contentProviders":   secret.ContentProviders,
		"broadcastReceivers": secret.BroadcastReceivers,
		"usesLibrary":        secret.Metadata.AndroidManifest.UsesLibrary,
		"customPermissions":  secret.Metadata.AndroidManifest.Permissions,
		"usesFeatures":       secret.Metadata.AndroidManifest.UsesFeature,
	}
}

// Helper function to create resource data response
func createResourceDataResponse(resourceData models.ResourceData) gin.H {
	return gin.H{
		"numberOfStringResource": resourceData.NumberOfStringResource,
		"drawables": gin.H{
			"png": resourceData.PngDrawables,
			"jpg": resourceData.JpgDrawables,
			"gif": resourceData.GifDrawables,
			"xml": resourceData.XMLDrawables,
		},
		"layouts": resourceData.Layouts,
	}
}

// Helper function to create API response
func createAPIResponse(secret models.Secrets, scannerData []models.SecretModel) gin.H {
	metadataResponse := createMetadataResponse(secret)

	response := gin.H{
		"message": "Success",
		"data": gin.H{
			"fileName":           secret.FileName,
			"packageName":        secret.PackageDataModel.PackageName,
			"version":            secret.PackageDataModel.VersionName,
			"minSdk":             secret.Metadata.AndroidManifest.UsesMinSdkVersion,
			"targetSdk":          secret.Metadata.AndroidManifest.UsesTargetSdkVersion,
			"permissions":        secret.Metadata.AndroidManifest.UsesPermissions,
			"activities":         metadataResponse["activities"],
			"services":           metadataResponse["services"],
			"contentProviders":   metadataResponse["contentProviders"],
			"broadcastReceivers": metadataResponse["broadcastReceivers"],
			"usesLibrary":        metadataResponse["usesLibrary"],
			"customPermissions":  metadataResponse["customPermissions"],
			"usesFeatures":       metadataResponse["usesFeatures"],
			"resourceData":       createResourceDataResponse(secret.Metadata.ResourceData),
			"secretCount":        len(scannerData),
			"secrets":            scannerData,
			"createdAt":          time.Now().Format(time.RFC3339),
		},
	}

	return response
}

// Helper function to process APK data
func processAPKData(apkPath string) (models.Secrets, []models.SecretModel, []byte, error) {
	packageModel := ExtractPackageData(apkPath)
	metadata := StartMetaDataCollection(apkPath)
	scannerData := StartSecScan(utils.GetInputDir() + apkPath)

	secretData, secretError := json.Marshal(scannerData)
	if secretError != nil {
		log.Error(secretError)
		return models.Secrets{}, nil, nil, secretError
	}

	secret := utils.CreateSecretModel(apkPath, packageModel, metadata, scannerData, secretData)
	return secret, scannerData, secretData, nil
}

// handleExistingAPK handles the case when an APK is already in the database
func handleExistingAPK(jsonData string, isSlack bool, slackData models.SlackData, c *gin.Context) gin.H {
	if isSlack {
		utils.RespondSecretsToSlack(slackData, c, jsonData)
		return nil
	}

	existingSecret, err := response.ParseExistingSecret(jsonData)
	if err != nil {
		return response.CreateErrorResponse("Error parsing existing data")
	}

	// Create response handlers
	apiHandler := response.NewAPIResponseHandler(existingSecret, existingSecret.SecretModel)
	metadataHandler := response.NewMetadataHandler(existingSecret.Metadata)
	resourceHandler := response.NewResourceHandler(existingSecret.Metadata.ResourceData)

	// Create response
	resp := apiHandler.CreateDuplicateResponse()

	// Add metadata and resource data
	metadataHandler.AddMetadataToResponse(resp, &existingSecret)
	resourceHandler.AddResourceDataToResponse(resp)

	return resp
}

// handleDatabaseOperations handles database operations
func handleDatabaseOperations(db *gorm.DB, secret models.Secrets) error {
	if db == nil {
		return fmt.Errorf("database connection is not initialized")
	}

	if !database.DatabaseRequired {
		return fmt.Errorf("database operations are disabled - please check DATABASE_URL environment variable")
	}

	// Verify database connection is still alive
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %v", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("database connection lost: %v", err)
	}

	database.InsertSecrets(secret, db)
	return nil
}

func StartExtractProcess(apkPath string, db *gorm.DB, c *gin.Context, isSlack bool, slackData models.SlackData) gin.H {
	// Validate database connection
	if db == nil {
		log.Error("Database connection is required")
		return response.CreateErrorResponse("Database connection is required")
	}

	// Check for existing APK
	apkFound, jsonData := utils.CheckDuplicateInDB(db, apkPath)
	if apkFound {
		return handleExistingAPK(jsonData, isSlack, slackData, c)
	}

	// Process APK data
	secret, scannerData, secretData, err := processAPKData(apkPath)
	if err != nil {
		return response.CreateErrorResponse("Error processing APK")
	}

	// Handle database operations
	if err := handleDatabaseOperations(db, secret); err != nil {
		log.Error(err)
		return response.CreateErrorResponse(err.Error())
	}

	// Handle backup operations
	backupHandler := backup.NewBackupHandler(utils.GetAppFS())
	if err := backupHandler.HandleBackup(secret, secretData); err != nil {
		log.Error("Backup operation failed:", err)
	}

	// Return response
	if isSlack {
		utils.RespondSecretsToSlack(slackData, c, string(secretData))
		return nil
	}

	// Create response handlers
	apiHandler := response.NewAPIResponseHandler(secret, scannerData)
	metadataHandler := response.NewMetadataHandler(secret.Metadata)
	resourceHandler := response.NewResourceHandler(secret.Metadata.ResourceData)

	// Create response
	resp := apiHandler.CreateSuccessResponse()

	// Add metadata and resource data
	metadataHandler.AddMetadataToResponse(resp, &secret)
	resourceHandler.AddResourceDataToResponse(resp)

	return resp
}
