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
	"context"
	"encoding/json"
	"fmt"
	"morf/backup"
	database "morf/db"
	"morf/metrics"
	"morf/models"
	"morf/response"
	"morf/utils"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func StartCliExtraction(apkPath string, db *gorm.DB, is_db_req bool) {
	var fileName string

	// Create job context with isolated workspace
	jobCtx := utils.NewJobContext()
	log.WithFields(log.Fields{
		"job_id":   jobCtx.JobID,
		"apk_path": apkPath,
	}).Info("Starting CLI extraction with isolated workspace")

	// Create workspace directories
	if err := jobCtx.CreateWorkspace(); err != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  err.Error(),
		}).Error("Failed to create workspace")
		return
	}

	// Ensure cleanup on exit
	defer func() {
		if err := jobCtx.CleanupWorkspace(); err != nil {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"error":  err.Error(),
			}).Warn("Failed to cleanup workspace")
		}
	}()

	fs := utils.GetAppFS()
	if is_db_req {
		apkFound, json_data := utils.CheckDuplicateInDB(db, apkPath)
		if apkFound {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
			}).Info("APK already exists in the database")
			log.Info(json_data)
		}
	}

	// S-5: gate the metadata path on the zip-bomb / zip-slip check BEFORE any JVM runs.
	if err := utils.CheckAPKSafe(apkPath); err != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  err.Error(),
		}).Error("APK failed safety check; aborting CLI extraction")
		return
	}

	metadata, packageModel, metaErr := ExtractMetadataAndPackageData(context.Background(), apkPath, jobCtx)
	if metaErr != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  metaErr.Error(),
		}).Error("Metadata extraction failed; aborting CLI extraction")
		return
	}

	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
	}).Info("Metadata: Completed")

	if len(apkPath) > 0 && apkPath[0] == '/' {
		fileName = filepath.Base(apkPath)
	} else {
		fileName = apkPath
	}

	scanner_data, scan_error := StartSecScanE(context.Background(), apkPath, jobCtx)
	if scan_error != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  scan_error.Error(),
		}).Error("Secret scan failed; aborting CLI extraction")
		return
	}
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	secret := utils.CreateSecretModel(fileName, packageModel, metadata, scanner_data, secret_data)

	if is_db_req {
		// Use async write to avoid blocking response
		database.InsertSecretsAsync(secret)
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

	// Create job context with isolated workspace
	jobCtx := utils.NewJobContext()
	requestID := c.GetString("request_id")

	log.WithFields(log.Fields{
		"request_id": requestID,
		"job_id":     jobCtx.JobID,
		"apk_path":   apk_path,
	}).Info("Starting JIRA process with isolated workspace")

	// Create workspace directories
	if err := jobCtx.CreateWorkspace(); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobCtx.JobID,
			"error":      err.Error(),
		}).Error("Failed to create workspace")
		return
	}

	// Ensure cleanup on exit
	defer func() {
		if err := jobCtx.CleanupWorkspace(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobCtx.JobID,
				"error":      err.Error(),
			}).Warn("Failed to cleanup workspace")
		}
	}()

	apkFound, json_data := utils.CheckDuplicateInDB(db, apk_path)

	if apkFound {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Info("APK already exists in the database")
		var secrets models.Secrets
		apk_data := json.Unmarshal([]byte(json_data), &secrets)
		if apk_data != nil {
			log.Error(apk_data)
		}
		utils.CookJiraComment(jiramodel, secrets, c)
		return
	}

	// S-5: gate the metadata path on the zip-bomb / zip-slip check BEFORE any JVM runs.
	if err := utils.CheckAPKSafe(apk_path); err != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  err.Error(),
		}).Error("APK failed safety check; aborting JIRA process")
		return
	}

	metadata, packageModel, metaErr := ExtractMetadataAndPackageData(context.Background(), apk_path, jobCtx)
	if metaErr != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  metaErr.Error(),
		}).Error("Metadata extraction failed; aborting JIRA process")
		return
	}
	scanner_data, scan_error := StartSecScanE(context.Background(), apk_path, jobCtx)
	if scan_error != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  scan_error.Error(),
		}).Error("Secret scan failed; aborting JIRA process")
		return
	}
	secret_data, secret_error := json.Marshal(scanner_data)

	if secret_error != nil {
		log.Error(secret_error)
	}

	secret := utils.CreateSecretModel(apk_path, packageModel, metadata, scanner_data, secret_data)
	// Use async write to avoid blocking response
	database.InsertSecretsAsync(secret)

	// Comment the data to JIRA ticket
	utils.CookJiraComment(jiramodel, secret, c)
}

// Helper function to process APK data
func processAPKData(apkPath string, jobCtx *utils.JobContext) (models.Secrets, []models.SecretModel, []byte, error) {
	// S-5: gate the metadata path on the zip-bomb / zip-slip check BEFORE any JVM runs.
	if err := utils.CheckAPKSafe(apkPath); err != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  err.Error(),
		}).Error("APK failed safety check")
		return models.Secrets{}, nil, nil, fmt.Errorf("safety check failed: %w", err)
	}

	metadata, packageModel, metaErr := ExtractMetadataAndPackageData(context.Background(), apkPath, jobCtx)
	if metaErr != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  metaErr.Error(),
		}).Error("Metadata extraction failed")
		return models.Secrets{}, nil, nil, metaErr
	}
	scannerData, scanError := StartSecScanE(context.Background(), apkPath, jobCtx)
	if scanError != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  scanError.Error(),
		}).Error("Secret scan failed")
		return models.Secrets{}, nil, nil, scanError
	}

	secretData, secretError := json.Marshal(scannerData)
	if secretError != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  secretError.Error(),
		}).Error("Failed to marshal scanner data")
		return models.Secrets{}, nil, nil, secretError
	}

	secret := utils.CreateSecretModel(filepath.Base(apkPath), packageModel, metadata, scannerData, secretData)
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

	// Use async write to avoid blocking
	database.InsertSecretsAsync(secret)
	return nil
}

func StartExtractProcess(apkPath string, db *gorm.DB, c *gin.Context, isSlack bool, slackData models.SlackData) gin.H {
	// Validate database connection
	if db == nil {
		log.Error("Database connection is required")
		return response.CreateErrorResponse("Database connection is required")
	}

	// Create job context with isolated workspace
	jobCtx := utils.NewJobContext()
	requestID := c.GetString("request_id")

	log.WithFields(log.Fields{
		"request_id": requestID,
		"job_id":     jobCtx.JobID,
		"apk_path":   apkPath,
	}).Info("Starting extraction process with isolated workspace")

	// Create workspace directories
	if err := jobCtx.CreateWorkspace(); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobCtx.JobID,
			"error":      err.Error(),
		}).Error("Failed to create workspace")
		return response.CreateErrorResponse("Failed to create workspace")
	}

	// Ensure cleanup on exit
	defer func() {
		if err := jobCtx.CleanupWorkspace(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobCtx.JobID,
				"error":      err.Error(),
			}).Warn("Failed to cleanup workspace")
		}
	}()

	// Check for existing APK
	apkFound, jsonData := utils.CheckDuplicateInDB(db, apkPath)
	if apkFound {
		metrics.RecordScan("duplicate")
		return handleExistingAPK(jsonData, isSlack, slackData, c)
	}

	// Process APK data
	secret, scannerData, secretData, err := processAPKData(apkPath, jobCtx)
	if err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobCtx.JobID,
			"error":      err.Error(),
		}).Error("Error processing APK")
		metrics.RecordScan("failed")
		metrics.RecordError("apk_processing")
		return response.CreateErrorResponse("Error processing APK")
	}

	// Handle database operations asynchronously to avoid blocking response
	// This improves perceived latency by returning results immediately
	go func() {
		if err := handleDatabaseOperations(db, secret); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobCtx.JobID,
				"error":      err.Error(),
			}).Error("Async database operation failed")
			metrics.RecordError("database")
		}
	}()

	// Handle backup operations
	backupHandler := backup.NewBackupHandler(utils.GetAppFS())
	if err := backupHandler.HandleBackup(secret, secretData); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobCtx.JobID,
			"error":      err.Error(),
		}).Error("Backup operation failed")
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

	// SBOM-1: enrich the result payload with the evidence-bearing CycloneDX
	// component set (native libs + detected runtimes) under the contract key
	// "sbomComponents" (the same key the iOS path uses and exportCycloneDX
	// consumes). Best-effort: a nil/empty set simply omits the key.
	addSBOMComponents(resp, jobCtx)

	return resp
}

// addSBOMComponents attaches the Android native-lib / runtime SBOM component set
// to the "data" object of a result envelope under the contract key
// "sbomComponents". The envelope's "data" is a gin.H built by the response
// handlers; when the component set is empty the key is left absent so the
// omitempty JSON contract is preserved. It is best-effort and never fails a scan.
func addSBOMComponents(resp gin.H, jobCtx *utils.JobContext) {
	components := CollectSBOMComponents(jobCtx)
	if len(components) == 0 {
		return
	}
	if data, ok := resp["data"].(gin.H); ok {
		data["sbomComponents"] = components
	}
}
