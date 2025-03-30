package response

import (
	"encoding/json"
	"morf/models"
	"morf/utils"

	"github.com/gin-gonic/gin"
)

// APIResponseHandler handles the creation of API responses
type APIResponseHandler struct {
	secret      models.Secrets
	scannerData []models.SecretModel
}

// NewAPIResponseHandler creates a new instance of APIResponseHandler
func NewAPIResponseHandler(secret models.Secrets, scannerData []models.SecretModel) *APIResponseHandler {
	return &APIResponseHandler{
		secret:      secret,
		scannerData: scannerData,
	}
}

// CreateBasicResponse creates a basic response with common fields
func (h *APIResponseHandler) CreateBasicResponse() gin.H {
	return gin.H{
		"fileName":    h.secret.FileName,
		"packageName": h.secret.PackageDataModel.PackageName,
		"version":     h.secret.PackageDataModel.VersionName,
		"minSdk":      h.secret.Metadata.AndroidManifest.UsesMinSdkVersion,
		"targetSdk":   h.secret.Metadata.AndroidManifest.UsesTargetSdkVersion,
		"permissions": h.secret.Metadata.AndroidManifest.UsesPermissions,
		"secretCount": len(h.scannerData),
		"secrets":     h.scannerData,
	}
}

// CreateSuccessResponse creates a success response
func (h *APIResponseHandler) CreateSuccessResponse() gin.H {
	return CreateSuccessResponse(h.CreateBasicResponse())
}

// CreateDuplicateResponse creates a response for duplicate APK
func (h *APIResponseHandler) CreateDuplicateResponse() gin.H {
	return CreateDuplicateResponse(h.CreateBasicResponse())
}

// HandleExistingAPK handles the response for an existing APK
func (h *APIResponseHandler) HandleExistingAPK(isSlack bool, slackData models.SlackData, c *gin.Context, jsonData string) gin.H {
	if isSlack {
		utils.RespondSecretsToSlack(slackData, c, jsonData)
		return nil
	}
	return h.CreateDuplicateResponse()
}

// ParseExistingSecret parses JSON data into a Secrets model
func ParseExistingSecret(jsonData string) (models.Secrets, error) {
	var existingSecret models.Secrets
	err := json.Unmarshal([]byte(jsonData), &existingSecret)
	return existingSecret, err
}
