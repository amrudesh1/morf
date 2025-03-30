package response

import (
	"morf/models"

	"github.com/gin-gonic/gin"
)

// MetadataHandler handles metadata-related operations
type MetadataHandler struct {
	metadata models.MetaDataModel
}

// NewMetadataHandler creates a new instance of MetadataHandler
func NewMetadataHandler(metadata models.MetaDataModel) *MetadataHandler {
	return &MetadataHandler{
		metadata: metadata,
	}
}

// TransformComponents transforms metadata into a response format
func (h *MetadataHandler) TransformComponents(secret *models.Secrets) gin.H {
	return gin.H{
		"activities":         secret.Activities,
		"services":           secret.Services,
		"contentProviders":   secret.ContentProviders,
		"broadcastReceivers": secret.BroadcastReceivers,
		"usesLibrary":        h.metadata.AndroidManifest.UsesLibrary,
		"customPermissions":  h.metadata.AndroidManifest.Permissions,
		"usesFeatures":       h.metadata.AndroidManifest.UsesFeature,
	}
}

// AddMetadataToResponse adds metadata to an existing response
func (h *MetadataHandler) AddMetadataToResponse(response gin.H, secret *models.Secrets) {
	if data, ok := response["data"].(gin.H); ok {
		metadataResponse := h.TransformComponents(secret)
		for k, v := range metadataResponse {
			data[k] = v
		}
	}
}
