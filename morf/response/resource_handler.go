package response

import (
	"morf/models"

	"github.com/gin-gonic/gin"
)

// ResourceHandler handles resource data operations
type ResourceHandler struct {
	resourceData models.ResourceData
}

// NewResourceHandler creates a new instance of ResourceHandler
func NewResourceHandler(resourceData models.ResourceData) *ResourceHandler {
	return &ResourceHandler{
		resourceData: resourceData,
	}
}

// CreateResourceResponse creates a response with resource data
func (h *ResourceHandler) CreateResourceResponse() gin.H {
	return gin.H{
		"numberOfStringResource": h.resourceData.NumberOfStringResource,
		"drawables":              h.createDrawablesResponse(),
		"layouts":                h.resourceData.Layouts,
	}
}

// createDrawablesResponse creates a response for drawables data
func (h *ResourceHandler) createDrawablesResponse() gin.H {
	return gin.H{
		"png": h.resourceData.PngDrawables,
		"jpg": h.resourceData.JpgDrawables,
		"gif": h.resourceData.GifDrawables,
		"xml": h.resourceData.XMLDrawables,
	}
}

// AddResourceDataToResponse adds resource data to an existing response
func (h *ResourceHandler) AddResourceDataToResponse(response gin.H) {
	if data, ok := response["data"].(gin.H); ok {
		data["resourceData"] = h.CreateResourceResponse()
	}
}
