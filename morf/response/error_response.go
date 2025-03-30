package response

import (
	"github.com/gin-gonic/gin"
)

// CreateErrorResponse creates a standardized error response
func CreateErrorResponse(message string) gin.H {
	return gin.H{
		"error": message,
	}
}
