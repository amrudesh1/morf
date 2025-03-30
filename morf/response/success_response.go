package response

import (
	"github.com/gin-gonic/gin"
)

// CreateSuccessResponse creates a standardized success response
func CreateSuccessResponse(data interface{}) gin.H {
	return gin.H{
		"message": "Success",
		"data":    data,
	}
}

// CreateDuplicateResponse creates a standardized response for duplicate items
func CreateDuplicateResponse(data interface{}) gin.H {
	return gin.H{
		"message": "Item already exists",
		"data":    data,
	}
}
