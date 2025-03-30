package router

import (
	"github.com/gin-gonic/gin"
)

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		// Log request details before processing
		// fmt.Printf("Request Headers: %+v\n", c.Request.Header)
		// fmt.Printf("Request Method: %s\n", c.Request.Method)
		// fmt.Printf("Request URL: %s\n", c.Request.URL.Path)

		c.Next()

		// Log response details
		// fmt.Printf("Response Status: %d\n", c.Writer.Status())
		if c.Writer.Status() == 403 {
			c.Status(200) // Override 403 with 200
		}
	}
}
