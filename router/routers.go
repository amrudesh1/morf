package router

import (
	"fmt"
	"morf/apk"
	"morf/db"
	"morf/models"
	"morf/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

func InitRouters(router *gin.RouterGroup) *gin.RouterGroup {

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	router.POST("/upload", func(c *gin.Context) {
		file, error := c.FormFile("file")
		if error != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", error.Error()))
			return
		}
		c.SaveUploadedFile(file, file.Filename)
		apk.StartExtractProcess(file.Filename, db.DB, c, false, models.SlackData{})
	})

	router.POST("/slackscan", func(ctx *gin.Context) {
		requestBody := models.SlackData{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			fmt.Println("Error binding request body:", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		download_url := utils.GetDownloadUrlFromSlack(requestBody, ctx)
		if download_url == "" {
			return
		}

		// Send a response back to prevent API timeout
		ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})

		// sleep for 5 seconds to allow slack to upload the file

		apk.StartExtractProcess(download_url, db.DB, ctx, true, requestBody)

	})

	return router
}
