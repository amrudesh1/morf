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
*/

package router

import (
	"fmt"
	"net/http"

	"github.com/amrudesh1/morf/apk"
	"github.com/amrudesh1/morf/db"
	"github.com/amrudesh1/morf/models"
	"github.com/amrudesh1/morf/utils"

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

	router.POST("/jira", func(ctx *gin.Context) {
		requestBody := models.JiraModel{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			fmt.Println("Error binding request body:", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})
		go func() {
			apk.StartJiraProcess(requestBody, db.DB, ctx)
		}()
	})

	router.POST("/slackscan", func(ctx *gin.Context) {
		requestBody := models.SlackData{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			fmt.Println("Error binding request body:", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		go func() {
			download_url := utils.GetDownloadUrlFromSlack(requestBody, ctx)
			if download_url == "" {
				return
			}

			// Send a response back to prevent API timeout
			ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})

			apk.StartExtractProcess(download_url, db.DB, ctx, true, requestBody)
		}()

	})

	return router
}
