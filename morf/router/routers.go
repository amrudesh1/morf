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
	"morf/apk"
	"morf/db"
	"morf/models"
	"morf/utils"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	log "github.com/sirupsen/logrus"
)

// checkDatabaseStatus verifies database connection and configuration
func checkDatabaseStatus() error {
	if !db.DatabaseRequired {
		return fmt.Errorf("database operations are disabled - please check DATABASE_URL environment variable")
	}

	if db.GormDB == nil {
		return fmt.Errorf("database connection is not initialized - please check your database configuration")
	}

	// Verify database connection is still alive
	sqlDB, err := db.GormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %v", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("database connection lost: %v", err)
	}

	return nil
}

func InitRouters(router *gin.RouterGroup) *gin.RouterGroup {
	// Add CORS middleware
	router.Use(CORSMiddleware())
	router.GET("/health", func(c *gin.Context) {

		c.JSON(200, gin.H{
			"message": "ok",
		})

	})

	// Map to store processing results with mutex for concurrent access
	var (
		resultsMap = make(map[string]gin.H)
		mapMutex   = &sync.Mutex{}
	)

	router.GET("/results/:filename", func(c *gin.Context) {
		filename := c.Param("filename")
		mapMutex.Lock()
		result, exists := resultsMap[filename]
		if exists {
			delete(resultsMap, filename)
			mapMutex.Unlock()
			c.JSON(http.StatusOK, result)
		} else {
			mapMutex.Unlock()
			c.JSON(http.StatusAccepted, gin.H{"message": "Processing"})
		}
	})

	router.POST("/upload", func(c *gin.Context) {
		fmt.Printf("Received upload request. Method: %s, Content-Type: %s\n", c.Request.Method, c.GetHeader("Content-Type"))

		file, err := c.FormFile("file")
		if err != nil {
			fmt.Printf("File upload error: %s\n", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("File upload error: %s", err.Error()),
			})
			return
		}
		fmt.Printf("File received: %s, Size: %d\n", file.Filename, file.Size)

		// Validate file extension
		if filepath.Ext(file.Filename) != ".apk" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Only APK files are allowed",
			})
			return
		}

		// Check database status
		if err := checkDatabaseStatus(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Save the uploaded file
		if err := c.SaveUploadedFile(file, file.Filename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to save file: %s", err.Error()),
			})
			return
		}

		// Send success response
		c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully. Processing started."})

		// Start the extraction process in a goroutine
		go func() {
			if result := apk.StartExtractProcess(file.Filename, db.GormDB, c, false, models.SlackData{}); result != nil {
				if result["error"] != nil {
					log.Error("Error in extraction process:", result["error"])
					return
				}
				mapMutex.Lock()
				resultsMap[file.Filename] = result
				mapMutex.Unlock()
			}
		}()
	})

	router.POST("/jira", func(ctx *gin.Context) {
		requestBody := models.JiraModel{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			fmt.Println("Error binding request body:", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if !db.DatabaseRequired {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Database is required for JIRA integration"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})
		go func() {
			apk.StartJiraProcess(requestBody, db.GormDB, ctx)
		}()
	})

	router.POST("/slackscan", func(ctx *gin.Context) {
		requestBody := models.SlackData{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			fmt.Println("Error binding request body:", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check database status
		if err := checkDatabaseStatus(); err != nil {
			ctx.JSON(http.StatusServiceUnavailable, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Send initial response
		ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})

		// Start processing in goroutine
		go func() {
			download_url := utils.GetDownloadUrlFromSlack(requestBody, ctx)
			if download_url == "" {
				log.Error("Failed to get download URL from Slack")
				return
			}

			// Start the extraction process
			if result := apk.StartExtractProcess(download_url, db.GormDB, ctx, true, requestBody); result != nil {
				if result["error"] != nil {
					log.Error("Error in extraction process:", result["error"])
					return
				}
			}
		}()
	})

	return router
}
