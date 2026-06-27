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
*/package cmd

import (
	"morf/db"
	route "morf/router"
	"net/http"
	"os"
	"time"

	gin "github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	cob "github.com/spf13/cobra"
	vip "github.com/spf13/viper"
)

// maskDatabaseURL masks sensitive information in a database URL for logging
func maskDatabaseURL(dbURL string) string {
	// Simple string-based masking without regex
	// Format: username:password@tcp(host:port)/dbname

	// Find the position of @ and : characters
	atPos := -1
	colonPos := -1

	for i := 0; i < len(dbURL); i++ {
		if dbURL[i] == '@' {
			atPos = i
			break
		}
		if dbURL[i] == ':' && colonPos == -1 {
			colonPos = i
		}
	}

	if atPos > 0 && colonPos > 0 && colonPos < atPos {
		// Mask both username and password
		return "****:****@" + dbURL[atPos+1:]
	}

	// If URL format is different, return a generic masked version
	return "****"
}

var port int = 0

// GetServerCmd returns the server command for MORF
func GetServerCmd() *cob.Command {
	var dbType string
	var dbURL string

	serverCmd := &cob.Command{
		Use:   "server",
		Short: "Starts MORF as a Service",
		Long:  ``,
		Run: func(cmd *cob.Command, args []string) {
			if port != 0 {
				vip.SetDefault("port", port)
			}

			// Check for DATABASE_URL environment variable
			databaseURL := dbURL
			if databaseURL == "" {
				databaseURL = vip.GetString("db-url")
			}
			if databaseURL == "" {
				databaseURL = os.Getenv("DATABASE_URL")
			}

			// If DATABASE_URL is set, use MySQL
			if databaseURL != "" {
				dbType = "mysql"
				os.Setenv("DATABASE_URL", databaseURL)
				// Mask database URL in logs
				maskedURL := maskDatabaseURL(databaseURL)
				log.WithFields(log.Fields{
					"database_type": "mysql",
					"database_url":  maskedURL,
				}).Info("Using MySQL database")
			} else {
				log.Info("No DATABASE_URL found, using SQLite database")
			}

			db.InitDB()
			r := gin.Default()

			// Configure CORS
			r.Use(func(c *gin.Context) {
				c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
				c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, Authorization")

				if c.Request.Method == "OPTIONS" {
					c.AbortWithStatus(204)
					return
				}

				c.Next()
			})

			r.MaxMultipartMemory = 8 << 20 // 8 MiB

			r.GET("/", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "Welcome to MORF",
				})
			})

			router := r.Group("/api")

			srv := &http.Server{
				Addr:         ":" + vip.GetString("port"),
				Handler:      r,
				ReadTimeout:  5 * 60 * time.Second,
				WriteTimeout: 10 * 60 * time.Second,
			}

			route.InitRouters(router)
			srv.ListenAndServe()
		},
	}

	serverCmd.Flags().IntVarP(&port, "port", "p", 8080, "The default port is 8080")
	serverCmd.Flags().StringVarP(&dbType, "db-type", "t", "sqlite", "Database type (sqlite or mysql)")
	serverCmd.Flags().StringVarP(&dbURL, "db-url", "u", "", "Database URL (required for mysql)")

	return serverCmd
}

// Legacy function, kept for reference
// func runServer(cmd *cob.Command, args []string) {
// 	switch {
// 	case port != 0:
// 		vip.SetDefault("port", port)
// 	}

// 	db.InitDB("sqlite")
// 	r := gin.Default()

// 	r.MaxMultipartMemory = 8 << 20 // 8 MiB

// 	r.GET("/", func(c *gin.Context) {
// 		c.JSON(200, gin.H{
// 			"message": "Welcome to MORF",
// 		})
// 	})

// 	router := r.Group("/api")

// 	srv := &http.Server{
// 		Addr:         ":" + vip.GetString("port"),
// 		Handler:      r,
// 		ReadTimeout:  5 * 60 * time.Second,
// 		WriteTimeout: 10 * 60 * time.Second,
// 	}

// 	route.InitRouters(router)
// 	srv.ListenAndServe()
// }
