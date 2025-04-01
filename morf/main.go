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

package main

import (
	"fmt"
	"morf/cmd"
	"morf/db"
	"morf/router"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "morf",
	Short: "Mobile Reconnaissance Framework",
	Long:  `A tool to scan mobile applications for sensitive information`,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run MORF as a web server",
	Long:  `Start the MORF web server with API and frontend`,
	Run:   runServer,
}

func init() {
	// Configure logging
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	rootCmd.AddCommand(cmd.GetCliCmd())
	rootCmd.AddCommand(serverCmd)

	// Server command flags
	serverCmd.Flags().IntP("port", "p", 9092, "Port to run the server on")
	serverCmd.Flags().StringP("db-url", "u", "", "Database URL (optional)")
}

func runServer(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetInt("port")
	dbURL, _ := cmd.Flags().GetString("db-url")

	log.Info("Starting MORF server...")
	log.Infof("Port: %d", port)

	// Set database URL if provided
	if dbURL != "" {
		os.Setenv("DATABASE_URL", dbURL)
	}

	// Initialize database (will be disabled if DATABASE_URL is not set)
	db.InitDB()

	// Initialize Gin with debug logging
	gin.SetMode(gin.DebugMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Configure CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:4200"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	r.Use(cors.New(config))

	// API routes
	apiGroup := r.Group("/api")
	router.InitRouters(apiGroup)

	// Serve static files for Angular frontend
	r.Static("/assets", "./web/dist/browser/assets")
	r.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/browser/index.html")
	})

	// Start server
	log.Infof("Starting server on port %d", port)
	r.Run(fmt.Sprintf(":%d", port))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
