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

package db

import (
	"fmt"
	"morf/models"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
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

// GormDB is the global database connection for GORM
var GormDB *gorm.DB

// DatabaseRequired indicates if database operations are required
var DatabaseRequired = true

const (
	maxRetries = 5
	retryDelay = 3 * time.Second
)

// InitDB initializes the database connection with retries
func InitDB() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Error("DATABASE_URL not set")
		DatabaseRequired = false
		return
	}

	log.Info("Initializing MySQL database...")

	// Mask sensitive information in logs
	maskedURL := maskDatabaseURL(dbURL)
	log.Infof("Using database URL: %s", maskedURL)

	// Initialize connection with retries
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err = connectToDatabase(dbURL); err == nil {
			// Set DatabaseRequired to true after successful connection
			DatabaseRequired = true
			log.Info("Successfully connected to MySQL database")
			break
		}
		if attempt < maxRetries {
			log.Warnf("Database connection attempt %d failed: %v. Retrying in %v...", attempt, err, retryDelay)
			time.Sleep(retryDelay)
		}
	}

	if err != nil {
		log.Error("All database connection attempts failed:", err)
		log.Warn("Database operations will be disabled")
		DatabaseRequired = false
		return
	}

	// Run migrations
	if err := runMigrations(); err != nil {
		log.Error("Failed to run migrations:", err)
		log.Warn("Database operations will be disabled")
		DatabaseRequired = false
		return
	}

	log.Info("MySQL database initialized successfully")
}

// connectToDatabase attempts to establish a database connection
func connectToDatabase(dbURL string) error {
	config := &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	}

	var err error
	GormDB, err = gorm.Open(mysql.Open(dbURL), config)
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL database: %v", err)
	}

	// Test the connection
	sqlDB, err := GormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %v", err)
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	err = sqlDB.Ping()
	if err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// runMigrations runs the database migrations with data validation
func runMigrations() error {
	log.Info("Running database migrations...")

	// First try to repair any invalid JSON data
	if err := repairInvalidJSONData(); err != nil {
		log.Warnf("Failed to repair JSON data: %v", err)
		// Continue with migrations even if repair fails
	}

	// Run auto migrations first
	if err := GormDB.AutoMigrate(&models.Secrets{}); err != nil {
		// If migration fails, check if it's a JSON error
		if strings.Contains(err.Error(), "Invalid JSON text") {
			log.Warn("Migration failed due to JSON error, attempting to continue with database operations")
			// Don't return error here, allow database operations to continue
			return nil
		}
		return fmt.Errorf("failed to run migrations: %v", err)
	}

	// Run SQL migrations
	sqlDB, err := GormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %v", err)
	}

	// Read and execute the SQL migration file
	migrationSQL, err := os.ReadFile("/app/db/migrations/002_add_component_json.sql")
	if err != nil {
		log.Warnf("Failed to read SQL migration file: %v", err)
		// Continue even if SQL migration fails
		return nil
	}

	// Split the SQL file into individual statements
	statements := strings.Split(string(migrationSQL), ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		if _, err := sqlDB.Exec(stmt); err != nil {
			log.Warnf("Failed to execute migration statement: %v", err)
			// Continue with next statement even if one fails
			continue
		}
	}

	log.Info("Database migrations completed successfully")
	return nil
}

// repairInvalidJSONData attempts to fix any invalid JSON in the database
func repairInvalidJSONData() error {
	var secrets []models.Secrets

	// Get all records that might have invalid JSON
	if err := GormDB.Find(&secrets).Error; err != nil {
		return fmt.Errorf("failed to fetch records for repair: %v", err)
	}

	for _, secret := range secrets {
		// Create empty arrays for any nil JSON fields
		if secret.Metadata.AndroidManifest.UsesPermissions == nil {
			secret.Metadata.AndroidManifest.UsesPermissions = models.JSONStringArray{}
		}
		if secret.Metadata.AndroidManifest.UsesLibrary == nil {
			secret.Metadata.AndroidManifest.UsesLibrary = models.JSONStringArray{}
		}
		if secret.Metadata.AndroidManifest.UsesFeature == nil {
			secret.Metadata.AndroidManifest.UsesFeature = models.JSONStringArray{}
		}
		if secret.Metadata.AndroidManifest.Permissions == nil {
			secret.Metadata.AndroidManifest.Permissions = models.JSONStringArray{}
		}
		if secret.Metadata.AndroidManifest.PermissionsProtectionLevel == nil {
			secret.Metadata.AndroidManifest.PermissionsProtectionLevel = models.JSONStringArray{}
		}

		// Initialize component arrays if nil
		if secret.Metadata.AndroidManifest.Activities == nil {
			secret.Metadata.AndroidManifest.Activities = models.JSONComponentArray[models.ManifestActivityInfo]{}
		}
		if secret.Metadata.AndroidManifest.Services == nil {
			secret.Metadata.AndroidManifest.Services = models.JSONComponentArray[models.ManifestServiceInfo]{}
		}
		if secret.Metadata.AndroidManifest.ContentProviders == nil {
			secret.Metadata.AndroidManifest.ContentProviders = models.JSONComponentArray[models.ManifestProviderInfo]{}
		}
		if secret.Metadata.AndroidManifest.BroadcastReceivers == nil {
			secret.Metadata.AndroidManifest.BroadcastReceivers = models.JSONComponentArray[models.ManifestReceiverInfo]{}
		}

		// Ensure intent filters are initialized
		for i := range secret.Metadata.AndroidManifest.Activities {
			if secret.Metadata.AndroidManifest.Activities[i].IntentFilters == nil {
				secret.Metadata.AndroidManifest.Activities[i].IntentFilters = []models.ManifestFilter{}
			}
			for j := range secret.Metadata.AndroidManifest.Activities[i].IntentFilters {
				if secret.Metadata.AndroidManifest.Activities[i].IntentFilters[j].Data == nil {
					secret.Metadata.AndroidManifest.Activities[i].IntentFilters[j].Data = []models.ManifestFilterData{}
				}
			}
		}

		// Save the repaired record
		if err := GormDB.Save(&secret).Error; err != nil {
			log.Warnf("Failed to repair record %d: %v", secret.ID, err)
			// Continue with other records even if one fails
			continue
		}
	}

	return nil
}

// InsertSecrets inserts a secret into the database
func InsertSecrets(secret models.Secrets, db interface{}) {
	if GormDB == nil {
		log.Error("Database connection is nil")
		return
	}

	log.Infof("Inserting secret for file: %s", secret.FileName)
	result := GormDB.Create(&secret)
	if result.Error != nil {
		log.Error("Failed to insert secret:", result.Error)
	} else {
		log.Info("Secret inserted successfully")
	}
}

// GetSecrets retrieves all secrets from the database
func GetSecrets(db interface{}) []models.Secrets {
	var secrets []models.Secrets

	if GormDB == nil {
		log.Error("Database connection is nil")
		return secrets
	}

	log.Info("Retrieving all secrets from database")
	result := GormDB.Find(&secrets)
	if result.Error != nil {
		log.Error("Failed to get secrets:", result.Error)
	} else {
		log.Infof("Found %d secrets", len(secrets))
	}

	return secrets
}

// GetLastSecret retrieves the most recent secret from the database
func GetLastSecret(db interface{}) models.Secrets {
	var secret models.Secrets

	if GormDB == nil {
		log.Error("Database connection is nil")
		return secret
	}

	log.Info("Retrieving most recent secret from database")
	result := GormDB.Last(&secret)
	if result.Error != nil {
		log.Error("Failed to get last secret:", result.Error)
	} else {
		log.Infof("Found secret for file: %s", secret.FileName)
	}

	return secret
}
