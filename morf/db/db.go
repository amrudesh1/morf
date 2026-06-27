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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"morf/models"
	"morf/utils"
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

	// DB-6: bounds for secret list queries so a full-table read can never load an
	// unbounded number of rows into memory.
	defaultSecretsLimit = 100  // default page size for GetSecretsPage
	maxSecretsLimit     = 1000 // hard cap applied to both GetSecretsPage and GetSecrets
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

// TuneConnectionPool tunes the database connection pool based on worker count
func TuneConnectionPool(workerCount int) {
	if GormDB == nil {
		return
	}

	sqlDB, err := GormDB.DB()
	if err != nil {
		log.Warnf("Failed to get database instance for tuning: %v", err)
		return
	}

	// Calculate pool size based on worker count
	maxIdleConns := workerCount
	if maxIdleConns < 2 {
		maxIdleConns = 2
	}

	maxOpenConns := workerCount * 3
	if maxOpenConns < 10 {
		maxOpenConns = 10
	}

	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(10 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	log.WithFields(log.Fields{
		"worker_count":       workerCount,
		"max_idle_conns":     maxIdleConns,
		"max_open_conns":     maxOpenConns,
		"conn_max_lifetime":  "10m",
		"conn_max_idle_time": "5m",
	}).Info("Database connection pool tuned")
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

	// Configure connection pool (will be tuned based on worker count after worker pool is initialized)
	// Default values for now, will be updated by TuneConnectionPool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	err = sqlDB.Ping()
	if err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// runMigrations runs the database migrations with data validation.
// AutoMigrate can be skipped via MORF_DISABLE_AUTO_MIGRATE=true, intended for
// production pods that rely on a separate `morf migrate` initContainer.
func runMigrations() error {
	if os.Getenv("MORF_DISABLE_AUTO_MIGRATE") == "true" {
		log.Info("MORF_DISABLE_AUTO_MIGRATE=true; skipping AutoMigrate (initContainer/migrate command is responsible)")
		return nil
	}

	log.Info("Running database migrations...")

	// First try to repair any invalid JSON data
	if err := repairInvalidJSONData(); err != nil {
		log.Warnf("Failed to repair JSON data: %v", err)
		// Continue with migrations even if repair fails
	}

	// Run auto migrations first - include both old and new models for migration period
	if err := GormDB.AutoMigrate(
		&models.Secrets{},           // Old table (for migration period)
		&models.APIKey{},            // API keys
		&models.PackageData{},       // New normalized table
		&models.Secret{},            // New normalized secrets table
		&models.SecretFinding{},     // New normalized secret findings
		&models.Activity{},          // New normalized activities
		&models.Service{},           // New normalized services
		&models.ContentProvider{},   // New normalized content providers
		&models.BroadcastReceiver{}, // New normalized broadcast receivers
	); err != nil {
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

	// Read and execute SQL migration files
	migrationFiles := []string{
		"/app/db/migrations/002_add_component_json.sql",
		"/app/db/migrations/003_add_apk_hash_unique_index.sql",
		"/app/db/migrations/004_normalize_schema.sql",
		"/app/db/migrations/005_add_indexes.sql",
	}

	ctx := context.Background()
	for _, migrationFile := range migrationFiles {
		migrationSQL, err := os.ReadFile(migrationFile)
		if err != nil {
			log.Warnf("Failed to read SQL migration file %s: %v", migrationFile, err)
			// Continue with next migration even if one fails
			continue
		}

		// DB-7: run every statement of a single migration file on ONE dedicated
		// connection. Splitting on ';' and running each statement via the pooled
		// sqlDB.Exec could spread session-scoped state (user @vars, PREPARE, temp
		// tables) across different physical connections, corrupting migrations that
		// rely on session continuity. A dedicated *sql.Conn keeps that state coherent
		// for the lifetime of the file.
		conn, err := sqlDB.Conn(ctx)
		if err != nil {
			log.Warnf("Failed to acquire dedicated connection for migration %s: %v", migrationFile, err)
			// Continue with next migration even if one fails
			continue
		}

		// Split the SQL file into individual statements
		statements := strings.Split(string(migrationSQL), ";")
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}

			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				log.Warnf("Failed to execute migration statement from %s: %v", migrationFile, err)
				// Continue with next statement even if one fails
				continue
			}
		}

		// Release the dedicated connection back to the pool before the next file.
		if cerr := conn.Close(); cerr != nil {
			log.Warnf("Failed to close dedicated connection for migration %s: %v", migrationFile, cerr)
		}
	}

	log.Info("Database migrations completed successfully")
	return nil
}

// repairInvalidJSONData attempts to fix any invalid JSON in the legacy Secrets
// table.
//
// DB-1: this is an expensive one-off maintenance task, not a per-boot operation.
// It is gated behind MORF_REPAIR_JSON=true and skipped entirely when the flag is
// unset (the default). When it does run, records are streamed in batches via
// FindInBatches (200 per batch) instead of loading the whole table into memory,
// and only rows that were actually mutated are written back (dirty tracking).
func repairInvalidJSONData() error {
	if os.Getenv("MORF_REPAIR_JSON") != "true" {
		log.Debug("MORF_REPAIR_JSON not set to true; skipping legacy JSON repair pass")
		return nil
	}

	log.Info("MORF_REPAIR_JSON=true; running legacy JSON repair pass in batches")

	var repaired int
	var batchSecrets []models.Secrets
	result := GormDB.FindInBatches(&batchSecrets, 200, func(tx *gorm.DB, batch int) error {
		for i := range batchSecrets {
			secret := &batchSecrets[i]
			if !normalizeSecretJSON(secret) {
				// Nothing changed for this row; do not Save it.
				continue
			}
			if err := tx.Save(secret).Error; err != nil {
				log.Warnf("Failed to repair record %d: %v", secret.ID, err)
				// Continue with other records even if one fails.
				continue
			}
			repaired++
		}
		return nil
	})
	if result.Error != nil {
		return fmt.Errorf("failed to fetch records for repair: %v", result.Error)
	}

	log.Infof("Legacy JSON repair pass completed; %d record(s) updated", repaired)
	return nil
}

// normalizeSecretJSON initializes any nil JSON slices on the secret's manifest in
// place and reports whether it changed anything (the dirty flag used by DB-1 to
// avoid writing back untouched rows).
func normalizeSecretJSON(secret *models.Secrets) bool {
	dirty := false

	// Create empty arrays for any nil JSON fields
	if secret.Metadata.AndroidManifest.UsesPermissions == nil {
		secret.Metadata.AndroidManifest.UsesPermissions = models.JSONStringArray{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.UsesLibrary == nil {
		secret.Metadata.AndroidManifest.UsesLibrary = models.JSONStringArray{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.UsesFeature == nil {
		secret.Metadata.AndroidManifest.UsesFeature = models.JSONStringArray{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.Permissions == nil {
		secret.Metadata.AndroidManifest.Permissions = models.JSONStringArray{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.PermissionsProtectionLevel == nil {
		secret.Metadata.AndroidManifest.PermissionsProtectionLevel = models.JSONStringArray{}
		dirty = true
	}

	// Initialize component arrays if nil
	if secret.Metadata.AndroidManifest.Activities == nil {
		secret.Metadata.AndroidManifest.Activities = models.JSONComponentArray[models.ManifestActivityInfo]{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.Services == nil {
		secret.Metadata.AndroidManifest.Services = models.JSONComponentArray[models.ManifestServiceInfo]{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.ContentProviders == nil {
		secret.Metadata.AndroidManifest.ContentProviders = models.JSONComponentArray[models.ManifestProviderInfo]{}
		dirty = true
	}
	if secret.Metadata.AndroidManifest.BroadcastReceivers == nil {
		secret.Metadata.AndroidManifest.BroadcastReceivers = models.JSONComponentArray[models.ManifestReceiverInfo]{}
		dirty = true
	}

	// Ensure intent filters are initialized
	for i := range secret.Metadata.AndroidManifest.Activities {
		if secret.Metadata.AndroidManifest.Activities[i].IntentFilters == nil {
			secret.Metadata.AndroidManifest.Activities[i].IntentFilters = []models.ManifestFilter{}
			dirty = true
		}
		for j := range secret.Metadata.AndroidManifest.Activities[i].IntentFilters {
			if secret.Metadata.AndroidManifest.Activities[i].IntentFilters[j].Data == nil {
				secret.Metadata.AndroidManifest.Activities[i].IntentFilters[j].Data = []models.ManifestFilterData{}
				dirty = true
			}
		}
	}

	return dirty
}

// InsertSecrets inserts a secret into the database using normalized schema
func InsertSecrets(secret models.Secrets, db interface{}) {
	if GormDB == nil {
		log.Error("Database connection is nil")
		return
	}

	log.Infof("Inserting secret for file: %s", secret.FileName)
	insertSecretsSync(secret)
}

// InsertSecretsAsync inserts a secret into the database asynchronously
func InsertSecretsAsync(secret models.Secrets) {
	if GormDB == nil {
		log.Error("Database connection is nil")
		return
	}

	// Run database write in background goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.WithFields(log.Fields{
					"error": r,
					"file":  secret.FileName,
				}).Error("Panic in async database write")
			}
		}()

		insertSecretsSync(secret)
		log.WithFields(log.Fields{
			"file": secret.FileName,
		}).Info("Async database write completed")
	}()
}

// insertSecretsSync performs the actual database insertion synchronously.
//
// DB-2: every table write (package_data + secret + secret_findings +
// activities/services/providers/receivers) is performed inside a SINGLE GORM
// transaction. Any child insert error aborts the transaction, so the whole secret
// row is rolled back instead of being left in a partial/inconsistent state.
//
// DB-3: package_data is obtained via an atomic get-or-create (FirstOrCreate keyed
// on apk_hash) so concurrent workers cannot double-insert, and the existing-secret
// duplicate check only treats gorm.ErrRecordNotFound as "not present" — any other
// error aborts rather than being misread as a duplicate.
//
// CONC-7: the whole write path runs through the "db" circuit breaker. utils.Do is
// fail-open: when the breaker is unset/closed the function executes unchanged.
func insertSecretsSync(secret models.Secrets) {
	// DB-8: marshal metadata exactly once per insert and reuse the bytes below.
	metadataJSON, err := json.Marshal(secret.Metadata)
	if err != nil {
		log.Warnf("Failed to marshal metadata: %v", err)
		metadataJSON = []byte("{}")
	}
	metadataStr := string(metadataJSON)

	breakerErr := utils.Do("db", func() error {
		return GormDB.Transaction(func(tx *gorm.DB) error {
			// Step 1: Atomically get or create the package_data record (DB-3).
			// Where() keys the lookup on apk_hash only; Attrs() supplies the column
			// values used only when a new row is inserted.
			var packageData models.PackageData
			if err := tx.
				Where(models.PackageData{APKHash: secret.APKHash}).
				Attrs(models.PackageData{
					PackageName:       secret.PackageDataModel.PackageName,
					VersionCode:       secret.PackageDataModel.VersionCode,
					VersionName:       secret.PackageDataModel.VersionName,
					CompileSdkVersion: secret.PackageDataModel.CompileSdkVersion,
					SdkVersion:        secret.PackageDataModel.SdkVersion,
					TargetSdk:         secret.PackageDataModel.TargetSdk,
					MinSDK:            secret.PackageDataModel.MinSDK,
					SupportScreens:    secret.PackageDataModel.SupportScreens,
					Densities:         secret.PackageDataModel.Densities,
					NativeCode:        secret.PackageDataModel.NativeCode,
				}).
				FirstOrCreate(&packageData).Error; err != nil {
				return fmt.Errorf("failed to get or create package_data for %s: %w", secret.APKHash, err)
			}

			// Step 2: Duplicate check. Only a genuine "not found" means we should
			// insert; any other error must abort the transaction (DB-3).
			var existingSecret models.Secret
			err := tx.Where("apk_hash = ?", secret.APKHash).First(&existingSecret).Error
			switch {
			case err == nil:
				log.Infof("Secret already exists for APK hash: %s", secret.APKHash)
				return nil // nothing to insert; commit the (no-op) transaction
			case !errors.Is(err, gorm.ErrRecordNotFound):
				return fmt.Errorf("failed to check for existing secret %s: %w", secret.APKHash, err)
			}

			// Step 3: Create the secret record.
			newSecret := models.Secret{
				PackageDataID: packageData.ID,
				FileName:      secret.FileName,
				APKHash:       secret.APKHash,
				APKVersion:    secret.APKVersion,
				SecretCount:   len(secret.SecretModel),
				Metadata:      metadataStr,
			}
			if err := tx.Create(&newSecret).Error; err != nil {
				return fmt.Errorf("failed to create secret %s: %w", secret.APKHash, err)
			}

			// Step 4: Insert secret findings.
			if len(secret.SecretModel) > 0 {
				findings := make([]models.SecretFinding, 0, len(secret.SecretModel))
				for _, secretModel := range secret.SecretModel {
					findings = append(findings, models.SecretFinding{
						SecretID:         newSecret.ID,
						Type:             secretModel.Type,
						LineNo:           secretModel.LineNo,
						FileLocation:     secretModel.FileLocation,
						SecretType:       secretModel.SecretType,
						SecretString:     secretModel.SecretString,
						SecretConfidence: secretModel.SecretConfidence,
					})
				}
				if err := tx.CreateInBatches(findings, 100).Error; err != nil {
					return fmt.Errorf("failed to create secret findings for %s: %w", secret.APKHash, err)
				}
				log.Infof("Inserted %d secret findings", len(findings))
			}

			// Step 5: Insert components.
			// Activities
			if len(secret.Activities) > 0 {
				activities := make([]models.Activity, 0, len(secret.Activities))
				for _, activity := range secret.Activities {
					intentFiltersJSON, _ := json.Marshal(activity.IntentFilters)
					activities = append(activities, models.Activity{
						SecretID:      newSecret.ID,
						Name:          activity.Name,
						Exported:      activity.Exported,
						IntentFilters: string(intentFiltersJSON),
					})
				}
				if err := tx.CreateInBatches(activities, 100).Error; err != nil {
					return fmt.Errorf("failed to create activities for %s: %w", secret.APKHash, err)
				}
			}

			// Services
			if len(secret.Services) > 0 {
				services := make([]models.Service, 0, len(secret.Services))
				for _, service := range secret.Services {
					services = append(services, models.Service{
						SecretID: newSecret.ID,
						Name:     service.Name,
						Exported: service.Exported,
					})
				}
				if err := tx.CreateInBatches(services, 100).Error; err != nil {
					return fmt.Errorf("failed to create services for %s: %w", secret.APKHash, err)
				}
			}

			// Content Providers
			if len(secret.ContentProviders) > 0 {
				providers := make([]models.ContentProvider, 0, len(secret.ContentProviders))
				for _, provider := range secret.ContentProviders {
					providers = append(providers, models.ContentProvider{
						SecretID: newSecret.ID,
						Name:     provider.Name,
						Exported: provider.Exported,
					})
				}
				if err := tx.CreateInBatches(providers, 100).Error; err != nil {
					return fmt.Errorf("failed to create content providers for %s: %w", secret.APKHash, err)
				}
			}

			// Broadcast Receivers
			if len(secret.BroadcastReceivers) > 0 {
				receivers := make([]models.BroadcastReceiver, 0, len(secret.BroadcastReceivers))
				for _, receiver := range secret.BroadcastReceivers {
					receivers = append(receivers, models.BroadcastReceiver{
						SecretID: newSecret.ID,
						Name:     receiver.Name,
						Exported: receiver.Exported,
					})
				}
				if err := tx.CreateInBatches(receivers, 100).Error; err != nil {
					return fmt.Errorf("failed to create broadcast receivers for %s: %w", secret.APKHash, err)
				}
			}

			return nil
		})
	})

	if breakerErr != nil {
		log.Errorf("Failed to insert secret for %s (transaction rolled back): %v", secret.FileName, breakerErr)
		return
	}

	log.Info("Secret inserted successfully into normalized schema")
}

// BatchInsertSecrets inserts multiple secrets into the database using normalized schema
func BatchInsertSecrets(secrets []models.Secrets) error {
	if GormDB == nil {
		return fmt.Errorf("database connection is nil")
	}

	if len(secrets) == 0 {
		return nil
	}

	log.Infof("Batch inserting %d secrets", len(secrets))

	// Process in chunks of 100
	chunkSize := 100
	for i := 0; i < len(secrets); i += chunkSize {
		end := i + chunkSize
		if end > len(secrets) {
			end = len(secrets)
		}

		chunk := secrets[i:end]
		for _, secret := range chunk {
			InsertSecrets(secret, nil)
		}
	}

	log.Infof("Batch insert completed for %d secrets", len(secrets))
	return nil
}

// querySecrets runs the 6-Preload secret query with the given Limit/Offset.
// All relationships (PackageData + 5 child tables) are eager-loaded in a bounded
// number of queries (one per relationship) instead of N+1 per row. The read is
// routed through the "db" circuit breaker (CONC-7); utils.Do is fail-open so the
// behaviour is unchanged when the breaker is closed/unset.
func querySecrets(limit, offset int) ([]models.Secret, error) {
	var secretRecords []models.Secret
	err := utils.Do("db", func() error {
		q := GormDB.
			Preload("PackageData").
			Preload("SecretFindings").
			Preload("Activities").
			Preload("Services").
			Preload("ContentProviders").
			Preload("BroadcastReceivers").
			Order("created_at DESC").
			Limit(limit)
		if offset > 0 {
			q = q.Offset(offset)
		}
		return q.Find(&secretRecords).Error
	})
	return secretRecords, err
}

// GetSecrets retrieves secrets from the database using the normalized schema.
//
// DB-6: this query is hard-capped at maxSecretsLimit (1000) rows so it can never
// load an unbounded table into memory. Callers that need to page through more
// than the cap should use GetSecretsPage.
func GetSecrets(db interface{}) []models.Secrets {
	var secrets []models.Secrets

	if GormDB == nil {
		log.Error("Database connection is nil")
		return secrets
	}

	log.Info("Retrieving secrets from database (capped at max limit)")

	secretRecords, err := querySecrets(maxSecretsLimit, 0)
	if err != nil {
		log.Error("Failed to get secrets:", err)
		return secrets
	}

	for _, secretRecord := range secretRecords {
		secret := convertSecretToOldFormat(secretRecord)
		secrets = append(secrets, secret)
	}

	log.Infof("Found %d secrets", len(secrets))
	return secrets
}

// GetSecretsPage retrieves a bounded page of secrets using the normalized schema.
//
// DB-6: limit defaults to defaultSecretsLimit (100) when <= 0 and is clamped to
// maxSecretsLimit (1000); offset is floored at 0. This is the safe, paginated
// alternative to an unbounded full-table read.
func GetSecretsPage(limit, offset int) []models.Secrets {
	var secrets []models.Secrets

	if GormDB == nil {
		log.Error("Database connection is nil")
		return secrets
	}

	if limit <= 0 {
		limit = defaultSecretsLimit
	}
	if limit > maxSecretsLimit {
		limit = maxSecretsLimit
	}
	if offset < 0 {
		offset = 0
	}

	log.Infof("Retrieving secrets page (limit=%d, offset=%d)", limit, offset)

	secretRecords, err := querySecrets(limit, offset)
	if err != nil {
		log.Error("Failed to get secrets page:", err)
		return secrets
	}

	for _, secretRecord := range secretRecords {
		secret := convertSecretToOldFormat(secretRecord)
		secrets = append(secrets, secret)
	}

	log.Infof("Found %d secrets (page)", len(secrets))
	return secrets
}

// convertSecretToOldFormat converts a normalized Secret (with its relationships
// eagerly loaded by the caller) to the legacy Secrets format. It performs no
// database I/O; the caller is responsible for Preload-ing PackageData,
// SecretFindings, Activities, Services, ContentProviders, BroadcastReceivers.
func convertSecretToOldFormat(secret models.Secret) models.Secrets {
	secretFindings := secret.SecretFindings
	activities := secret.Activities
	services := secret.Services
	contentProviders := secret.ContentProviders
	broadcastReceivers := secret.BroadcastReceivers

	// Convert secret findings
	secretModelArray := make([]models.SecretModel, 0, len(secretFindings))
	for _, finding := range secretFindings {
		secretModelArray = append(secretModelArray, models.SecretModel{
			Type:             finding.Type,
			LineNo:           finding.LineNo,
			FileLocation:     finding.FileLocation,
			SecretType:       finding.SecretType,
			SecretString:     finding.SecretString,
			SecretConfidence: finding.SecretConfidence,
		})
	}

	// Parse metadata
	var metadata models.MetaDataModel
	if err := json.Unmarshal([]byte(secret.Metadata), &metadata); err != nil {
		metadata = models.MetaDataModel{}
	}

	// Convert activities
	activitiesArray := make([]models.ManifestActivityInfo, 0, len(activities))
	for _, activity := range activities {
		var intentFilters []models.ManifestFilter
		if activity.IntentFilters != "" {
			json.Unmarshal([]byte(activity.IntentFilters), &intentFilters)
		}
		activitiesArray = append(activitiesArray, models.ManifestActivityInfo{
			Name:          activity.Name,
			Exported:      activity.Exported,
			IntentFilters: intentFilters,
		})
	}

	// Convert services
	servicesArray := make([]models.ManifestServiceInfo, 0, len(services))
	for _, service := range services {
		servicesArray = append(servicesArray, models.ManifestServiceInfo{
			Name:     service.Name,
			Exported: service.Exported,
		})
	}

	// Convert content providers
	providersArray := make([]models.ManifestProviderInfo, 0, len(contentProviders))
	for _, provider := range contentProviders {
		providersArray = append(providersArray, models.ManifestProviderInfo{
			Name:     provider.Name,
			Exported: provider.Exported,
		})
	}

	// Convert broadcast receivers
	receiversArray := make([]models.ManifestReceiverInfo, 0, len(broadcastReceivers))
	for _, receiver := range broadcastReceivers {
		receiversArray = append(receiversArray, models.ManifestReceiverInfo{
			Name:     receiver.Name,
			Exported: receiver.Exported,
		})
	}

	return models.Secrets{
		FileName:    secret.FileName,
		APKHash:     secret.APKHash,
		APKVersion:  secret.APKVersion,
		SecretModel: models.SecretModelArray(secretModelArray),
		Metadata:    metadata,
		PackageDataModel: models.PackageDataModel{
			APKHash:           secret.PackageData.APKHash,
			PackageName:       secret.PackageData.PackageName,
			VersionCode:       secret.PackageData.VersionCode,
			VersionName:       secret.PackageData.VersionName,
			CompileSdkVersion: secret.PackageData.CompileSdkVersion,
			SdkVersion:        secret.PackageData.SdkVersion,
			TargetSdk:         secret.PackageData.TargetSdk,
			MinSDK:            secret.PackageData.MinSDK,
			SupportScreens:    secret.PackageData.SupportScreens,
			Densities:         secret.PackageData.Densities,
			NativeCode:        secret.PackageData.NativeCode,
		},
		Activities:         models.JSONComponentArray[models.ManifestActivityInfo](activitiesArray),
		Services:           models.JSONComponentArray[models.ManifestServiceInfo](servicesArray),
		ContentProviders:   models.JSONComponentArray[models.ManifestProviderInfo](providersArray),
		BroadcastReceivers: models.JSONComponentArray[models.ManifestReceiverInfo](receiversArray),
	}
}

// GetLastSecret retrieves the most recent secret from the database using normalized schema
func GetLastSecret(db interface{}) models.Secrets {
	var secret models.Secrets

	if GormDB == nil {
		log.Error("Database connection is nil")
		return secret
	}

	log.Info("Retrieving most recent secret from database")

	var secretRecord models.Secret
	result := GormDB.
		Preload("PackageData").
		Preload("SecretFindings").
		Preload("Activities").
		Preload("Services").
		Preload("ContentProviders").
		Preload("BroadcastReceivers").
		Order("created_at DESC").
		First(&secretRecord)
	if result.Error != nil {
		log.Error("Failed to get last secret:", result.Error)
		return secret
	}

	secret = convertSecretToOldFormat(secretRecord)
	log.Infof("Found secret for file: %s", secret.FileName)

	return secret
}
