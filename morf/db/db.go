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
	"path/filepath"
	"strconv"
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

	// SC-2: TuneConnectionPool is otherwise fleet-blind — every pod independently
	// sizes its pool to workerCount*3, so a large fleet can collectively exhaust the
	// database's max_connections. MORF_DB_MAX_OPEN_CONNS, when set (>0), clamps the
	// per-pod open-connection cap to min(workerCount*3, that value). Unset keeps the
	// current behavior.
	if capStr := os.Getenv("MORF_DB_MAX_OPEN_CONNS"); capStr != "" {
		if capVal, err := strconv.Atoi(capStr); err == nil && capVal > 0 {
			if maxOpenConns > capVal {
				maxOpenConns = capVal
			}
		} else {
			log.Warnf("Invalid MORF_DB_MAX_OPEN_CONNS=%q; ignoring", capStr)
		}
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

// migrationNames is the ORDERED list of SQL migration files the loader applies.
// Order is significant (001 creates the legacy table that 002/003 ALTER; 004
// normalizes; 006 adds component-security columns), so it must stay ascending.
// Kept package-level so the ordering/existence invariant is unit-testable.
var migrationNames = []string{
	"001_create_secrets_table.sql",
	"002_add_component_json.sql",
	"003_add_apk_hash_unique_index.sql",
	"004_normalize_schema.sql",
	"005_add_indexes.sql",
	"006_component_security_fields.sql",
	"007_ios_support.sql",
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
	// Default values for now, will be updated by TuneConnectionPool.
	// SC-2: default lowered from 100 to a saner 25 so an api-only pod that never
	// calls TuneConnectionPool does not sit at 100 open connections per pod.
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(25)
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
	log.Info("Running database migrations...")

	// DB-3: MORF_DISABLE_AUTO_MIGRATE gates ONLY the GORM AutoMigrate step (used
	// by production pods that AutoMigrate via a separate path). The SQL-file
	// migrations below must always run — the explicit `morf migrate` command and a
	// fresh-DB bootstrap both depend on them — so the flag no longer short-circuits
	// the whole function.
	disableAutoMigrate := os.Getenv("MORF_DISABLE_AUTO_MIGRATE") == "true"
	if disableAutoMigrate {
		log.Info("MORF_DISABLE_AUTO_MIGRATE=true; skipping GORM AutoMigrate (SQL file migrations still run)")
	} else {
		// First try to repair any invalid JSON data
		if err := repairInvalidJSONData(); err != nil {
			log.Warnf("Failed to repair JSON data: %v", err)
			// Continue with migrations even if repair fails
		}

		// DB-schema-fork: the normalized child tables (package_data, secrets_new,
		// secret_findings, activities, services, content_providers,
		// broadcast_receivers) are created and owned by the SQL migrations
		// (004_normalize_schema.sql + 006_component_security_fields.sql), which are
		// the authoritative DDL for their types (BIGINT UNSIGNED ids/foreign keys).
		// They are deliberately NOT listed here: letting GORM AutoMigrate them too
		// forks the schema, because gorm.Model emits BIGINT UNSIGNED while the SQL
		// used INT, and AutoMigrate would silently reconcile column types on every
		// boot. AutoMigrate is kept only for the legacy wide Secrets table (still
		// read during the migration period) and the APIKey table, which have no SQL
		// migration of their own.
		if err := GormDB.AutoMigrate(
			&models.Secrets{},     // Legacy wide table (no SQL migration; still read during migration period)
			&models.APIKey{},      // API keys (no SQL migration owns this table)
			&models.IOSMetadata{}, // iOS metadata; SQL migration 007 owns the authoritative DDL, but the model's gorm.Model uint id already maps to the BIGINT UNSIGNED that 007 creates, so AutoMigrate does not fork the schema and only reconciles when 007 has not yet run.
		); err != nil {
			// DB-2: a JSON error from AutoMigrate must NOT short-circuit the SQL
			// migrations below (the old early `return nil` reported success while
			// silently skipping every SQL migration). Log and fall through so the
			// SQL migrations still run; any other AutoMigrate error is fatal.
			if strings.Contains(err.Error(), "Invalid JSON text") {
				log.Warn("AutoMigrate failed due to JSON error; continuing to SQL file migrations")
				// fall through to SQL migrations below
			} else {
				return fmt.Errorf("failed to run migrations: %v", err)
			}
		}
	}

	// Run SQL migrations
	sqlDB, err := GormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %v", err)
	}

	// DB-040: resolve the migrations directory instead of hardcoding the
	// in-container /app path. Honor MORF_MIGRATIONS_DIR, else look for a
	// db/migrations dir next to the executable, else fall back to the container
	// default. Previously these files were read from a hardcoded
	// /app/db/migrations and silently skipped (warn + continue) anywhere that
	// path did not exist, so the apk_hash UNIQUE index (003), JSON columns (002)
	// and component indexes (005) were never applied off-container without any
	// error being surfaced.
	migrationsDir := resolveMigrationsDir()
	log.Infof("Loading SQL migrations from %s", migrationsDir)

	// DB-041: accumulate read/statement failures so a migrate run that could not
	// apply a required schema change fails loudly with a non-nil error instead of
	// logging warnings and reporting success. InitDB turns that error into
	// DatabaseRequired=false, and the `morf migrate` command turns that into a
	// non-zero exit, so a broken migration now fails the deploy. Benign
	// "already exists"/"duplicate key/column name" idempotency errors are skipped
	// and do NOT count as failures.
	var migrationErrs []string

	ctx := context.Background()
	for _, name := range migrationNames {
		migrationFile := filepath.Join(migrationsDir, name)
		migrationSQL, err := os.ReadFile(migrationFile)
		if err != nil {
			// DB-040: a migration file we cannot read is a hard failure — the
			// schema change it carries would otherwise be silently skipped.
			log.Errorf("Failed to read SQL migration file %s: %v", migrationFile, err)
			migrationErrs = append(migrationErrs, fmt.Sprintf("read %s: %v", migrationFile, err))
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
			log.Errorf("Failed to acquire dedicated connection for migration %s: %v", migrationFile, err)
			migrationErrs = append(migrationErrs, fmt.Sprintf("conn %s: %v", migrationFile, err))
			continue
		}

		// Split the SQL file into individual statements. Strip SQL comments
		// first (DB-042): a ';' inside a '--' comment (e.g. migration 003's
		// "naturally idempotent; it is additionally guarded") otherwise
		// corrupts naive ';' splitting and breaks PREPARE/EXECUTE pairing.
		statements := strings.Split(stripSQLComments(string(migrationSQL)), ";")
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}

			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				// DB-041: distinguish a benign "already applied" idempotency
				// error (safe to ignore on re-run) from a real failure that must
				// abort the migrate. A genuine duplicate-data error (e.g. the
				// 003 UNIQUE INDEX failing because duplicate apk_hash rows exist)
				// is NOT benign and is recorded as a failure.
				if isAlreadyExistsErr(err) {
					log.Infof("Migration statement from %s already applied, skipping: %v", migrationFile, err)
					continue
				}
				log.Errorf("Failed to execute migration statement from %s: %v", migrationFile, err)
				migrationErrs = append(migrationErrs, fmt.Sprintf("exec %s: %v", migrationFile, err))
				// Keep going so the log shows every failing statement; the
				// accumulated error is returned at the end.
				continue
			}
		}

		// Release the dedicated connection back to the pool before the next file.
		if cerr := conn.Close(); cerr != nil {
			log.Warnf("Failed to close dedicated connection for migration %s: %v", migrationFile, cerr)
		}
	}

	if len(migrationErrs) > 0 {
		return fmt.Errorf("%d SQL migration step(s) failed: %s",
			len(migrationErrs), strings.Join(migrationErrs, "; "))
	}

	log.Info("Database migrations completed successfully")
	return nil
}

// resolveMigrationsDir locates the directory holding the numbered .sql migration
// files (DB-040). Resolution order: the MORF_MIGRATIONS_DIR env var, then a
// "db/migrations" directory next to the running executable, then the in-container
// default /app/db/migrations. The returned directory is not guaranteed to exist;
// runMigrations reports a hard error when an expected file cannot be read.
func resolveMigrationsDir() string {
	if dir := os.Getenv("MORF_MIGRATIONS_DIR"); dir != "" {
		return dir
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "db", "migrations")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate
		}
	}
	return "/app/db/migrations"
}

// isAlreadyExistsErr reports whether a migration statement error is a benign
// idempotency error — the index/column/table the statement creates already
// exists — which is safe to ignore when migrations are re-run (DB-041). A
// "duplicate entry" error is deliberately NOT treated as benign: it means the
// data violates the constraint being added (e.g. a UNIQUE index over rows that
// already contain duplicates), which is a real failure that must abort.
// stripSQLComments removes '--' line comments and '/* ... */' block comments
// from a migration file before it is split on ';' (DB-042). Migration 003
// embeds a ';' inside a '--' comment; without stripping, naive splitting emits
// the comment tail as a bogus statement and desynchronises PREPARE/EXECUTE.
// The migration files here never place '--' or ';' inside string literals, so
// line-level stripping is safe.
func stripSQLComments(sql string) string {
	var b strings.Builder
	i, n := 0, len(sql)
	for i < n {
		// block comment
		if i+1 < n && sql[i] == '/' && sql[i+1] == '*' {
			if end := strings.Index(sql[i+2:], "*/"); end >= 0 {
				i += 2 + end + 2
				continue
			}
			break // unterminated block comment: drop the rest
		}
		// line comment: '--' to end of line (keep the newline)
		if i+1 < n && sql[i] == '-' && sql[i+1] == '-' {
			if nl := strings.IndexByte(sql[i:], '\n'); nl >= 0 {
				i += nl
				continue
			}
			break // comment runs to EOF
		}
		b.WriteByte(sql[i])
		i++
	}
	return b.String()
}

func isAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "duplicate entry") {
		return false
	}
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate key name") ||
		strings.Contains(msg, "duplicate column name")
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
					intentFiltersJSON, _ := json.Marshal(service.IntentFilters)
					services = append(services, models.Service{
						SecretID:      newSecret.ID,
						Name:          service.Name,
						Exported:      service.Exported,
						IntentFilters: string(intentFiltersJSON),
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
					authoritiesJSON, _ := json.Marshal(provider.Authorities)
					providers = append(providers, models.ContentProvider{
						SecretID:            newSecret.ID,
						Name:                provider.Name,
						Exported:            provider.Exported,
						Authorities:         string(authoritiesJSON),
						GrantUriPermissions: provider.GrantUriPermissions,
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
					intentFiltersJSON, _ := json.Marshal(receiver.IntentFilters)
					receivers = append(receivers, models.BroadcastReceiver{
						SecretID:      newSecret.ID,
						Name:          receiver.Name,
						Exported:      receiver.Exported,
						IntentFilters: string(intentFiltersJSON),
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

// The normalized read path below — querySecrets, convertSecretToOldFormat, and
// the exported GetSecrets / GetSecretsPage / GetLastSecret — backs the live
// GET /api/secrets reader (router.InitRouters) over the normalized tables, so
// write-correctness of insertSecretsSync is observable. GetSecrets/GetLastSecret
// remain available for callers needing the full cap / most-recent row.
//
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
func GetSecrets() []models.Secrets {
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
		var intentFilters []models.ManifestFilter
		if service.IntentFilters != "" {
			json.Unmarshal([]byte(service.IntentFilters), &intentFilters)
		}
		servicesArray = append(servicesArray, models.ManifestServiceInfo{
			Name:          service.Name,
			Exported:      service.Exported,
			IntentFilters: intentFilters,
		})
	}

	// Convert content providers
	providersArray := make([]models.ManifestProviderInfo, 0, len(contentProviders))
	for _, provider := range contentProviders {
		var authorities []string
		if provider.Authorities != "" {
			json.Unmarshal([]byte(provider.Authorities), &authorities)
		}
		providersArray = append(providersArray, models.ManifestProviderInfo{
			Name:                provider.Name,
			Exported:            provider.Exported,
			Authorities:         authorities,
			GrantUriPermissions: provider.GrantUriPermissions,
		})
	}

	// Convert broadcast receivers
	receiversArray := make([]models.ManifestReceiverInfo, 0, len(broadcastReceivers))
	for _, receiver := range broadcastReceivers {
		var intentFilters []models.ManifestFilter
		if receiver.IntentFilters != "" {
			json.Unmarshal([]byte(receiver.IntentFilters), &intentFilters)
		}
		receiversArray = append(receiversArray, models.ManifestReceiverInfo{
			Name:          receiver.Name,
			Exported:      receiver.Exported,
			IntentFilters: intentFilters,
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
func GetLastSecret() models.Secrets {
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
