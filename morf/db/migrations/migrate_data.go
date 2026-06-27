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

package migrations

import (
	"encoding/json"
	"fmt"
	"morf/db"
	"morf/models"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// MigrateData migrates data from old flat schema to normalized schema
func MigrateData() error {
	if db.GormDB == nil {
		return fmt.Errorf("database connection is nil")
	}

	log.Info("Starting data migration to normalized schema...")

	// Step 1: Migrate package_data and get mapping
	packageDataMap, err := migratePackageData()
	if err != nil {
		return fmt.Errorf("failed to migrate package_data: %v", err)
	}

	// Step 2: Migrate secrets
	if err := migrateSecrets(packageDataMap); err != nil {
		return fmt.Errorf("failed to migrate secrets: %v", err)
	}

	// Step 3: Migrate secret_findings
	if err := migrateSecretFindings(); err != nil {
		return fmt.Errorf("failed to migrate secret_findings: %v", err)
	}

	// Step 4: Migrate components
	if err := migrateComponents(); err != nil {
		return fmt.Errorf("failed to migrate components: %v", err)
	}

	// Step 5: Add foreign keys
	if err := addForeignKeys(); err != nil {
		return fmt.Errorf("failed to add foreign keys: %v", err)
	}

	log.Info("Data migration completed successfully")
	return nil
}

// migratePackageData migrates unique APK hashes to package_data table
// Returns a map of APK hash to package_data ID
func migratePackageData() (map[string]uint, error) {
	log.Info("Migrating package_data...")

	var oldSecrets []models.Secrets
	if err := db.GormDB.Find(&oldSecrets).Error; err != nil {
		return nil, err
	}

	// Map to track unique APK hashes
	packageDataMap := make(map[string]uint) // Maps APK hash to package_data ID

	for _, secret := range oldSecrets {
		if _, exists := packageDataMap[secret.APKHash]; !exists {
			// Check if already exists
			var existing models.PackageData
			if err := db.GormDB.Where("apk_hash = ?", secret.APKHash).First(&existing).Error; err == nil {
				packageDataMap[secret.APKHash] = existing.ID
				continue
			}

			// Create new package_data record
			pkgData := models.PackageData{
				APKHash:           secret.APKHash,
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
			}

			if err := db.GormDB.Create(&pkgData).Error; err != nil {
				log.Warnf("Failed to create package_data for %s: %v", secret.APKHash, err)
				continue
			}

			packageDataMap[secret.APKHash] = pkgData.ID
		}
	}

	log.Infof("Migrated %d unique package_data records", len(packageDataMap))
	return packageDataMap, nil
}

// migrateSecrets migrates secrets to new table structure
func migrateSecrets(packageDataMap map[string]uint) error {
	log.Info("Migrating secrets...")

	var oldSecrets []models.Secrets
	if err := db.GormDB.Find(&oldSecrets).Error; err != nil {
		return err
	}

	for _, oldSecret := range oldSecrets {
		// Get package_data_id from map
		packageDataID, exists := packageDataMap[oldSecret.APKHash]
		if !exists {
			log.Warnf("Package data ID not found for %s, looking up...", oldSecret.APKHash)
			// Try to look it up from database
			var existingPkgData models.PackageData
			if err := db.GormDB.Where("apk_hash = ?", oldSecret.APKHash).First(&existingPkgData).Error; err == nil {
				packageDataID = existingPkgData.ID
			} else {
				log.Warnf("Package data ID not found for %s, skipping", oldSecret.APKHash)
				continue
			}
		}

		// Marshal metadata to JSON
		metadataJSON, err := json.Marshal(oldSecret.Metadata)
		if err != nil {
			log.Warnf("Failed to marshal metadata: %v", err)
			metadataJSON = []byte("{}")
		}

		// Count secrets
		secretCount := len(oldSecret.SecretModel)

		// Create new secret record
		newSecret := models.Secret{
			PackageDataID: packageDataID,
			FileName:      oldSecret.FileName,
			APKHash:       oldSecret.APKHash,
			APKVersion:    oldSecret.APKVersion,
			SecretCount:   secretCount,
			Metadata:      string(metadataJSON),
		}

		// Check if already exists
		var existing models.Secret
		if err := db.GormDB.Where("apk_hash = ?", oldSecret.APKHash).First(&existing).Error; err == nil {
			continue
		}

		if err := db.GormDB.Create(&newSecret).Error; err != nil {
			log.Warnf("Failed to create secret for %s: %v", oldSecret.APKHash, err)
			continue
		}
	}

	log.Info("Secrets migration completed")
	return nil
}

// migrateSecretFindings migrates individual secrets to secret_findings table
func migrateSecretFindings() error {
	log.Info("Migrating secret_findings...")

	var oldSecrets []models.Secrets
	if err := db.GormDB.Find(&oldSecrets).Error; err != nil {
		return err
	}

	for _, oldSecret := range oldSecrets {
		// Get new secret ID
		var newSecret models.Secret
		if err := db.GormDB.Where("apk_hash = ?", oldSecret.APKHash).First(&newSecret).Error; err != nil {
			log.Warnf("Secret not found for APK hash %s, skipping secret findings", oldSecret.APKHash)
			continue
		}

		// Migrate each secret finding
		for _, secretModel := range oldSecret.SecretModel {
			// Check if already exists
			var existing models.SecretFinding
			if err := db.GormDB.Where("secret_id = ? AND type = ? AND line_no = ? AND file_location = ?",
				newSecret.ID, secretModel.Type, secretModel.LineNo, secretModel.FileLocation).First(&existing).Error; err == nil {
				continue // Already exists
			}

			finding := models.SecretFinding{
				SecretID:         newSecret.ID,
				Type:             secretModel.Type,
				LineNo:           secretModel.LineNo,
				FileLocation:     secretModel.FileLocation,
				SecretType:       secretModel.SecretType,
				SecretString:     secretModel.SecretString,
				SecretConfidence: secretModel.SecretConfidence,
			}

			if err := db.GormDB.Create(&finding).Error; err != nil {
				log.Warnf("Failed to create secret finding: %v", err)
				continue
			}
		}
	}

	log.Info("Secret findings migration completed")
	return nil
}

// migrateComponents migrates component data to normalized tables
func migrateComponents() error {
	log.Info("Migrating components...")

	var oldSecrets []models.Secrets
	if err := db.GormDB.Find(&oldSecrets).Error; err != nil {
		return err
	}

	for _, oldSecret := range oldSecrets {
		// Get new secret ID
		var newSecret models.Secret
		if err := db.GormDB.Where("apk_hash = ?", oldSecret.APKHash).First(&newSecret).Error; err != nil {
			log.Warnf("Secret not found for APK hash %s, skipping components", oldSecret.APKHash)
			continue
		}

		// Migrate activities
		for _, activity := range oldSecret.Activities {
			// Check if already exists
			var existing models.Activity
			if err := db.GormDB.Where("secret_id = ? AND name = ?", newSecret.ID, activity.Name).First(&existing).Error; err == nil {
				continue // Already exists
			}

			intentFiltersJSON, _ := json.Marshal(activity.IntentFilters)
			activityRecord := models.Activity{
				SecretID:      newSecret.ID,
				Name:          activity.Name,
				Exported:      activity.Exported,
				IntentFilters: string(intentFiltersJSON),
			}
			if err := db.GormDB.Create(&activityRecord).Error; err != nil {
				log.Warnf("Failed to create activity: %v", err)
			}
		}

		// Migrate services
		for _, service := range oldSecret.Services {
			// Check if already exists
			var existing models.Service
			if err := db.GormDB.Where("secret_id = ? AND name = ?", newSecret.ID, service.Name).First(&existing).Error; err == nil {
				continue // Already exists
			}

			serviceRecord := models.Service{
				SecretID: newSecret.ID,
				Name:     service.Name,
				Exported: service.Exported,
			}
			if err := db.GormDB.Create(&serviceRecord).Error; err != nil {
				log.Warnf("Failed to create service: %v", err)
			}
		}

		// Migrate content providers
		for _, provider := range oldSecret.ContentProviders {
			// Check if already exists
			var existing models.ContentProvider
			if err := db.GormDB.Where("secret_id = ? AND name = ?", newSecret.ID, provider.Name).First(&existing).Error; err == nil {
				continue // Already exists
			}

			providerRecord := models.ContentProvider{
				SecretID: newSecret.ID,
				Name:     provider.Name,
				Exported: provider.Exported,
			}
			if err := db.GormDB.Create(&providerRecord).Error; err != nil {
				log.Warnf("Failed to create content provider: %v", err)
			}
		}

		// Migrate broadcast receivers
		for _, receiver := range oldSecret.BroadcastReceivers {
			// Check if already exists
			var existing models.BroadcastReceiver
			if err := db.GormDB.Where("secret_id = ? AND name = ?", newSecret.ID, receiver.Name).First(&existing).Error; err == nil {
				continue // Already exists
			}

			receiverRecord := models.BroadcastReceiver{
				SecretID: newSecret.ID,
				Name:     receiver.Name,
				Exported: receiver.Exported,
			}
			if err := db.GormDB.Create(&receiverRecord).Error; err != nil {
				log.Warnf("Failed to create broadcast receiver: %v", err)
			}
		}
	}

	log.Info("Components migration completed")
	return nil
}

// BackfillNormalized is the entry point called by `morf migrate --backfill`.
// It reads legacy rows from the `secrets` table in batches of 200 and writes
// them into the normalized tables (package_data, secrets_new, secret_findings,
// activities, services, content_providers, broadcast_receivers).
//
// Idempotency: a legacy row whose apk_hash already appears in secrets_new is
// skipped, so the function is safe to re-run after a partial failure.
//
// Child rows are inserted with CreateInBatches (size 100) per batch of legacy rows.
func BackfillNormalized(gormDB *gorm.DB) error {
	log.Info("BackfillNormalized: starting batched idempotent migration to normalized schema")

	var (
		totalProcessed int
		totalSkipped   int
		totalMigrated  int
	)

	var rows []models.Secrets
	result := gormDB.FindInBatches(&rows, 200, func(tx *gorm.DB, batch int) error {
		// Collect apk_hashes present in this batch.
		hashes := make([]string, 0, len(rows))
		for i := range rows {
			hashes = append(hashes, rows[i].APKHash)
		}

		// Idempotency: which hashes already have a normalized Secret row?
		var existingSecrets []models.Secret
		if err := gormDB.Where("apk_hash IN ?", hashes).Select("apk_hash").Find(&existingSecrets).Error; err != nil {
			return fmt.Errorf("BackfillNormalized: failed to query existing secrets: %w", err)
		}
		existingSet := make(map[string]struct{}, len(existingSecrets))
		for _, s := range existingSecrets {
			existingSet[s.APKHash] = struct{}{}
		}

		// Phase 1: find-or-create PackageData for each new hash in this batch.
		pkgDataByHash := make(map[string]uint)
		for i := range rows {
			row := &rows[i]
			if _, skip := existingSet[row.APKHash]; skip {
				continue
			}
			if _, ok := pkgDataByHash[row.APKHash]; ok {
				continue // deduplicate duplicates within the same batch
			}

			var pkgData models.PackageData
			if err := gormDB.Where("apk_hash = ?", row.APKHash).First(&pkgData).Error; err != nil {
				// Not found: create it.
				pkgData = models.PackageData{
					APKHash:           row.APKHash,
					PackageName:       row.PackageDataModel.PackageName,
					VersionCode:       row.PackageDataModel.VersionCode,
					VersionName:       row.PackageDataModel.VersionName,
					CompileSdkVersion: row.PackageDataModel.CompileSdkVersion,
					SdkVersion:        row.PackageDataModel.SdkVersion,
					TargetSdk:         row.PackageDataModel.TargetSdk,
					MinSDK:            row.PackageDataModel.MinSDK,
					SupportScreens:    row.PackageDataModel.SupportScreens,
					Densities:         row.PackageDataModel.Densities,
					NativeCode:        row.PackageDataModel.NativeCode,
				}
				if createErr := gormDB.Create(&pkgData).Error; createErr != nil {
					log.Warnf("BackfillNormalized: failed to create package_data for %s: %v", row.APKHash, createErr)
					continue
				}
			}
			pkgDataByHash[row.APKHash] = pkgData.ID
		}

		// Phase 2: build normalized Secret records for rows not yet migrated.
		newSecrets := make([]models.Secret, 0, len(rows))
		for i := range rows {
			row := &rows[i]
			if _, skip := existingSet[row.APKHash]; skip {
				continue
			}
			pkgDataID, ok := pkgDataByHash[row.APKHash]
			if !ok {
				continue // package_data creation failed above; skip gracefully
			}
			metadataJSON, err := json.Marshal(row.Metadata)
			if err != nil {
				metadataJSON = []byte("{}")
			}
			newSecrets = append(newSecrets, models.Secret{
				PackageDataID: pkgDataID,
				FileName:      row.FileName,
				APKHash:       row.APKHash,
				APKVersion:    row.APKVersion,
				SecretCount:   len(row.SecretModel),
				Metadata:      string(metadataJSON),
			})
		}

		batchSkipped := len(rows) - len(newSecrets)

		if len(newSecrets) > 0 {
			if err := gormDB.CreateInBatches(&newSecrets, 100).Error; err != nil {
				return fmt.Errorf("BackfillNormalized: failed to insert secrets batch %d: %w", batch, err)
			}
		}

		// Build apk_hash -> newly assigned Secret.ID for child-row insertion.
		secretIDByHash := make(map[string]uint, len(newSecrets))
		for _, s := range newSecrets {
			secretIDByHash[s.APKHash] = s.ID
		}

		// Phase 3: collect child rows for this batch, then insert in sub-batches.
		var (
			findings  []models.SecretFinding
			acts      []models.Activity
			svcs      []models.Service
			providers []models.ContentProvider
			receivers []models.BroadcastReceiver
		)

		for i := range rows {
			row := &rows[i]
			secretID, ok := secretIDByHash[row.APKHash]
			if !ok {
				continue
			}
			for _, sm := range row.SecretModel {
				findings = append(findings, models.SecretFinding{
					SecretID:         secretID,
					Type:             sm.Type,
					LineNo:           sm.LineNo,
					FileLocation:     sm.FileLocation,
					SecretType:       sm.SecretType,
					SecretString:     sm.SecretString,
					SecretConfidence: sm.SecretConfidence,
				})
			}
			for _, a := range row.Activities {
				ifJSON, _ := json.Marshal(a.IntentFilters)
				acts = append(acts, models.Activity{
					SecretID:      secretID,
					Name:          a.Name,
					Exported:      a.Exported,
					IntentFilters: string(ifJSON),
				})
			}
			for _, svc := range row.Services {
				svcs = append(svcs, models.Service{
					SecretID: secretID,
					Name:     svc.Name,
					Exported: svc.Exported,
				})
			}
			for _, p := range row.ContentProviders {
				providers = append(providers, models.ContentProvider{
					SecretID: secretID,
					Name:     p.Name,
					Exported: p.Exported,
				})
			}
			for _, r := range row.BroadcastReceivers {
				receivers = append(receivers, models.BroadcastReceiver{
					SecretID: secretID,
					Name:     r.Name,
					Exported: r.Exported,
				})
			}
		}

		if len(findings) > 0 {
			if err := gormDB.CreateInBatches(&findings, 100).Error; err != nil {
				log.Warnf("BackfillNormalized: failed to insert secret_findings batch %d: %v", batch, err)
			}
		}
		if len(acts) > 0 {
			if err := gormDB.CreateInBatches(&acts, 100).Error; err != nil {
				log.Warnf("BackfillNormalized: failed to insert activities batch %d: %v", batch, err)
			}
		}
		if len(svcs) > 0 {
			if err := gormDB.CreateInBatches(&svcs, 100).Error; err != nil {
				log.Warnf("BackfillNormalized: failed to insert services batch %d: %v", batch, err)
			}
		}
		if len(providers) > 0 {
			if err := gormDB.CreateInBatches(&providers, 100).Error; err != nil {
				log.Warnf("BackfillNormalized: failed to insert content_providers batch %d: %v", batch, err)
			}
		}
		if len(receivers) > 0 {
			if err := gormDB.CreateInBatches(&receivers, 100).Error; err != nil {
				log.Warnf("BackfillNormalized: failed to insert broadcast_receivers batch %d: %v", batch, err)
			}
		}

		totalProcessed += len(rows)
		totalSkipped += batchSkipped
		totalMigrated += len(newSecrets)
		log.Infof("BackfillNormalized: batch %d — rows=%d migrated=%d skipped=%d; cumulative: processed=%d migrated=%d skipped=%d",
			batch, len(rows), len(newSecrets), batchSkipped,
			totalProcessed, totalMigrated, totalSkipped)

		return nil
	})

	if result.Error != nil {
		return fmt.Errorf("BackfillNormalized: scan error: %w", result.Error)
	}

	log.Infof("BackfillNormalized complete — processed=%d migrated=%d skipped=%d",
		totalProcessed, totalMigrated, totalSkipped)
	return nil
}

// addForeignKeys adds foreign key constraints after data migration
func addForeignKeys() error {
	log.Info("Adding foreign key constraints...")

	// Add foreign keys (MySQL syntax)
	foreignKeys := []string{
		"ALTER TABLE secrets_new ADD CONSTRAINT fk_secrets_package_data FOREIGN KEY (package_data_id) REFERENCES package_data(id) ON DELETE CASCADE",
		"ALTER TABLE secret_findings ADD CONSTRAINT fk_secret_findings_secret FOREIGN KEY (secret_id) REFERENCES secrets_new(id) ON DELETE CASCADE",
		"ALTER TABLE activities ADD CONSTRAINT fk_activities_secret FOREIGN KEY (secret_id) REFERENCES secrets_new(id) ON DELETE CASCADE",
		"ALTER TABLE services ADD CONSTRAINT fk_services_secret FOREIGN KEY (secret_id) REFERENCES secrets_new(id) ON DELETE CASCADE",
		"ALTER TABLE content_providers ADD CONSTRAINT fk_content_providers_secret FOREIGN KEY (secret_id) REFERENCES secrets_new(id) ON DELETE CASCADE",
		"ALTER TABLE broadcast_receivers ADD CONSTRAINT fk_broadcast_receivers_secret FOREIGN KEY (secret_id) REFERENCES secrets_new(id) ON DELETE CASCADE",
	}

	for _, fkSQL := range foreignKeys {
		if err := db.GormDB.Exec(fkSQL).Error; err != nil {
			log.Warnf("Failed to add foreign key (may already exist): %v", err)
		}
	}

	log.Info("Foreign keys added")
	return nil
}

// RollbackMigration rolls back the migration by dropping new tables
func RollbackMigration() error {
	log.Info("Rolling back migration...")

	// Drop foreign keys first
	dropFKs := []string{
		"ALTER TABLE broadcast_receivers DROP FOREIGN KEY IF EXISTS fk_broadcast_receivers_secret",
		"ALTER TABLE content_providers DROP FOREIGN KEY IF EXISTS fk_content_providers_secret",
		"ALTER TABLE services DROP FOREIGN KEY IF EXISTS fk_services_secret",
		"ALTER TABLE activities DROP FOREIGN KEY IF EXISTS fk_activities_secret",
		"ALTER TABLE secret_findings DROP FOREIGN KEY IF EXISTS fk_secret_findings_secret",
		"ALTER TABLE secrets_new DROP FOREIGN KEY IF EXISTS fk_secrets_package_data",
	}

	for _, dropFK := range dropFKs {
		if err := db.GormDB.Exec(dropFK).Error; err != nil {
			log.Warnf("Failed to drop foreign key (may not exist): %v", err)
		}
	}

	// Drop tables in reverse order of dependencies
	tables := []string{
		"broadcast_receivers",
		"content_providers",
		"services",
		"activities",
		"secret_findings",
		"secrets_new",
		"package_data",
	}

	for _, table := range tables {
		if err := db.GormDB.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
			log.Warnf("Failed to drop table %s: %v", table, err)
		}
	}

	log.Info("Rollback completed")
	return nil
}
