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
	"morf/crypto"
	"morf/models"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

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
	result := gormDB.FindInBatches(&rows, 200, func(batchTx *gorm.DB, batch int) error {
		// Wrap the entire batch (package_data + secret + child inserts) in a
		// single transaction so a partial child-insert failure rolls the whole
		// batch back instead of orphaning secret rows without their children
		// (MED-backfill-tx). All writes below use the transaction handle `tx`.
		var (
			batchMigrated int
			batchSkipped  int
		)
		err := batchTx.Transaction(func(tx *gorm.DB) error {
			// Collect apk_hashes present in this batch.
			hashes := make([]string, 0, len(rows))
			for i := range rows {
				hashes = append(hashes, rows[i].APKHash)
			}

			// Idempotency: which hashes already have a normalized Secret row?
			var existingSecrets []models.Secret
			if err := tx.Where("apk_hash IN ?", hashes).Select("apk_hash").Find(&existingSecrets).Error; err != nil {
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
				if err := tx.Where("apk_hash = ?", row.APKHash).First(&pkgData).Error; err != nil {
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
					if createErr := tx.Create(&pkgData).Error; createErr != nil {
						// Abort the batch so nothing is left partially migrated.
						return fmt.Errorf("BackfillNormalized: failed to create package_data for %s: %w", row.APKHash, createErr)
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

			batchSkipped = len(rows) - len(newSecrets)
			batchMigrated = len(newSecrets)

			if len(newSecrets) > 0 {
				if err := tx.CreateInBatches(&newSecrets, 100).Error; err != nil {
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
					// AT-REST protection: store ciphertext/masked preview plus a
					// deterministic fingerprint identity, never the plaintext
					// value (mirrors the primary write in db.insertSecretsSync).
					findings = append(findings, models.SecretFinding{
						SecretID:         secretID,
						Type:             sm.Type,
						LineNo:           sm.LineNo,
						FileLocation:     sm.FileLocation,
						SecretType:       sm.SecretType,
						SecretString:     crypto.ProtectAtRest(sm.SecretString),
						Fingerprint:      crypto.Fingerprint(sm.SecretString),
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
					ifJSON, _ := json.Marshal(svc.IntentFilters)
					svcs = append(svcs, models.Service{
						SecretID:      secretID,
						Name:          svc.Name,
						Exported:      svc.Exported,
						IntentFilters: string(ifJSON),
					})
				}
				for _, p := range row.ContentProviders {
					authJSON, _ := json.Marshal(p.Authorities)
					providers = append(providers, models.ContentProvider{
						SecretID:            secretID,
						Name:                p.Name,
						Exported:            p.Exported,
						Authorities:         string(authJSON),
						GrantUriPermissions: p.GrantUriPermissions,
					})
				}
				for _, r := range row.BroadcastReceivers {
					ifJSON, _ := json.Marshal(r.IntentFilters)
					receivers = append(receivers, models.BroadcastReceiver{
						SecretID:      secretID,
						Name:          r.Name,
						Exported:      r.Exported,
						IntentFilters: string(ifJSON),
					})
				}
			}

			// Child inserts now abort the transaction on failure (MED-backfill-tx)
			// instead of logging and continuing, which previously left orphaned
			// secret rows whose children were never written.
			if len(findings) > 0 {
				if err := tx.CreateInBatches(&findings, 100).Error; err != nil {
					return fmt.Errorf("BackfillNormalized: failed to insert secret_findings batch %d: %w", batch, err)
				}
			}
			if len(acts) > 0 {
				if err := tx.CreateInBatches(&acts, 100).Error; err != nil {
					return fmt.Errorf("BackfillNormalized: failed to insert activities batch %d: %w", batch, err)
				}
			}
			if len(svcs) > 0 {
				if err := tx.CreateInBatches(&svcs, 100).Error; err != nil {
					return fmt.Errorf("BackfillNormalized: failed to insert services batch %d: %w", batch, err)
				}
			}
			if len(providers) > 0 {
				if err := tx.CreateInBatches(&providers, 100).Error; err != nil {
					return fmt.Errorf("BackfillNormalized: failed to insert content_providers batch %d: %w", batch, err)
				}
			}
			if len(receivers) > 0 {
				if err := tx.CreateInBatches(&receivers, 100).Error; err != nil {
					return fmt.Errorf("BackfillNormalized: failed to insert broadcast_receivers batch %d: %w", batch, err)
				}
			}

			return nil
		})
		if err != nil {
			return err
		}

		totalProcessed += len(rows)
		totalSkipped += batchSkipped
		totalMigrated += batchMigrated
		log.Infof("BackfillNormalized: batch %d — rows=%d migrated=%d skipped=%d; cumulative: processed=%d migrated=%d skipped=%d",
			batch, len(rows), batchMigrated, batchSkipped,
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
