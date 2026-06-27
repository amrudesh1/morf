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
	"fmt"
	"morf/db"
	"morf/models"
	"time"

	log "github.com/sirupsen/logrus"
)

// TestMigration validates the migration by checking data integrity
func TestMigration() error {
	if db.GormDB == nil {
		return fmt.Errorf("database connection is nil")
	}

	log.Info("Testing migration data integrity...")

	// Test 1: Check package_data records
	var packageDataCount int64
	if err := db.GormDB.Model(&models.PackageData{}).Count(&packageDataCount).Error; err != nil {
		return fmt.Errorf("failed to count package_data: %v", err)
	}
	log.Infof("Found %d package_data records", packageDataCount)

	// Test 2: Check secrets records
	var secretsCount int64
	if err := db.GormDB.Model(&models.Secret{}).Count(&secretsCount).Error; err != nil {
		return fmt.Errorf("failed to count secrets: %v", err)
	}
	log.Infof("Found %d secrets records", secretsCount)

	// Test 3: Check secret_findings records
	var findingsCount int64
	if err := db.GormDB.Model(&models.SecretFinding{}).Count(&findingsCount).Error; err != nil {
		return fmt.Errorf("failed to count secret_findings: %v", err)
	}
	log.Infof("Found %d secret_findings records", findingsCount)

	// Test 4: Check activities records
	var activitiesCount int64
	if err := db.GormDB.Model(&models.Activity{}).Count(&activitiesCount).Error; err != nil {
		return fmt.Errorf("failed to count activities: %v", err)
	}
	log.Infof("Found %d activities records", activitiesCount)

	// Test 5: Check services records
	var servicesCount int64
	if err := db.GormDB.Model(&models.Service{}).Count(&servicesCount).Error; err != nil {
		return fmt.Errorf("failed to count services: %v", err)
	}
	log.Infof("Found %d services records", servicesCount)

	// Test 6: Check content_providers records
	var providersCount int64
	if err := db.GormDB.Model(&models.ContentProvider{}).Count(&providersCount).Error; err != nil {
		return fmt.Errorf("failed to count content_providers: %v", err)
	}
	log.Infof("Found %d content_providers records", providersCount)

	// Test 7: Check broadcast_receivers records
	var receiversCount int64
	if err := db.GormDB.Model(&models.BroadcastReceiver{}).Count(&receiversCount).Error; err != nil {
		return fmt.Errorf("failed to count broadcast_receivers: %v", err)
	}
	log.Infof("Found %d broadcast_receivers records", receiversCount)

	// Test 8: Verify foreign key relationships
	var orphanedSecrets int64
	db.GormDB.Model(&models.Secret{}).
		Joins("LEFT JOIN package_data ON secrets_new.package_data_id = package_data.id").
		Where("package_data.id IS NULL").
		Count(&orphanedSecrets)
	if orphanedSecrets > 0 {
		return fmt.Errorf("found %d orphaned secrets (missing package_data)", orphanedSecrets)
	}

	var orphanedFindings int64
	db.GormDB.Model(&models.SecretFinding{}).
		Joins("LEFT JOIN secrets_new ON secret_findings.secret_id = secrets_new.id").
		Where("secrets_new.id IS NULL").
		Count(&orphanedFindings)
	if orphanedFindings > 0 {
		return fmt.Errorf("found %d orphaned secret_findings (missing secrets)", orphanedFindings)
	}

	log.Info("Migration test completed successfully - all data integrity checks passed")
	return nil
}

// ValidateMigrationPerformance tests query performance on normalized schema
func ValidateMigrationPerformance() error {
	if db.GormDB == nil {
		return fmt.Errorf("database connection is nil")
	}

	log.Info("Validating migration performance...")

	// Test query by APK hash
	var secret models.Secret
	start := time.Now()
	if err := db.GormDB.Where("apk_hash = ?", "test_hash").First(&secret).Error; err != nil {
		// Expected to fail if test_hash doesn't exist, but we're measuring performance
	}
	hashQueryTime := time.Since(start)
	log.Infof("Query by APK hash took: %v", hashQueryTime)

	// Test query by package name
	var packageData []models.PackageData
	start = time.Now()
	db.GormDB.Where("package_name = ?", "com.example.app").Find(&packageData)
	packageQueryTime := time.Since(start)
	log.Infof("Query by package name took: %v", packageQueryTime)

	// Test query by secret type
	var findings []models.SecretFinding
	start = time.Now()
	db.GormDB.Where("secret_type = ?", "API_KEY").Limit(100).Find(&findings)
	secretTypeQueryTime := time.Since(start)
	log.Infof("Query by secret type took: %v", secretTypeQueryTime)

	log.Info("Performance validation completed")
	return nil
}
