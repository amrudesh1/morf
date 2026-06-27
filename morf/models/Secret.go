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

package models

import (
	"gorm.io/gorm"
)

// Secret represents a scan result (normalized, references package_data)
type Secret struct {
	gorm.Model
	PackageDataID uint   `json:"packageDataId" gorm:"column:package_data_id;index:idx_package_data_id;not null"`
	FileName      string `json:"fileName" gorm:"column:file_name;index:idx_file_name;not null"`
	APKHash       string `json:"apkHash" gorm:"column:apk_hash;uniqueIndex:idx_apk_hash;not null"`
	APKVersion    string `json:"apkVersion" gorm:"column:apk_version"`
	SecretCount   int    `json:"secretCount" gorm:"column:secret_count;default:0"`
	Metadata      string `json:"metadata" gorm:"type:json;column:metadata"` // Full metadata JSON for backward compatibility

	// Relationships
	PackageData        PackageData         `json:"-" gorm:"foreignKey:PackageDataID"`
	SecretFindings     []SecretFinding     `json:"secretFindings" gorm:"foreignKey:SecretID"`
	Activities         []Activity          `json:"activities" gorm:"foreignKey:SecretID"`
	Services           []Service           `json:"services" gorm:"foreignKey:SecretID"`
	ContentProviders   []ContentProvider   `json:"contentProviders" gorm:"foreignKey:SecretID"`
	BroadcastReceivers []BroadcastReceiver `json:"broadcastReceivers" gorm:"foreignKey:SecretID"`
}

// TableName specifies the table name for Secret
func (Secret) TableName() string {
	return "secrets_new" // Will be renamed to "secrets" after migration
}
