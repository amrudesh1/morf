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

// SecretFinding represents an individual secret finding (normalized)
type SecretFinding struct {
	gorm.Model
	SecretID         uint   `json:"secretId" gorm:"column:secret_id;index:idx_secret_id;not null"`
	Type             string `json:"type" gorm:"column:type;size:255;index:idx_type;not null"`
	LineNo           int    `json:"lineNo" gorm:"column:line_no;not null"`
	FileLocation     string `json:"fileLocation" gorm:"column:file_location;not null"`
	SecretType       string `json:"secretType" gorm:"column:secret_type;size:255;index:idx_secret_type;not null"`
	SecretString     string `json:"secretString" gorm:"column:secret_string;type:text;not null"`
	SecretConfidence string `json:"secretConfidence" gorm:"column:secret_confidence;type:ENUM('high','medium','low');index:idx_secret_confidence;not null;default:'low'"`

	// Fingerprint is a deterministic keyed HMAC-SHA256 hex digest of the raw
	// secret value (crypto.Fingerprint), stored so a stable per-value identity
	// survives AT-REST protection: SecretString holds AES-256-GCM ciphertext or
	// a masked preview (never plaintext), while Fingerprint carries the identity
	// used for de-duplication and build-diff comparison. Nullable so rows
	// written before migration 010 persist without a value. Populated on write.
	Fingerprint string `json:"fingerprint,omitempty" gorm:"column:fingerprint;size:64;index:idx_secret_fingerprint"`

	// Precision / verification / compliance enrichment. Nullable so pre-existing
	// rows (and findings not yet processed by the precision/verification stages)
	// persist without a value. Mirrors the matching fields on models.SecretModel
	// and migration 009_precision_verification.sql.
	Score              *float64 `json:"score,omitempty" gorm:"column:score"`
	Tier               string   `json:"tier,omitempty" gorm:"column:tier;size:16"`
	VerificationStatus string   `json:"verificationStatus,omitempty" gorm:"column:verification_status;size:16"`
	MASVSID            string   `json:"masvsId,omitempty" gorm:"column:masvs_id;size:32"`

	// Relationship
	Secret Secret `json:"-" gorm:"foreignKey:SecretID"`
}

// TableName specifies the table name for SecretFinding
func (SecretFinding) TableName() string {
	return "secret_findings"
}
