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
	"encoding/json"
	"strings"

	"gorm.io/gorm"
)

// IOSMetadata holds iOS-specific package metadata extracted from an IPA's
// Info.plist, Mach-O binary, and embedded provisioning/entitlements. It is the
// iOS analogue of the Android component tables: one row per scanned IPA, linked
// to the owning Secret via SecretID.
//
// The JSON-typed columns store variable-length lists/maps extracted from the
// binary and plists (architectures, URL schemes, entitlements, frameworks, ATS
// exceptions) as marshalled JSON strings, mirroring how Activity.IntentFilters
// stores its data.
type IOSMetadata struct {
	gorm.Model
	SecretID uint `json:"secretId" gorm:"column:secret_id;index:idx_secret_id;not null"`

	// Core Info.plist identity fields (size:255 on indexed string columns,
	// matching the Android component-table convention).
	BundleIdentifier string `json:"bundleIdentifier" gorm:"column:bundle_identifier;size:255;index:idx_bundle_identifier"`
	BundleVersion    string `json:"bundleVersion" gorm:"column:bundle_version;size:255"`
	DeploymentTarget string `json:"deploymentTarget" gorm:"column:deployment_target;size:255"` // MinimumOSVersion / min OS
	ExecutableName   string `json:"executableName" gorm:"column:executable_name;size:255"`

	// Mach-O binary attributes.
	Architectures string `json:"architectures" gorm:"type:json;column:architectures"`  // JSON array of arch names (e.g. ["arm64","x86_64"])
	IsEncrypted   bool   `json:"isEncrypted" gorm:"column:is_encrypted;default:false"` // FairPlay: any LC_ENCRYPTION_INFO(_64) with cryptid != 0

	// Variable-length extracted data, stored as marshalled JSON.
	URLSchemes    string `json:"urlSchemes" gorm:"type:json;column:url_schemes"`       // JSON array of CFBundleURLSchemes
	Entitlements  string `json:"entitlements" gorm:"type:json;column:entitlements"`    // JSON object of embedded entitlements
	Frameworks    string `json:"frameworks" gorm:"type:json;column:frameworks"`        // JSON array of linked/embedded framework names
	ATSExceptions string `json:"atsExceptions" gorm:"type:json;column:ats_exceptions"` // JSON object of NSAppTransportSecurity exceptions

	// Relationship
	Secret Secret `json:"-" gorm:"foreignKey:SecretID"`
}

// TableName specifies the table name for IOSMetadata
// BeforeSave guarantees every `type:json` column holds a syntactically valid
// JSON document before it reaches MySQL. The extraction pipeline may leave a
// JSON field empty (e.g. no entitlements, no URL schemes), and MySQL rejects an
// empty string in a JSON column with Error 3140 ("The document is empty"),
// which would roll back the entire secret-persistence transaction and silently
// drop ALL findings for the scan. Coercing empty/invalid values to a valid
// empty container ("[]" for arrays, "{}" for objects) makes persistence robust
// regardless of what the extractor produced.
func (m *IOSMetadata) BeforeSave(*gorm.DB) error {
	m.Architectures = ensureJSON(m.Architectures, "[]")
	m.URLSchemes = ensureJSON(m.URLSchemes, "[]")
	m.Frameworks = ensureJSON(m.Frameworks, "[]")
	m.Entitlements = ensureJSON(m.Entitlements, "{}")
	m.ATSExceptions = ensureJSON(m.ATSExceptions, "{}")
	return nil
}

// ensureJSON returns s if it is non-empty valid JSON, otherwise the fallback
// (a valid empty JSON container).
func ensureJSON(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" || !json.Valid([]byte(s)) {
		return fallback
	}
	return s
}

func (IOSMetadata) TableName() string {
	return "ios_metadata"
}
