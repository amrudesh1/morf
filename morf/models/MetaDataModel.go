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
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

// JSONStringArray is a custom type for handling string arrays in MySQL JSON columns
type JSONStringArray []string

func (a *JSONStringArray) Scan(value interface{}) error {
	if value == nil {
		*a = JSONStringArray{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal JSONStringArray value")
	}

	// Handle empty array case
	if len(bytes) == 0 {
		*a = JSONStringArray{}
		return nil
	}

	// If the value is already a JSON array, unmarshal it directly
	if bytes[0] == '[' {
		if err := json.Unmarshal(bytes, a); err != nil {
			log.Errorf("Error unmarshaling JSON array: %v", err)
			*a = JSONStringArray{}
			return nil
		}
		return nil
	}

	// If it's a single value, create a single-element array
	var singleValue string
	if err := json.Unmarshal(bytes, &singleValue); err == nil {
		*a = JSONStringArray{singleValue}
		return nil
	}

	// Try to handle comma-separated string
	if strings.Contains(string(bytes), ",") {
		values := strings.Split(string(bytes), ",")
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		*a = JSONStringArray(values)
		return nil
	}

	// Default to empty array on error
	*a = JSONStringArray{}
	return nil
}

func (a JSONStringArray) Value() (driver.Value, error) {
	if a == nil {
		return json.Marshal([]string{}) // Return empty array instead of null
	}

	// Clean up the array
	cleanArray := make([]string, 0, len(a))
	for _, s := range a {
		if s = strings.TrimSpace(s); s != "" {
			cleanArray = append(cleanArray, s)
		}
	}

	// Marshal the array
	bytes, err := json.Marshal(cleanArray)
	if err != nil {
		log.Errorf("Error marshaling JSONStringArray: %v", err)
		return json.Marshal([]string{}) // Return empty array on error
	}

	// If the result is "null", return empty array instead
	if string(bytes) == "null" {
		return json.Marshal([]string{})
	}

	return bytes, nil
}

// MetaDataModel represents metadata extracted from an APK file
type MetaDataModel struct {
	FileName        string `json:"fileName"`
	FileSize        int    `json:"fileSize"`
	DexSize         int    `json:"dexSize"`
	ArscSize        int    `json:"arscSize"`
	AndroidManifest struct {
		PackageName                string                                   `json:"packageName"`
		VersionCode                string                                   `json:"versionCode"`
		NumberOfActivities         int                                      `json:"numberOfActivities"`
		NumberOfServices           int                                      `json:"numberOfServices"`
		NumberOfContentProviders   int                                      `json:"numberOfContentProviders"`
		NumberOfBroadcastReceivers int                                      `json:"numberOfBroadcastReceivers"`
		Activities                 JSONComponentArray[ManifestActivityInfo] `gorm:"type:json;default:'[]'" json:"activities"`
		Services                   JSONComponentArray[ManifestServiceInfo]  `gorm:"type:json;default:'[]'" json:"services"`
		ContentProviders           JSONComponentArray[ManifestProviderInfo] `gorm:"type:json;default:'[]'" json:"contentProviders"`
		BroadcastReceivers         JSONComponentArray[ManifestReceiverInfo] `gorm:"type:json;default:'[]'" json:"broadcastReceivers"`
		UsesPermissions            JSONStringArray                          `gorm:"type:json" json:"usesPermissions"`
		UsesLibrary                JSONStringArray                          `gorm:"type:json" json:"usesLibrary"`
		UsesFeature                JSONStringArray                          `gorm:"type:json" json:"usesFeature"`
		Permissions                JSONStringArray                          `gorm:"type:json" json:"permissions"`
		PermissionsProtectionLevel JSONStringArray                          `gorm:"type:json" json:"permissionsProtectionLevel"`
		UsesMinSdkVersion          string                                   `json:"usesMinSdkVersion"`
		UsesTargetSdkVersion       string                                   `json:"usesTargetSdkVersion"`
		UsesMaxSdkVersion          string                                   `json:"usesMaxSdkVersion"`
	} `gorm:"embedded;" json:"androidManifest"`
	CertificateDatas struct {
		FileName         string `json:"fileName"`
		SignAlgorithm    string `json:"signAlgorithm"`
		SignAlgorithmOID string `json:"signAlgorithmOID"`
		StartDate        string `json:"startDate"`
		EndDate          string `json:"endDate"`
		PublicKeyMd5     string `json:"publicKeyMd5"`
		CertBase64Md5    string `json:"certBase64Md5"`
		CertMd5          string `json:"certMd5"`
		Version          int    `json:"version"`
		IssuerName       string `json:"issuerName"`
		SubjectName      string `json:"subjectName"`
	} `gorm:"embedded;"`
	ResourceData ResourceData `gorm:"embedded;" json:"resourceData"`
	FileDigest   struct {
	} `gorm:"embedded;" json:"fileDigest" `
}
