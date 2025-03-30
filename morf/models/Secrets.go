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

// Secrets represents the main model for storing scan results
type Secrets struct {
	gorm.Model
	FileName           string                                   `json:"fileName" gorm:"column:file_name"`
	APKHash            string                                   `json:"apkHash" gorm:"column:apk_hash"`
	APKVersion         string                                   `json:"apkVersion" gorm:"column:apk_version"`
	SecretModel        SecretModelArray                         `json:"secretModel" gorm:"type:json;column:secret_model"`
	Metadata           MetaDataModel                            `json:"metadata" gorm:"embedded"`
	PackageDataModel   PackageDataModel                         `json:"packageDataModel" gorm:"embedded"`
	Activities         JSONComponentArray[ManifestActivityInfo] `json:"activities" gorm:"type:json;column:activities"`
	Services           JSONComponentArray[ManifestServiceInfo]  `json:"services" gorm:"type:json;column:services"`
	ContentProviders   JSONComponentArray[ManifestProviderInfo] `json:"contentProviders" gorm:"type:json;column:content_providers"`
	BroadcastReceivers JSONComponentArray[ManifestReceiverInfo] `json:"broadcastReceivers" gorm:"type:json;column:broadcast_receivers"`
}

// BeforeSave ensures arrays are initialized before saving
func (s *Secrets) BeforeSave(tx *gorm.DB) error {
	if s.Activities == nil {
		s.Activities = JSONComponentArray[ManifestActivityInfo]{}
	}
	if s.Services == nil {
		s.Services = JSONComponentArray[ManifestServiceInfo]{}
	}
	if s.ContentProviders == nil {
		s.ContentProviders = JSONComponentArray[ManifestProviderInfo]{}
	}
	if s.BroadcastReceivers == nil {
		s.BroadcastReceivers = JSONComponentArray[ManifestReceiverInfo]{}
	}
	return nil
}

// TableName specifies the table name for the Secrets model
func (Secrets) TableName() string {
	return "secrets"
}
