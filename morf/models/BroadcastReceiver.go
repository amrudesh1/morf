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

// BroadcastReceiver represents a broadcast receiver component (normalized)
type BroadcastReceiver struct {
	gorm.Model
	SecretID      uint   `json:"secretId" gorm:"column:secret_id;index:idx_secret_id;not null"`
	Name          string `json:"name" gorm:"column:name;size:255;index:idx_name;not null"`
	Exported      bool   `json:"exported" gorm:"column:exported;index:idx_exported;default:false"`
	IntentFilters string `json:"intentFilters" gorm:"type:json;column:intent_filters"`

	// Relationship
	Secret Secret `json:"-" gorm:"foreignKey:SecretID"`
}

// TableName specifies the table name for BroadcastReceiver
func (BroadcastReceiver) TableName() string {
	return "broadcast_receivers"
}
