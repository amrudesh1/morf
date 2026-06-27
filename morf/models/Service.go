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

// Service represents a service component (normalized)
type Service struct {
	gorm.Model
	SecretID uint   `json:"secretId" gorm:"column:secret_id;index:idx_secret_id;not null"`
	Name     string `json:"name" gorm:"column:name;index:idx_name;not null"`
	Exported bool   `json:"exported" gorm:"column:exported;index:idx_exported;default:false"`

	// Relationship
	Secret Secret `json:"-" gorm:"foreignKey:SecretID"`
}

// TableName specifies the table name for Service
func (Service) TableName() string {
	return "services"
}
