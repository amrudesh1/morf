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
	"time"

	"gorm.io/gorm"
)

// APIKey represents an API key for authentication
type APIKey struct {
	gorm.Model
	Key       string          `json:"key" gorm:"column:key;uniqueIndex:idx_api_key"`
	Name      string          `json:"name" gorm:"column:name"`
	Scopes    JSONStringArray `json:"scopes" gorm:"type:json;column:scopes"`
	RateLimit int             `json:"rateLimit" gorm:"column:rate_limit;default:100"` // requests per hour
	CreatedAt time.Time       `json:"createdAt" gorm:"column:created_at"`
	ExpiresAt *time.Time      `json:"expiresAt,omitempty" gorm:"column:expires_at"`
	LastUsed  *time.Time      `json:"lastUsed,omitempty" gorm:"column:last_used"`
	IsActive  bool            `json:"isActive" gorm:"column:is_active;default:true"`
}

// TableName specifies the table name for the APIKey model
func (APIKey) TableName() string {
	return "api_keys"
}

// IsExpired checks if the API key has expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid checks if the API key is valid (active and not expired)
func (k *APIKey) IsValid() bool {
	return k.IsActive && !k.IsExpired()
}

// HasScope checks if the API key has a specific scope
func (k *APIKey) HasScope(scope string) bool {
	if len(k.Scopes) == 0 {
		return true // No scopes means all access
	}
	for _, s := range k.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}
