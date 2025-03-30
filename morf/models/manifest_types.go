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

	log "github.com/sirupsen/logrus"
)

// Component types for Android manifest parsing

// ManifestActivityInfo represents information about an Android activity
type ManifestActivityInfo struct {
	Name          string           `json:"name"`
	Exported      bool             `json:"exported"`
	IntentFilters []ManifestFilter `json:"intentFilters,omitempty"`
}

// ManifestServiceInfo represents information about an Android service
type ManifestServiceInfo struct {
	Name          string           `json:"name"`
	Exported      bool             `json:"exported"`
	IntentFilters []ManifestFilter `json:"intentFilters,omitempty"`
}

// ManifestReceiverInfo represents information about an Android broadcast receiver
type ManifestReceiverInfo struct {
	Name          string           `json:"name"`
	Exported      bool             `json:"exported"`
	IntentFilters []ManifestFilter `json:"intentFilters,omitempty"`
}

// ManifestProviderInfo represents information about an Android content provider
type ManifestProviderInfo struct {
	Name        string   `json:"name"`
	Exported    bool     `json:"exported"`
	Authorities []string `json:"authorities,omitempty"`
}

// ManifestFilter represents an intent filter in the Android manifest
type ManifestFilter struct {
	Actions    []string             `json:"actions,omitempty"`
	Categories []string             `json:"categories,omitempty"`
	Data       []ManifestFilterData `json:"data,omitempty"`
	Priority   int                  `json:"priority"`
	AutoVerify bool                 `json:"autoVerify"`
}

// ManifestFilterData represents the data section of an intent filter
type ManifestFilterData struct {
	Scheme      string   `json:"scheme,omitempty"`
	Host        string   `json:"host,omitempty"`
	Port        string   `json:"port,omitempty"`
	Path        string   `json:"path,omitempty"`
	PathPrefix  []string `json:"pathPrefix,omitempty"`
	PathPattern string   `json:"pathPattern,omitempty"`
	MimeType    string   `json:"mimeType,omitempty"`
}

// Custom types for database handling

// JSONComponentArray is a custom type for handling arrays of components in MySQL JSON columns
type JSONComponentArray[T any] []T

func (a *JSONComponentArray[T]) Scan(value interface{}) error {
	if value == nil {
		*a = JSONComponentArray[T]{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal JSONComponentArray value")
	}

	// Handle empty array case
	if len(bytes) == 0 {
		*a = JSONComponentArray[T]{}
		return nil
	}

	// If the value is already a JSON array, unmarshal it directly
	if bytes[0] == '[' {
		if err := json.Unmarshal(bytes, a); err != nil {
			log.Errorf("Error unmarshaling JSON array: %v", err)
			*a = JSONComponentArray[T]{}
			return nil
		}
		return nil
	}

	// Default to empty array on error
	*a = JSONComponentArray[T]{}
	return nil
}

func (a JSONComponentArray[T]) Value() (driver.Value, error) {
	if a == nil {
		return json.Marshal([]T{}) // Return empty array instead of null
	}

	// Marshal the array
	bytes, err := json.Marshal(a)
	if err != nil {
		log.Errorf("Error marshaling JSONComponentArray: %v", err)
		return json.Marshal([]T{}) // Return empty array on error
	}

	// If the result is "null", return empty array instead
	if string(bytes) == "null" {
		return json.Marshal([]T{})
	}

	return bytes, nil
}
