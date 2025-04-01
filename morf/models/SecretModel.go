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
)

// SecretModel represents a single secret found in the code
type SecretModel struct {
	Type             string `json:"type"`
	LineNo           int    `json:"lineNo"`
	FileLocation     string `json:"fileLocation"`
	SecretType       string `json:"secretType"`
	SecretString     string `json:"secretString"`
	SecretConfidence string `json:"secretConfidence"`
}

// SecretModelArray is a custom type for handling arrays of SecretModel in MySQL
type SecretModelArray []SecretModel

// Scan implements sql.Scanner interface
func (s *SecretModelArray) Scan(value interface{}) error {
	if value == nil {
		*s = SecretModelArray{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal SecretModelArray value")
	}

	return json.Unmarshal(bytes, s)
}

// Value implements driver.Valuer interface
func (s SecretModelArray) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}
