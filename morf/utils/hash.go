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

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
)

// ExtractHash calculates the SHA-256 hash of a file
func ExtractHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Error("Error opening file for hashing:", err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		log.Error("Error calculating file hash:", err)
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil)[:16])
}

// ValidateHash checks if a file matches a given hash
