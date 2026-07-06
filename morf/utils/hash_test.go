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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractHash(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test content
	testContent := "test content for hashing"
	_, err = tmpFile.WriteString(testContent)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test hash extraction
	hash := ExtractHash(tmpFile.Name())
	assert.NotEmpty(t, hash, "Hash should not be empty")
	assert.Len(t, hash, 32, "Hash should be 32 characters (16 bytes hex encoded)")

	// Test with same file - should produce same hash
	hash2 := ExtractHash(tmpFile.Name())
	assert.Equal(t, hash, hash2, "Same file should produce same hash")

	// Test with non-existent file
	hash3 := ExtractHash("/nonexistent/file/path")
	assert.Empty(t, hash3, "Non-existent file should return empty hash")
}
