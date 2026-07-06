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
	"morf/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareScans(t *testing.T) {
	// Create test scan jobs
	job1 := &models.ScanJob{
		ID: "job1",
		Result: `{
			"data": {
				"secrets": [
					{
						"secretString": "secret1",
						"fileLocation": "file1.java",
						"lineNo": 10
					},
					{
						"secretString": "secret2",
						"fileLocation": "file2.java",
						"lineNo": 20
					}
				]
			}
		}`,
	}

	job2 := &models.ScanJob{
		ID: "job2",
		Result: `{
			"data": {
				"secrets": [
					{
						"secretString": "secret2",
						"fileLocation": "file2.java",
						"lineNo": 20
					},
					{
						"secretString": "secret3",
						"fileLocation": "file3.java",
						"lineNo": 30
					}
				]
			}
		}`,
	}

	// Compare scans
	result, err := CompareScans(job1, job2)
	assert.NoError(t, err, "CompareScans should not return error")
	assert.NotNil(t, result, "Result should not be nil")

	// Verify job IDs
	assert.Equal(t, "job1", result.JobID1)
	assert.Equal(t, "job2", result.JobID2)

	// Verify counts
	assert.Equal(t, 2, result.TotalJob1, "Job1 should have 2 secrets")
	assert.Equal(t, 2, result.TotalJob2, "Job2 should have 2 secrets")
	assert.Equal(t, 1, result.AddedCount, "Should have 1 added secret")
	assert.Equal(t, 1, result.RemovedCount, "Should have 1 removed secret")
	assert.Equal(t, 1, result.UnchangedCount, "Should have 1 unchanged secret")

	// Verify added secret
	assert.Len(t, result.Added, 1, "Should have 1 added secret")
	assert.Equal(t, "secret3", result.Added[0]["secretString"])

	// Verify removed secret
	assert.Len(t, result.Removed, 1, "Should have 1 removed secret")
	assert.Equal(t, "secret1", result.Removed[0]["secretString"])

	// Verify unchanged secret
	assert.Len(t, result.Unchanged, 1, "Should have 1 unchanged secret")
	assert.Equal(t, "secret2", result.Unchanged[0]["secretString"])
}

func TestCompareScansEmpty(t *testing.T) {
	// Test with empty scans
	job1 := &models.ScanJob{
		ID:     "job1",
		Result: `{"data": {"secrets": []}}`,
	}

	job2 := &models.ScanJob{
		ID:     "job2",
		Result: `{"data": {"secrets": []}}`,
	}

	result, err := CompareScans(job1, job2)
	assert.NoError(t, err, "CompareScans should not return error")
	assert.Equal(t, 0, result.TotalJob1)
	assert.Equal(t, 0, result.TotalJob2)
	assert.Equal(t, 0, result.AddedCount)
	assert.Equal(t, 0, result.RemovedCount)
	assert.Equal(t, 0, result.UnchangedCount)
}

func TestCompareScansInvalidJSON(t *testing.T) {
	job1 := &models.ScanJob{
		ID:     "job1",
		Result: `invalid json`,
	}

	job2 := &models.ScanJob{
		ID:     "job2",
		Result: `{"data": {"secrets": []}}`,
	}

	_, err := CompareScans(job1, job2)
	assert.Error(t, err, "Should return error for invalid JSON")
}

func TestGetSecretKey(t *testing.T) {
	// camelCase string lineNo (matches stored contract; lineNo may decode as string in some paths)
	secret := map[string]interface{}{
		"secretString": "test_secret",
		"fileLocation": "test.java",
		"lineNo":       "42",
	}

	key := getSecretKey(secret)
	assert.Equal(t, "test_secret|test.java|42", key, "Secret key should match expected format")

	// Numeric lineNo as stored: SecretModel.LineNo is an int → decodes as float64.
	secret2 := map[string]interface{}{
		"secretString": "test_secret",
		"fileLocation": "test.java",
		"lineNo":       42.0,
	}

	key2 := getSecretKey(secret2)
	assert.Equal(t, "test_secret|test.java|42", key2, "Numeric lineNo should be converted to string")
}

func TestExtractSecrets(t *testing.T) {
	resultData := map[string]interface{}{
		"data": map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{
					"secretString": "secret1",
					"fileLocation": "file1.java",
				},
				map[string]interface{}{
					"secretString": "secret2",
					"fileLocation": "file2.java",
				},
			},
		},
	}

	secrets := extractSecrets(resultData)
	assert.Len(t, secrets, 2, "Should extract 2 secrets")
	assert.Equal(t, "secret1", secrets[0]["secretString"])
	assert.Equal(t, "secret2", secrets[1]["secretString"])

	// Test with no secrets
	resultData2 := map[string]interface{}{
		"data": map[string]interface{}{
			"secrets": []interface{}{},
		},
	}

	secrets2 := extractSecrets(resultData2)
	assert.Len(t, secrets2, 0, "Should return empty slice for no secrets")
}
