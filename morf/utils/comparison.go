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
	"encoding/json"
	"fmt"
	"morf/models"
)

// ComparisonResult represents the result of comparing two scans
type ComparisonResult struct {
	JobID1         string                   `json:"job_id_1"`
	JobID2         string                   `json:"job_id_2"`
	Added          []map[string]interface{} `json:"added"`     // Secrets found in job2 but not in job1
	Removed        []map[string]interface{} `json:"removed"`   // Secrets found in job1 but not in job2
	Unchanged      []map[string]interface{} `json:"unchanged"` // Secrets found in both
	TotalJob1      int                      `json:"total_job_1"`
	TotalJob2      int                      `json:"total_job_2"`
	AddedCount     int                      `json:"added_count"`
	RemovedCount   int                      `json:"removed_count"`
	UnchangedCount int                      `json:"unchanged_count"`
}

// extractSecrets extracts secrets from a pre-decoded map[string]interface{}.
// Retained for backward compatibility with existing tests.
func extractSecrets(resultData map[string]interface{}) []map[string]interface{} {
	secrets := make([]map[string]interface{}, 0)
	if data, ok := resultData["data"].(map[string]interface{}); ok {
		if secretsArray, ok := data["secrets"].([]interface{}); ok {
			for _, secretInterface := range secretsArray {
				if secretMap, ok := secretInterface.(map[string]interface{}); ok {
					secrets = append(secrets, secretMap)
				}
			}
		}
	}
	return secrets
}

// getSecretKey generates a unique key for a secret based on its content.
// Retained for backward compatibility with existing tests.
func getSecretKey(secret map[string]interface{}) string {
	secretString := ""
	fileLocation := ""
	lineNo := ""

	if val, ok := secret["secret_string"].(string); ok {
		secretString = val
	}
	if val, ok := secret["file_location"].(string); ok {
		fileLocation = val
	}
	if val, ok := secret["line_no"].(string); ok {
		lineNo = val
	} else if val, ok := secret["line_no"].(float64); ok {
		lineNo = fmt.Sprintf("%.0f", val)
	}

	return fmt.Sprintf("%s|%s|%s", secretString, fileLocation, lineNo)
}

// CompareScans compares two scan results and returns the differences.
// It operates on the schemaless result JSON (snake_case keys; line_no may be a
// string or a number), which is the stored format and the tested contract.
// CMP-1: index maps and result slices are pre-sized to cut allocation churn; a
// full typed decode was intentionally NOT used here because the result shape is
// dynamic and the output contract is map-based (see TestExtractSecrets/TestGetSecretKey).
func CompareScans(job1 *models.ScanJob, job2 *models.ScanJob) (*ComparisonResult, error) {
	var data1, data2 map[string]interface{}
	if err := json.Unmarshal([]byte(job1.Result), &data1); err != nil {
		return nil, fmt.Errorf("failed to parse job1 result: %v", err)
	}
	if err := json.Unmarshal([]byte(job2.Result), &data2); err != nil {
		return nil, fmt.Errorf("failed to parse job2 result: %v", err)
	}

	secrets1 := extractSecrets(data1)
	secrets2 := extractSecrets(data2)

	idx1 := make(map[string]struct{}, len(secrets1))
	for _, s := range secrets1 {
		idx1[getSecretKey(s)] = struct{}{}
	}
	idx2 := make(map[string]struct{}, len(secrets2))
	for _, s := range secrets2 {
		idx2[getSecretKey(s)] = struct{}{}
	}

	added := make([]map[string]interface{}, 0, len(secrets2))
	removed := make([]map[string]interface{}, 0, len(secrets1))
	unchanged := make([]map[string]interface{}, 0, len(secrets1))

	// Secrets in job2 but not in job1 → added.
	for _, s := range secrets2 {
		if _, exists := idx1[getSecretKey(s)]; !exists {
			added = append(added, s)
		}
	}
	// Secrets in job1: in both → unchanged, else removed.
	for _, s := range secrets1 {
		if _, exists := idx2[getSecretKey(s)]; exists {
			unchanged = append(unchanged, s)
		} else {
			removed = append(removed, s)
		}
	}

	return &ComparisonResult{
		JobID1:         job1.ID,
		JobID2:         job2.ID,
		Added:          added,
		Removed:        removed,
		Unchanged:      unchanged,
		TotalJob1:      len(secrets1),
		TotalJob2:      len(secrets2),
		AddedCount:     len(added),
		RemovedCount:   len(removed),
		UnchangedCount: len(unchanged),
	}, nil
}
