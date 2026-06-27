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
	"bytes"
	"morf/models"
	"testing"
	"time"
)

// TestExportPDFValidStructure verifies that exportPDF produces bytes that
// start with the %%PDF- header and end with %%%%EOF, confirming the output
// is a structurally valid PDF rather than plain text mislabelled as
// application/pdf (EXPORT-1).
func TestExportPDFValidStructure(t *testing.T) {
	job := &models.ScanJob{
		ID:               "test-job-001",
		Status:           models.JobStatusCompleted,
		OriginalFilename: "example.apk",
		CreatedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	result := &scanResultPayload{
		Message: "Success",
		Data: scanResultData{
			FileName:    "example.apk",
			PackageName: "com.example.app",
			Version:     "1.2.3",
			SecretCount: 1,
			Secrets: []models.SecretModel{
				{
					Type:             "api_key",
					LineNo:           42,
					FileLocation:     "res/values/strings.xml",
					SecretType:       "AWS_ACCESS_KEY",
					SecretString:     "AKIAIOSFODNN7EXAMPLE",
					SecretConfidence: "high",
				},
			},
		},
	}

	data, ct, err := exportPDF(job, result)
	if err != nil {
		t.Fatalf("exportPDF returned error: %v", err)
	}
	if ct != "application/pdf" {
		t.Errorf("content type = %q; want application/pdf", ct)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Errorf("PDF output does not start with %%PDF-; got prefix %q", data[:min(20, len(data))])
	}
	trimmed := bytes.TrimRight(data, "\r\n ")
	if !bytes.HasSuffix(trimmed, []byte("%%EOF")) {
		t.Errorf("PDF output does not end with %%%%EOF; tail = %q", trimmed[max(0, len(trimmed)-10):])
	}
}
