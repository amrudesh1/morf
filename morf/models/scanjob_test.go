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
	"testing"
	"time"
)

// TestScanJobRoundTrip verifies basic ToMap→FromMap round-trip fidelity.
func TestScanJobRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	original := &ScanJob{
		ID:               "job-123",
		Status:           JobStatusProcessing,
		APKPath:          "/tmp/test.apk",
		OriginalFilename: "test.apk",
		CreatedAt:        now,
		StartedAt:        &now,
		Error:            "transient error",
		WorkerID:         "worker-1",
		RetryCount:       1,
		StorageKey:       "uploads/2024/test.apk",
	}

	m := original.ToMap()

	restored := &ScanJob{}
	if err := restored.FromMap(m); err != nil {
		t.Fatalf("FromMap returned error: %v", err)
	}

	if restored.ID != original.ID {
		t.Errorf("ID: got %q, want %q", restored.ID, original.ID)
	}
	if restored.Status != original.Status {
		t.Errorf("Status: got %q, want %q", restored.Status, original.Status)
	}
	if restored.Error != original.Error {
		t.Errorf("Error: got %q, want %q", restored.Error, original.Error)
	}
	if restored.WorkerID != original.WorkerID {
		t.Errorf("WorkerID: got %q, want %q", restored.WorkerID, original.WorkerID)
	}
	if restored.RetryCount != original.RetryCount {
		t.Errorf("RetryCount: got %d, want %d", restored.RetryCount, original.RetryCount)
	}
	if restored.StorageKey != original.StorageKey {
		t.Errorf("StorageKey: got %q, want %q", restored.StorageKey, original.StorageKey)
	}
	if restored.StartedAt == nil {
		t.Fatal("StartedAt: got nil, want non-nil")
	}
	if !restored.StartedAt.Equal(*original.StartedAt) {
		t.Errorf("StartedAt: got %v, want %v", restored.StartedAt, original.StartedAt)
	}
}

// TestScanJobClearedFieldsOverwrite is the CONC-8 regression test.
// It verifies that after clearing Error and StartedAt, ToMap still emits the
// keys (with empty values) so a Redis HSet will overwrite stale data.
func TestScanJobClearedFieldsOverwrite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	job := &ScanJob{
		ID:         "job-456",
		Status:     JobStatusFailed,
		APKPath:    "/tmp/test.apk",
		CreatedAt:  now,
		StartedAt:  &now,
		Error:      "disk full",
		WorkerID:   "worker-2",
		RetryCount: 1,
		StorageKey: "uploads/test.apk",
	}

	// Simulate retry: clear mutable fields.
	job.Status = JobStatusQueued
	job.Error = ""
	job.StartedAt = nil
	job.WorkerID = ""

	m := job.ToMap()

	// CONC-8: keys must be present even when the value is empty.
	errVal, hasError := m["error"]
	if !hasError {
		t.Error("ToMap: 'error' key missing after Error cleared — Redis HSet won't overwrite stale value")
	} else if errVal != "" {
		t.Errorf("ToMap: 'error' = %q, want empty string", errVal)
	}

	startedVal, hasStarted := m["started_at"]
	if !hasStarted {
		t.Error("ToMap: 'started_at' key missing after StartedAt cleared — Redis HSet won't overwrite stale value")
	} else if startedVal != "" {
		t.Errorf("ToMap: 'started_at' = %q, want empty string", startedVal)
	}

	workerVal, hasWorker := m["worker_id"]
	if !hasWorker {
		t.Error("ToMap: 'worker_id' key missing after WorkerID cleared")
	} else if workerVal != "" {
		t.Errorf("ToMap: 'worker_id' = %q, want empty string", workerVal)
	}

	// FromMap of the cleared map must yield zero values.
	restored := &ScanJob{}
	if err := restored.FromMap(m); err != nil {
		t.Fatalf("FromMap returned error: %v", err)
	}
	if restored.Error != "" {
		t.Errorf("FromMap: Error = %q, want empty string", restored.Error)
	}
	if restored.StartedAt != nil {
		t.Errorf("FromMap: StartedAt = %v, want nil", restored.StartedAt)
	}
	if restored.WorkerID != "" {
		t.Errorf("FromMap: WorkerID = %q, want empty string", restored.WorkerID)
	}
}

// TestScanJobStorageKeyRoundTrip exercises StorageKey specifically.
func TestScanJobStorageKeyRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	job := &ScanJob{
		ID:         "job-789",
		Status:     JobStatusQueued,
		APKPath:    "/tmp/app.apk",
		CreatedAt:  now,
		StorageKey: "bucket/prefix/app-v1.2.3.apk",
	}

	m := job.ToMap()
	if v, ok := m["storage_key"]; !ok {
		t.Error("ToMap: 'storage_key' key missing")
	} else if v != job.StorageKey {
		t.Errorf("ToMap: 'storage_key' = %q, want %q", v, job.StorageKey)
	}

	restored := &ScanJob{}
	if err := restored.FromMap(m); err != nil {
		t.Fatalf("FromMap returned error: %v", err)
	}
	if restored.StorageKey != job.StorageKey {
		t.Errorf("FromMap: StorageKey = %q, want %q", restored.StorageKey, job.StorageKey)
	}

	// Cleared StorageKey must also round-trip.
	job.StorageKey = ""
	m2 := job.ToMap()
	if v, ok := m2["storage_key"]; !ok {
		t.Error("ToMap: 'storage_key' key missing after clearing")
	} else if v != "" {
		t.Errorf("ToMap: 'storage_key' = %q after clearing, want empty string", v)
	}

	restored2 := &ScanJob{}
	if err := restored2.FromMap(m2); err != nil {
		t.Fatalf("FromMap returned error: %v", err)
	}
	if restored2.StorageKey != "" {
		t.Errorf("FromMap: StorageKey = %q after clearing, want empty string", restored2.StorageKey)
	}
}
