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
	"encoding/json"
	"fmt"
	"time"
)

// JobStatus represents the status of a scan job
type JobStatus string

const (
	JobStatusQueued     JobStatus = "queued"
	JobStatusProcessing JobStatus = "processing"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusCancelled  JobStatus = "cancelled"
)

// ScanJob represents a scan job in the queue
type ScanJob struct {
	ID               string            `json:"id"`
	Status           JobStatus         `json:"status"`
	APKPath          string            `json:"apk_path"`
	FileType         string            `json:"file_type,omitempty"` // Platform discriminator derived from the uploaded file extension: "apk" (Android) or "ipa" (iOS). Empty is treated as "apk" for backward compatibility.
	OriginalFilename string            `json:"original_filename"`
	CreatedAt        time.Time         `json:"created_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
	FailedAt         *time.Time        `json:"failed_at,omitempty"`
	Error            string            `json:"error,omitempty"`
	Phase            string            `json:"phase,omitempty"`  // Coarse in-progress stage for the UI stepper (unpacking|parsing|scanning|compiling). Advisory; written via SetJobPhase, never through ToMap.
	Result           string            `json:"result,omitempty"` // JSON string
	WorkerID         string            `json:"worker_id,omitempty"`
	RetryCount       int               `json:"retry_count"`
	WebhookURL       string            `json:"webhook_url,omitempty"`    // Webhook URL for notifications
	WebhookSecret    string            `json:"webhook_secret,omitempty"` // Secret for webhook signature
	ScanTimeout      int               `json:"scan_timeout,omitempty"`   // Timeout in seconds (0 = use default)
	StorageKey       string            `json:"storage_key,omitempty"`    // Object key in the storage backend for the uploaded APK
	RequestID        string            `json:"request_id,omitempty"`     // Originating HTTP request/correlation ID (X-Request-ID) captured at enqueue, so an upload can be traced to its async scan logs across the queue boundary
	TraceContext     map[string]string `json:"traceContext,omitempty"`   // W3C TraceContext carrier injected at enqueue; extracted by the worker to continue the distributed trace across the async Redis boundary
}

// formatTimePtr formats a *time.Time for Redis: RFC3339 when set, empty string when nil.
// This ensures a cleared timestamp actually overwrites the old value in the Redis hash
// (HSet is additive; omitting the key leaves the old value).
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// ToMap converts ScanJob to map[string]interface{} for Redis storage.
//
// Mutable status fields (status, error, started_at, failed_at, completed_at,
// worker_id, retry_count, storage_key) are ALWAYS included, even when empty.
// This is required so that a Redis HSet call overwrites stale values when a
// job is retried — omitting a key leaves the old value in the hash (CONC-8).
func (j *ScanJob) ToMap() map[string]interface{} {
	m := make(map[string]interface{})

	// Immutable identity fields — always present.
	m["id"] = j.ID
	m["apk_path"] = j.APKPath
	m["original_filename"] = j.OriginalFilename
	m["created_at"] = j.CreatedAt.Format(time.RFC3339)

	// Mutable status fields — always included so cleared values overwrite Redis.
	m["status"] = string(j.Status)
	m["error"] = j.Error
	m["worker_id"] = j.WorkerID
	m["retry_count"] = j.RetryCount
	m["storage_key"] = j.StorageKey
	m["started_at"] = formatTimePtr(j.StartedAt)
	m["completed_at"] = formatTimePtr(j.CompletedAt)
	m["failed_at"] = formatTimePtr(j.FailedAt)

	// Append-only / creation-time fields — omitted when empty to keep hashes lean.
	if j.Result != "" {
		m["result"] = j.Result
	}
	if j.WebhookURL != "" {
		m["webhook_url"] = j.WebhookURL
	}
	if j.WebhookSecret != "" {
		m["webhook_secret"] = j.WebhookSecret
	}
	if j.ScanTimeout > 0 {
		m["scan_timeout"] = j.ScanTimeout
	}
	// Correlation ID captured at enqueue; immutable once set, so it is
	// omitted-when-empty like the other creation-time fields.
	if j.RequestID != "" {
		m["request_id"] = j.RequestID
	}
	// Platform discriminator ("apk"/"ipa") captured at enqueue; immutable once
	// set, so it is omitted-when-empty like the other creation-time fields. An
	// absent value is read back as "" and treated as Android by consumers.
	if j.FileType != "" {
		m["file_type"] = j.FileType
	}
	// W3C TraceContext carrier: JSON-serialised map of tracestate/traceparent
	// headers injected at upload and extracted by the worker so OTel spans
	// propagate across the async Redis boundary.
	if len(j.TraceContext) > 0 {
		if b, err := json.Marshal(j.TraceContext); err == nil {
			m["trace_context"] = string(b)
		}
	}
	return m
}

// FromMap creates ScanJob from map[string]interface{} from Redis
func (j *ScanJob) FromMap(m map[string]interface{}) error {
	if id, ok := m["id"].(string); ok {
		j.ID = id
	}
	if status, ok := m["status"].(string); ok {
		j.Status = JobStatus(status)
	}
	if apkPath, ok := m["apk_path"].(string); ok {
		j.APKPath = apkPath
	}
	if filename, ok := m["original_filename"].(string); ok {
		j.OriginalFilename = filename
	}
	if createdAt, ok := m["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			j.CreatedAt = t
		}
	}
	// For *time.Time fields, an empty string sentinel means "cleared" → nil.
	if startedAt, ok := m["started_at"].(string); ok {
		if startedAt == "" {
			j.StartedAt = nil
		} else if t, err := time.Parse(time.RFC3339, startedAt); err == nil {
			j.StartedAt = &t
		}
	}
	if completedAt, ok := m["completed_at"].(string); ok {
		if completedAt == "" {
			j.CompletedAt = nil
		} else if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
			j.CompletedAt = &t
		}
	}
	if failedAt, ok := m["failed_at"].(string); ok {
		if failedAt == "" {
			j.FailedAt = nil
		} else if t, err := time.Parse(time.RFC3339, failedAt); err == nil {
			j.FailedAt = &t
		}
	}
	if err, ok := m["error"].(string); ok {
		j.Error = err
	}
	if phase, ok := m["phase"].(string); ok {
		j.Phase = phase
	}
	if result, ok := m["result"].(string); ok {
		j.Result = result
	}
	if workerID, ok := m["worker_id"].(string); ok {
		j.WorkerID = workerID
	}
	if storageKey, ok := m["storage_key"].(string); ok {
		j.StorageKey = storageKey
	}
	if retryCount, ok := m["retry_count"].(int); ok {
		j.RetryCount = retryCount
	} else if retryCountStr, ok := m["retry_count"].(string); ok {
		// Handle string conversion
		var count int
		if _, err := fmt.Sscanf(retryCountStr, "%d", &count); err == nil {
			j.RetryCount = count
		}
	}
	if webhookURL, ok := m["webhook_url"].(string); ok {
		j.WebhookURL = webhookURL
	}
	if webhookSecret, ok := m["webhook_secret"].(string); ok {
		j.WebhookSecret = webhookSecret
	}
	if requestID, ok := m["request_id"].(string); ok {
		j.RequestID = requestID
	}
	if fileType, ok := m["file_type"].(string); ok {
		j.FileType = fileType
	}
	if scanTimeout, ok := m["scan_timeout"].(int); ok {
		j.ScanTimeout = scanTimeout
	} else if scanTimeoutStr, ok := m["scan_timeout"].(string); ok {
		var timeout int
		if _, err := fmt.Sscanf(scanTimeoutStr, "%d", &timeout); err == nil {
			j.ScanTimeout = timeout
		}
	}
	// W3C TraceContext carrier: deserialise the JSON blob stored at enqueue.
	// Missing or malformed values are silently ignored so legacy jobs (enqueued
	// before this field existed) deserialise cleanly (omitempty in JSON tags
	// ensures the field is absent in old hashes).
	if tcStr, ok := m["trace_context"].(string); ok && tcStr != "" {
		var tc map[string]string
		if err := json.Unmarshal([]byte(tcStr), &tc); err == nil {
			j.TraceContext = tc
		}
	}
	return nil
}
