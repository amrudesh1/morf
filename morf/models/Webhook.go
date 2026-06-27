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
)

// WebhookDeliveryStatus represents the status of a webhook delivery
type WebhookDeliveryStatus string

const (
	WebhookStatusPending   WebhookDeliveryStatus = "pending"
	WebhookStatusDelivered WebhookDeliveryStatus = "delivered"
	WebhookStatusFailed    WebhookDeliveryStatus = "failed"
	WebhookStatusRetrying  WebhookDeliveryStatus = "retrying"
)

// Webhook represents a webhook configuration for a job
type Webhook struct {
	ID        string    `json:"id"`
	JobID     string    `json:"job_id"`
	URL       string    `json:"url"`
	Secret    string    `json:"secret,omitempty"` // Secret for signature verification
	Status    WebhookDeliveryStatus `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	RetryCount int      `json:"retry_count"`
	LastError  string   `json:"last_error,omitempty"`
}

// WebhookPayload represents the payload sent to webhook.
// SchemaVersion is non-omitempty so subscribers can rely on its presence even
// in error/cancelled deliveries.
type WebhookPayload struct {
	JobID         string                 `json:"job_id"`
	Status        string                 `json:"status"`
	Result        map[string]interface{} `json:"result,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	SchemaVersion string                 `json:"schema_version"`
}

