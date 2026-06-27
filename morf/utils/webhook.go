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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"morf/models"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

// webhookClient is a package-level HTTP client with a sane default timeout.
// Individual attempts may further constrain the deadline via context.
var webhookClient = &http.Client{
	Timeout: 30 * time.Second,
}

// deliverWebhookWithContext is the internal, context-aware delivery primitive.
// Every exported variant ultimately calls this function.
func deliverWebhookWithContext(ctx context.Context, webhookURL string, secret string, payload models.WebhookPayload) error {
	// Validate URL
	parsedURL, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %v", err)
	}

	// Only allow HTTP/HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme")
	}

	// Marshal payload
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create context-aware request so it can be cancelled on shutdown
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MORF-Webhook/1.0")

	// Add signature if secret is provided
	if secret != "" {
		signature := generateWebhookSignature(secret, payloadJSON)
		req.Header.Set("X-MORF-Signature", signature)
	}

	log.WithFields(log.Fields{
		"webhook_url": MaskURLForLogging(webhookURL),
		"job_id":      payload.JobID,
		"status":      payload.Status,
	}).Info("Delivering webhook")

	// Execute request
	resp, err := webhookClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook delivery failed: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-success status: %d", resp.StatusCode)
	}

	log.WithFields(log.Fields{
		"webhook_url": MaskURLForLogging(webhookURL),
		"job_id":      payload.JobID,
		"status_code": resp.StatusCode,
	}).Info("Webhook delivered successfully")

	return nil
}

// DeliverWebhook delivers a webhook payload to the specified URL.
// It delegates to deliverWebhookWithContext with a background context so it
// is not cancellable but still has the per-client Timeout.
func DeliverWebhook(webhookURL string, secret string, payload models.WebhookPayload) error {
	return deliverWebhookWithContext(context.Background(), webhookURL, secret, payload)
}

// DeliverWebhookWithRetry delivers a webhook with retry logic.
// It delegates to DeliverWebhookWithRetryCtx with a background context for
// backwards compatibility; callers that can supply a context should prefer
// DeliverWebhookWithRetryCtx directly.
func DeliverWebhookWithRetry(webhookURL string, secret string, payload models.WebhookPayload) error {
	return DeliverWebhookWithRetryCtx(context.Background(), webhookURL, secret, payload)
}

// DeliverWebhookWithRetryCtx delivers a webhook with retry logic and full
// context support. ctx cancellation is honoured both during inter-attempt
// backoff sleeps (via RetryWithContext) and inside each HTTP attempt (via
// http.NewRequestWithContext). Each attempt additionally receives its own
// 30-second deadline derived from ctx so a single stuck connection cannot
// block the entire retry budget.
func DeliverWebhookWithRetryCtx(ctx context.Context, webhookURL string, secret string, payload models.WebhookPayload) error {
	config := DefaultRetryConfig()
	config.MaxRetries = 3
	config.InitialDelay = 2 * time.Second
	config.MaxDelay = 30 * time.Second

	return RetryWithContext(ctx, func() error {
		// Derive a per-attempt context with a hard deadline so a single slow
		// connection cannot consume the whole retry window.
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return deliverWebhookWithContext(attemptCtx, webhookURL, secret, payload)
	}, config)
}

// generateWebhookSignature generates HMAC-SHA256 signature for webhook payload
func generateWebhookSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature verifies the webhook signature
func VerifyWebhookSignature(secret string, payload []byte, signature string) bool {
	expectedSignature := generateWebhookSignature(secret, payload)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

// MaskURLForLogging masks sensitive parts of URL for logging
func MaskURLForLogging(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "***"
	}
	if parsed.User != nil {
		parsed.User = url.UserPassword("***", "***")
	}
	return parsed.String()
}
