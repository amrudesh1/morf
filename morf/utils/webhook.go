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
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// isDisallowedIP reports whether ip points at a non-routable or internal
// destination that a webhook must never be allowed to reach. This blocks SSRF
// to loopback, link-local (incl. the 169.254.169.254 cloud metadata endpoint),
// RFC1918 private ranges, unique-local IPv6 (fc00::/7), unspecified and
// multicast addresses.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// IPv6 unique-local addresses (fc00::/7) are covered by IsPrivate in modern
	// Go, but guard explicitly in case of older semantics.
	if v6 := ip.To16(); v6 != nil && len(ip.To4()) == 0 {
		if v6[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}

// webhookDialer re-validates the ACTUAL connected IP at dial time via its
// Control hook. Because Control runs after DNS resolution but before the
// connection is used, this defeats DNS-rebinding attacks where a hostname
// resolves to a public address at validation time and an internal address at
// connection time.
var webhookDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("webhook dial: invalid address %q: %v", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("webhook dial: unresolvable address %q", host)
		}
		if isDisallowedIP(ip) {
			return fmt.Errorf("webhook dial: connection to disallowed IP %s blocked (SSRF protection)", ip.String())
		}
		return nil
	},
}

// webhookClient is a package-level HTTP client with a sane default timeout, an
// SSRF-aware dialer (see webhookDialer) and a redirect policy that refuses to
// follow redirects so a 3xx cannot be used to bounce the request to an
// internal host.
var webhookClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext:           webhookDialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("webhook: redirects are not allowed (SSRF protection)")
	},
}

// ValidateWebhookURL performs the same SSRF-safety checks the delivery path
// enforces (scheme + DNS resolution + private/loopback/link-local/metadata
// rejection) so a caller can fail-fast at request-intake time and return a clear
// 400 instead of accepting a job that will only fail at delivery. The dial-time
// Control hook on webhookDialer remains the authoritative defense against DNS
// rebinding; this is a complementary fail-fast gate.
func ValidateWebhookURL(ctx context.Context, webhookURL string) error {
	parsedURL, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %v", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme")
	}
	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("webhook URL resolves to a disallowed IP (SSRF protection)")
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to resolve webhook host: %v", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("webhook host did not resolve to any address")
	}
	for _, addr := range ips {
		if isDisallowedIP(addr.IP) {
			return fmt.Errorf("webhook host resolves to a disallowed IP %s (SSRF protection)", addr.IP.String())
		}
	}
	return nil
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

	// Up-front SSRF check: resolve the host and reject if ANY resolved address
	// is internal/non-routable. This is a fail-fast complement to the dial-time
	// Control hook (webhookDialer) that defeats DNS rebinding.
	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("webhook URL resolves to a disallowed IP (SSRF protection)")
		}
	} else {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return fmt.Errorf("failed to resolve webhook host: %v", err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("webhook host did not resolve to any address")
		}
		for _, addr := range ips {
			if isDisallowedIP(addr.IP) {
				return fmt.Errorf("webhook host resolves to a disallowed IP %s (SSRF protection)", addr.IP.String())
			}
		}
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
