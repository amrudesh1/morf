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
	"context"
	"errors"
	"math"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// RetryableError indicates if an error should be retried
type RetryableError struct {
	Err       error
	Retryable bool
}

func (e *RetryableError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying error
func (e *RetryableError) Unwrap() error {
	return e.Err
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check for RetryableError wrapper
	var retryableErr *RetryableError
	if errors.As(err, &retryableErr) {
		return retryableErr.Retryable
	}

	// Network errors are retryable
	if _, ok := err.(net.Error); ok {
		return true
	}

	// Timeout errors are retryable
	if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
		return true
	}

	// URL errors (network related) are retryable
	if _, ok := err.(*url.Error); ok {
		return true
	}

	// Check for 5xx HTTP errors (represented as strings)
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") || strings.Contains(errStr, "504") {
		return true
	}

	// Don't retry on 4xx errors (client errors)
	if strings.Contains(errStr, "400") || strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") || strings.Contains(errStr, "404") ||
		strings.Contains(errStr, "422") || strings.Contains(errStr, "validation") {
		return false
	}

	// Default: don't retry unknown errors
	return false
}

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       bool
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// RetryWithContext executes a function with exponential backoff retry logic and context
func RetryWithContext(ctx context.Context, fn func() error, config RetryConfig) error {
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if attempt > 0 {
			// Calculate delay with exponential backoff
			delay := time.Duration(float64(config.InitialDelay) * math.Pow(config.Multiplier, float64(attempt-1)))

			// Cap at max delay
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}

			// Add jitter if enabled. Guard against rand.Int63n(0), which panics:
			// when the (possibly MaxDelay-capped) delay is < 4ns, delay/4 == 0.
			if config.Jitter {
				if q := int64(delay / 4); q > 0 {
					jitter := time.Duration(rand.Int63n(q))
					delay = delay + jitter
				}
			}

			log.WithFields(log.Fields{
				"attempt": attempt,
				"delay":   delay,
			}).Info("Retrying after delay")

			// Sleep with context cancellation support
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		// Execute the function
		err := fn()
		if err == nil {
			if attempt > 0 {
				log.WithFields(log.Fields{
					"attempt": attempt + 1,
				}).Info("Operation succeeded after retry")
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !IsRetryable(err) {
			log.WithFields(log.Fields{
				"attempt": attempt + 1,
				"error":   err.Error(),
			}).Warn("Error is not retryable, stopping retries")
			return err
		}

		if attempt < config.MaxRetries {
			log.WithFields(log.Fields{
				"attempt":     attempt + 1,
				"max_retries": config.MaxRetries,
				"error":       err.Error(),
			}).Warn("Operation failed, will retry")
		}
	}

	log.WithFields(log.Fields{
		"max_retries": config.MaxRetries,
		"error":       lastErr.Error(),
	}).Error("Operation failed after all retries")

	return lastErr
}
