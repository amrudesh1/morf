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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsRetryable(t *testing.T) {
	// Test RetryableError
	retryableErr := &RetryableError{
		Err:       errors.New("test error"),
		Retryable: true,
	}
	assert.True(t, IsRetryable(retryableErr), "RetryableError with Retryable=true should be retryable")

	nonRetryableErr := &RetryableError{
		Err:       errors.New("test error"),
		Retryable: false,
	}
	assert.False(t, IsRetryable(nonRetryableErr), "RetryableError with Retryable=false should not be retryable")

	// Test network error
	netErr := &net.OpError{Op: "read", Err: errors.New("connection refused")}
	assert.True(t, IsRetryable(netErr), "Network error should be retryable")

	// Test timeout error
	timeoutErr := errors.New("context deadline exceeded")
	assert.True(t, IsRetryable(timeoutErr), "Timeout error should be retryable")

	// Test 5xx HTTP errors
	http500Err := errors.New("HTTP 500 Internal Server Error")
	assert.True(t, IsRetryable(http500Err), "5xx error should be retryable")

	http503Err := errors.New("HTTP 503 Service Unavailable")
	assert.True(t, IsRetryable(http503Err), "503 error should be retryable")

	// Test 4xx errors (should not be retryable)
	http400Err := errors.New("HTTP 400 Bad Request")
	assert.False(t, IsRetryable(http400Err), "4xx error should not be retryable")

	// Test nil error
	assert.False(t, IsRetryable(nil), "Nil error should not be retryable")

	// Test regular error
	regularErr := errors.New("regular error")
	assert.False(t, IsRetryable(regularErr), "Regular error should not be retryable")
}

func TestRetryWithContext(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.InitialDelay = time.Millisecond * 10
	config.MaxDelay = time.Millisecond * 50

	// Test successful operation (no retries needed)
	attempts := 0
	err := RetryWithContext(ctx, func() error {
		attempts++
		return nil
	}, config)
	assert.NoError(t, err, "Successful operation should not return error")
	assert.Equal(t, 1, attempts, "Should only attempt once for successful operation")

	// Test retryable error that eventually succeeds
	attempts = 0
	err = RetryWithContext(ctx, func() error {
		attempts++
		if attempts < 2 {
			return &RetryableError{Err: errors.New("temporary error"), Retryable: true}
		}
		return nil
	}, config)
	assert.NoError(t, err, "Operation should succeed after retries")
	assert.Equal(t, 2, attempts, "Should retry once then succeed")

	// Test non-retryable error (should fail immediately)
	attempts = 0
	err = RetryWithContext(ctx, func() error {
		attempts++
		return &RetryableError{Err: errors.New("permanent error"), Retryable: false}
	}, config)
	assert.Error(t, err, "Non-retryable error should fail immediately")
	assert.Equal(t, 1, attempts, "Should not retry non-retryable errors")

	// Test context cancellation
	ctx2, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	attempts = 0
	err = RetryWithContext(ctx2, func() error {
		attempts++
		return &RetryableError{Err: errors.New("retryable error"), Retryable: true}
	}, config)
	assert.Error(t, err, "Cancelled context should return error")
	assert.Equal(t, 0, attempts, "Should not attempt when context is cancelled")
}

// Note: the non-context Retry wrapper was removed (dead outside tests); its
// behavior is fully covered by TestRetryWithContext above.
