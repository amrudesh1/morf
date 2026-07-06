/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package worker

import (
	"errors"
	"testing"
	"time"
)

// TestIsRetryable pins the failure classification that decides DLQ-vs-requeue
// (C-1/R-2): deterministic APK failures must NOT be retried (they go straight to
// the DLQ), transient failures must be retried.
func TestIsRetryable(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("safety check failed: zip bomb detected"), false},
		{errors.New("decompilation failed: corrupt apk"), false},
		{errors.New("validation failed: bad extension"), false},
		{errors.New("SAFETY CHECK FAILED"), false}, // case-insensitive
		{errors.New("connection refused"), true},
		{errors.New("i/o timeout"), true},
		{errors.New("some transient redis error"), true},
	}
	for _, c := range cases {
		if got := isRetryable(c.err); got != c.want {
			t.Errorf("isRetryable(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// TestRetryBackoff verifies the exponential schedule is monotonic and capped so
// a worker never sleeps unbounded between retries.
func TestRetryBackoff(t *testing.T) {
	if got := retryBackoff(1); got != 2*time.Second {
		t.Errorf("retryBackoff(1) = %s, want 2s", got)
	}
	prev := time.Duration(0)
	for rc := 1; rc <= 10; rc++ {
		d := retryBackoff(rc)
		if d < prev {
			t.Errorf("retryBackoff(%d) = %s decreased below previous %s", rc, d, prev)
		}
		if d > 30*time.Second {
			t.Errorf("retryBackoff(%d) = %s exceeds the 30s cap", rc, d)
		}
		prev = d
	}
	if retryBackoff(100) != 30*time.Second {
		t.Errorf("retryBackoff(100) = %s, want 30s cap", retryBackoff(100))
	}
}

// TestEnvIntFloatDefaults covers the env helpers used for pool sizing / tunables
// (SC-3 / MED-ioFactor): unset -> default, set -> parsed.
func TestEnvIntFloatDefaults(t *testing.T) {
	if got := envInt("MORF_TEST_UNSET_INT_ZZ", 7); got != 7 {
		t.Errorf("envInt(unset) = %d, want default 7", got)
	}
	if got := envFloat("MORF_TEST_UNSET_FLOAT_ZZ", 1.25); got != 1.25 {
		t.Errorf("envFloat(unset) = %v, want default 1.25", got)
	}
	t.Setenv("MORF_TEST_SET_INT_ZZ", "42")
	if got := envInt("MORF_TEST_SET_INT_ZZ", 7); got != 42 {
		t.Errorf("envInt(set) = %d, want 42", got)
	}
	t.Setenv("MORF_TEST_SET_FLOAT_ZZ", "3.5")
	if got := envFloat("MORF_TEST_SET_FLOAT_ZZ", 1.0); got != 3.5 {
		t.Errorf("envFloat(set) = %v, want 3.5", got)
	}
}
