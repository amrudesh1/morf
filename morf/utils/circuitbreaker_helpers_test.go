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
	"errors"
	"testing"
	"time"
)

// TestDo_Success verifies that Do("db", fn returning nil) succeeds after init.
func TestDo_Success(t *testing.T) {
	InitCircuitBreakers()

	err := Do("db", func() error { return nil })
	if err != nil {
		t.Fatalf("Do(db, nil-returning fn) got err %v; want nil", err)
	}
}

// TestDo_DBBreaker_Registered verifies the "db" and "redis" breakers are
// registered after init. (The slack/jira breakers remain removed as unrouted;
// "db" and "redis" both have call sites — db/db.go and queue/ + utils/cache.go.)
func TestDo_DBBreaker_Registered(t *testing.T) {
	InitCircuitBreakers()

	if breakerRegistry["db"] == nil {
		t.Fatal("breakerRegistry[\"db\"] is nil after InitCircuitBreakers")
	}
	if breakerRegistry["redis"] == nil {
		t.Fatal("breakerRegistry[\"redis\"] is nil after InitCircuitBreakers")
	}
}

// TestBreakerState_Redis verifies BreakerState/IsBreakerOpen report the "redis"
// breaker (used by GET /ready to shed a pod whose Redis is down). After init it
// is registered and closed; tripping it open flips IsBreakerOpen to true.
func TestBreakerState_Redis(t *testing.T) {
	InitCircuitBreakers()

	state, ok := BreakerState("redis")
	if !ok {
		t.Fatal("BreakerState(\"redis\") not registered after InitCircuitBreakers")
	}
	if state != StateClosed {
		t.Fatalf("initial redis breaker state = %v, want closed", state)
	}
	if IsBreakerOpen("redis") {
		t.Fatal("IsBreakerOpen(\"redis\") = true initially, want false")
	}

	// An unregistered breaker fails-open (not reported open).
	if _, ok := BreakerState("nope"); ok {
		t.Fatal("BreakerState(\"nope\") ok = true, want false for unregistered breaker")
	}
	if IsBreakerOpen("nope") {
		t.Fatal("IsBreakerOpen(\"nope\") = true, want false for unregistered breaker")
	}

	// Trip the redis breaker open (5 failures) and confirm it is reported open.
	callErr := errors.New("redis down")
	for i := 0; i < 5; i++ {
		_ = Do("redis", func() error { return callErr })
	}
	if !IsBreakerOpen("redis") {
		t.Fatal("IsBreakerOpen(\"redis\") = false after 5 failures, want true")
	}
	// Reset so the shared breaker does not leak an open state into other tests.
	redisCircuitBreaker.Reset()
}

// TestDo_TripsToOpen verifies that repeated errors trip the breaker open and
// subsequent calls are short-circuited without invoking fn.
func TestDo_TripsToOpen(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		Name:         "test-trip",
		MaxFailures:  3,
		ResetTimeout: 60 * time.Second,
	})

	callErr := errors.New("service error")
	for i := 0; i < 3; i++ {
		if err := cb.Call(func() error { return callErr }); err != callErr {
			t.Fatalf("call %d: got %v; want %v", i+1, err, callErr)
		}
	}
	if cb.GetState() != StateOpen {
		t.Fatalf("breaker state = %v; want open after %d failures", cb.GetState(), 3)
	}

	// Temporarily register this breaker under a test name.
	origRegistry := breakerRegistry
	breakerRegistry = map[string]*CircuitBreaker{"test-trip": cb}
	defer func() { breakerRegistry = origRegistry }()

	invoked := false
	err := Do("test-trip", func() error {
		invoked = true
		return nil
	})
	if err == nil {
		t.Fatal("Do on open breaker: got nil error; want open-circuit error")
	}
	if invoked {
		t.Fatal("fn was invoked despite open breaker; expected short-circuit")
	}
}

// TestDo_UnknownName verifies that Do with an unregistered name runs fn directly.
func TestDo_UnknownName(t *testing.T) {
	InitCircuitBreakers()

	called := false
	err := Do("unknown-service-xyz", func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("Do(unknown, nil fn): got err %v; want nil", err)
	}
	if !called {
		t.Fatal("fn was NOT called for unknown name; expected fail-open direct call")
	}
}

// TestDo_NilRegistry_FailOpen verifies that Do runs fn directly when the
// registry is nil (i.e., before InitCircuitBreakers has been called).
func TestDo_NilRegistry_FailOpen(t *testing.T) {
	origRegistry := breakerRegistry
	breakerRegistry = nil
	defer func() { breakerRegistry = origRegistry }()

	called := false
	err := Do("db", func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("Do(db) with nil registry: got err %v; want nil", err)
	}
	if !called {
		t.Fatal("fn was NOT called when registry is nil; expected fail-open")
	}
}
