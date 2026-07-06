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
	"sync"
	"time"

	"morf/metrics"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// String returns the string representation of the circuit state
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	name          string
	maxFailures   int
	resetTimeout  time.Duration
	state         CircuitState
	failureCount  int
	lastFailTime  time.Time
	inFlightProbe bool // true while a single half-open probe is executing
	mu            sync.RWMutex
	onStateChange func(name string, from, to CircuitState)
}

// Config holds configuration for a circuit breaker
type Config struct {
	Name          string
	MaxFailures   int           // Number of failures before opening circuit
	ResetTimeout  time.Duration // Time to wait before attempting half-open
	OnStateChange func(name string, from, to CircuitState)
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config Config) *CircuitBreaker {
	if config.MaxFailures <= 0 {
		config.MaxFailures = 5
	}
	if config.ResetTimeout <= 0 {
		config.ResetTimeout = 60 * time.Second
	}

	return &CircuitBreaker{
		name:          config.Name,
		maxFailures:   config.MaxFailures,
		resetTimeout:  config.ResetTimeout,
		state:         StateClosed,
		failureCount:  0,
		onStateChange: config.OnStateChange,
	}
}

// Call executes a function with circuit breaker protection.
//
// Admission is decided under the lock so that, while half-open, only a single
// probe request runs fn() at a time. Concurrent callers that observe the open
// state cannot all slip through: the first to win the lock advances
// lastFailTime and claims the in-flight probe slot; the rest are rejected until
// the probe resolves. onStateChange callbacks are fired AFTER releasing the
// lock so a callback that re-enters the breaker cannot deadlock.
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()

	isProbe := false
	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastFailTime) < cb.resetTimeout {
			cb.mu.Unlock()
			return errors.New("circuit breaker is open")
		}
		// Transition to half-open and admit exactly one probe. Advance
		// lastFailTime so other goroutines that also observed StateOpen do not
		// pass the resetTimeout gate and run a second concurrent probe.
		from, to, changed := cb.setState(StateHalfOpen)
		cb.inFlightProbe = true
		cb.lastFailTime = time.Now()
		isProbe = true
		cb.mu.Unlock()
		if changed {
			cb.fireStateChange(from, to)
		}

	case StateHalfOpen:
		// A probe is already running; reject additional callers so only one
		// request tests the downstream while half-open.
		if cb.inFlightProbe {
			cb.mu.Unlock()
			return errors.New("circuit breaker is open")
		}
		cb.inFlightProbe = true
		isProbe = true
		cb.mu.Unlock()

	case StateClosed:
		cb.mu.Unlock()

	default:
		cb.mu.Unlock()
		return errors.New("unknown circuit breaker state")
	}

	// Execute the protected function outside the lock.
	err := fn()

	cb.mu.Lock()
	if isProbe {
		cb.inFlightProbe = false
	}
	var from, to CircuitState
	changed := false
	if err != nil {
		from, to, changed = cb.recordFailure()
	} else {
		from, to, changed = cb.recordSuccess()
	}
	cb.mu.Unlock()

	if changed {
		cb.fireStateChange(from, to)
	}

	return err
}

// recordFailure records a failure and updates circuit state. The caller must
// hold cb.mu. It returns the resulting state transition (if any) so the caller
// can fire onStateChange after releasing the lock.
func (cb *CircuitBreaker) recordFailure() (from, to CircuitState, changed bool) {
	cb.failureCount++
	cb.lastFailTime = time.Now()

	if cb.state == StateHalfOpen {
		// Half-open probe failed, go back to open.
		return cb.setState(StateOpen)
	} else if cb.failureCount >= cb.maxFailures {
		// Too many failures, open the circuit.
		return cb.setState(StateOpen)
	}
	return cb.state, cb.state, false
}

// recordSuccess records a success and resets the circuit. The caller must hold
// cb.mu. It returns the resulting state transition (if any) so the caller can
// fire onStateChange after releasing the lock.
func (cb *CircuitBreaker) recordSuccess() (from, to CircuitState, changed bool) {
	if cb.state == StateHalfOpen {
		// Success in half-open, close the circuit.
		f, t, c := cb.setState(StateClosed)
		cb.failureCount = 0
		return f, t, c
	}
	cb.failureCount = 0
	return cb.state, cb.state, false
}

// setState changes the circuit breaker state. The caller must hold cb.mu.
// It does NOT invoke onStateChange; instead it returns the transition so the
// caller can fire the callback after releasing the lock (avoids a re-entrant
// deadlock if the callback calls back into the breaker).
func (cb *CircuitBreaker) setState(newState CircuitState) (from, to CircuitState, changed bool) {
	if cb.state == newState {
		return cb.state, newState, false
	}

	oldState := cb.state
	cb.state = newState

	if newState == StateClosed {
		cb.failureCount = 0
	}

	return oldState, newState, true
}

// fireStateChange invokes the onStateChange callback (if configured) outside
// the lock.
func (cb *CircuitBreaker) fireStateChange(from, to CircuitState) {
	if cb.onStateChange != nil {
		cb.onStateChange(cb.name, from, to)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetFailureCount returns the current failure count
func (cb *CircuitBreaker) GetFailureCount() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failureCount
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	from, to, changed := cb.setState(StateClosed)
	cb.inFlightProbe = false
	cb.mu.Unlock()
	if changed {
		cb.fireStateChange(from, to)
	}
}

// Global circuit breakers for different services.
//
// Two breakers are wired:
//   - "db":    the sole production call sites are utils.Do("db", ...) in db/db.go.
//   - "redis": SC-1 (single-Redis SPOF) — the non-blocking Redis operations in
//     queue/ and utils/cache.go run through utils.Do("redis", ...). When Redis
//     is repeatedly failing the breaker opens and sheds those ops immediately
//     (fast-fail) instead of every producer/worker piling onto a hung Redis;
//     the breaker's open state is also surfaced in GET /ready so K8s stops
//     routing to a pod whose Redis is down.
//
// The previously-registered slack/jira breakers had no call sites, so they
// were removed to avoid implying circuit-breaker protection that is not
// actually wired.
var (
	dbCircuitBreaker    *CircuitBreaker
	redisCircuitBreaker *CircuitBreaker
	circuitBreakerOnce  sync.Once
	// breakerRegistry maps friendly names to circuit breakers for Do().
	breakerRegistry map[string]*CircuitBreaker
)

// InitCircuitBreakers initializes global circuit breakers
func InitCircuitBreakers() {
	circuitBreakerOnce.Do(func() {
		// Export breaker transitions so trips are visible in metrics.
		// CircuitState values (closed=0, open=1, half-open=2) map directly
		// onto the morf_circuit_breaker_state gauge encoding.
		onStateChange := func(name string, from, to CircuitState) {
			metrics.SetCircuitBreakerState(name, float64(to))
			if to == StateOpen {
				metrics.RecordCircuitBreakerTrip(name)
			}
		}

		dbCircuitBreaker = NewCircuitBreaker(Config{
			Name:          "database",
			MaxFailures:   5,
			ResetTimeout:  30 * time.Second,
			OnStateChange: onStateChange,
		})

		redisCircuitBreaker = NewCircuitBreaker(Config{
			Name:          "redis",
			MaxFailures:   5,
			ResetTimeout:  30 * time.Second,
			OnStateChange: onStateChange,
		})

		// Seed the gauges so the breakers report closed before their first trip.
		metrics.SetCircuitBreakerState("database", float64(StateClosed))
		metrics.SetCircuitBreakerState("redis", float64(StateClosed))

		breakerRegistry = map[string]*CircuitBreaker{
			"db":    dbCircuitBreaker,
			"redis": redisCircuitBreaker,
		}
	})
}

// BreakerState returns the current state of the named circuit breaker and
// whether it is registered. Used by health/readiness handlers to surface a
// tripped breaker (e.g. GET /ready reporting Redis as unhealthy when the
// "redis" breaker is open). If the breaker is not registered (or
// InitCircuitBreakers has not run), ok is false.
func BreakerState(name string) (state CircuitState, ok bool) {
	if breakerRegistry == nil {
		return StateClosed, false
	}
	cb, found := breakerRegistry[name]
	if !found {
		return StateClosed, false
	}
	return cb.GetState(), true
}

// IsBreakerOpen reports whether the named circuit breaker is currently open
// (i.e. shedding calls). Returns false for an unregistered breaker so callers
// fail-open before initialisation.
func IsBreakerOpen(name string) bool {
	state, ok := BreakerState(name)
	if !ok {
		return false
	}
	return state == StateOpen
}

// Do looks up the named circuit breaker from the registry and runs fn through it.
// Recording of success/failure and open-circuit short-circuiting are handled by
// the breaker's Call method.
// If name is not registered (or InitCircuitBreakers has not been called), fn is
// invoked directly — fail-open so callers are safe before initialisation.
func Do(name string, fn func() error) error {
	if breakerRegistry != nil {
		if cb, ok := breakerRegistry[name]; ok {
			return cb.Call(fn)
		}
	}
	return fn()
}
