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

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	switch state {
	case StateOpen:
		// Check if we should attempt half-open
		cb.mu.Lock()
		if time.Since(cb.lastFailTime) >= cb.resetTimeout {
			cb.setState(StateHalfOpen)
			state = StateHalfOpen
		} else {
			cb.mu.Unlock()
			return errors.New("circuit breaker is open")
		}
		cb.mu.Unlock()

		// Fall through to execute function in half-open state
		fallthrough

	case StateHalfOpen, StateClosed:
		// Execute the function
		err := fn()

		cb.mu.Lock()
		if err != nil {
			cb.recordFailure()
		} else {
			cb.recordSuccess()
		}
		cb.mu.Unlock()

		return err

	default:
		return errors.New("unknown circuit breaker state")
	}
}

// recordFailure records a failure and updates circuit state
func (cb *CircuitBreaker) recordFailure() {
	cb.failureCount++
	cb.lastFailTime = time.Now()

	if cb.state == StateHalfOpen {
		// Half-open failed, go back to open
		cb.setState(StateOpen)
	} else if cb.failureCount >= cb.maxFailures {
		// Too many failures, open the circuit
		cb.setState(StateOpen)
	}
}

// recordSuccess records a success and resets the circuit
func (cb *CircuitBreaker) recordSuccess() {
	if cb.state == StateHalfOpen {
		// Success in half-open, close the circuit
		cb.setState(StateClosed)
	}
	cb.failureCount = 0
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(newState CircuitState) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState

	if newState == StateClosed {
		cb.failureCount = 0
	}

	if cb.onStateChange != nil {
		cb.onStateChange(cb.name, oldState, newState)
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
	defer cb.mu.Unlock()
	cb.setState(StateClosed)
}

// Global circuit breakers for different services
var (
	dbCircuitBreaker    *CircuitBreaker
	redisCircuitBreaker *CircuitBreaker
	slackCircuitBreaker *CircuitBreaker
	jiraCircuitBreaker  *CircuitBreaker
	circuitBreakerOnce  sync.Once
	// breakerRegistry maps friendly names to circuit breakers for Do().
	breakerRegistry map[string]*CircuitBreaker
)

// InitCircuitBreakers initializes global circuit breakers
func InitCircuitBreakers() {
	circuitBreakerOnce.Do(func() {
		dbCircuitBreaker = NewCircuitBreaker(Config{
			Name:         "database",
			MaxFailures:  5,
			ResetTimeout: 30 * time.Second,
		})

		redisCircuitBreaker = NewCircuitBreaker(Config{
			Name:         "redis",
			MaxFailures:  5,
			ResetTimeout: 30 * time.Second,
		})

		slackCircuitBreaker = NewCircuitBreaker(Config{
			Name:         "slack",
			MaxFailures:  3,
			ResetTimeout: 60 * time.Second,
		})

		jiraCircuitBreaker = NewCircuitBreaker(Config{
			Name:         "jira",
			MaxFailures:  3,
			ResetTimeout: 60 * time.Second,
		})

		breakerRegistry = map[string]*CircuitBreaker{
			"db":       dbCircuitBreaker,
			"database": dbCircuitBreaker,
			"redis":    redisCircuitBreaker,
			"slack":    slackCircuitBreaker,
			"jira":     jiraCircuitBreaker,
		}
	})
}

// GetDBCircuitBreaker returns the database circuit breaker
func GetDBCircuitBreaker() *CircuitBreaker {
	return dbCircuitBreaker
}

// GetRedisCircuitBreaker returns the Redis circuit breaker
func GetRedisCircuitBreaker() *CircuitBreaker {
	return redisCircuitBreaker
}

// GetSlackCircuitBreaker returns the Slack circuit breaker
func GetSlackCircuitBreaker() *CircuitBreaker {
	return slackCircuitBreaker
}

// GetJiraCircuitBreaker returns the JIRA circuit breaker
func GetJiraCircuitBreaker() *CircuitBreaker {
	return jiraCircuitBreaker
}

// DBBreaker returns the database circuit breaker.
// If InitCircuitBreakers has not been called yet it is called lazily.
func DBBreaker() *CircuitBreaker {
	if dbCircuitBreaker == nil {
		InitCircuitBreakers()
	}
	return dbCircuitBreaker
}

// RedisBreaker returns the Redis circuit breaker.
// If InitCircuitBreakers has not been called yet it is called lazily.
func RedisBreaker() *CircuitBreaker {
	if redisCircuitBreaker == nil {
		InitCircuitBreakers()
	}
	return redisCircuitBreaker
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
