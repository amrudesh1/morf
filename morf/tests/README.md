# MORF Test Suite

This directory contains comprehensive tests for the MORF (Mobile Reconnaissance Framework) project.

## Test Structure

```
tests/
├── README.md              # This file
├── concurrency_test.go    # Concurrency and race condition tests
├── integration_test.go    # Integration tests for full workflows
├── performance_test.go    # Performance benchmarks and tests
├── scaling_test.go        # Horizontal scaling tests
├── chaos_test.go          # Chaos engineering and resilience tests
└── load/                  # Load testing scripts
    └── k6-script.js       # k6 load test script
```

## Running Tests

### Unit Tests

Run all unit tests:
```bash
go test ./...
```

Run tests for a specific package:
```bash
go test ./utils/...
go test ./apk/...
```

Run tests with coverage:
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Integration Tests

Integration tests require external dependencies (Redis, Database):
```bash
# Set up test environment
export REDIS_URL="redis://localhost:6379"
export DATABASE_URL="mysql://user:password@localhost:3306/morf_test"

# Run integration tests
go test -v ./tests/... -run TestIntegration
```

### Performance Tests

Run performance benchmarks:
```bash
go test -bench=. -benchmem ./tests/performance_test.go
```

### Load Tests

Load tests use k6. Install k6 first:
```bash
# macOS
brew install k6

# Linux
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

Run load tests:
```bash
cd tests/load
k6 run k6-script.js

# With custom options
k6 run --vus 100 --iterations 1000 k6-script.js

# With custom MORF URL
MORF_URL=http://localhost:9092 k6 run k6-script.js
```

### Chaos Tests

Chaos tests verify system resilience:
```bash
go test -v ./tests/... -run TestChaos
```

## Test Coverage Goals

- **Unit Tests**: 80%+ coverage
- **Integration Tests**: All critical workflows
- **Performance Tests**: Baseline metrics for all operations
- **Load Tests**: 100 concurrent users, 1000 total requests
- **Chaos Tests**: All failure scenarios

## Test Categories

### Unit Tests (`*_test.go`)

Unit tests are co-located with source files:
- `utils/hash_test.go` - Hash function tests
- `utils/jobcontext_test.go` - Job context tests
- `utils/retry_test.go` - Retry logic tests
- `utils/comparison_test.go` - Scan comparison tests
- `apk/manifest_parser_test.go` - Manifest parser tests

### Integration Tests (`tests/integration_test.go`)

Tests that verify end-to-end workflows:
- Concurrent scans of same APK
- Workspace isolation
- Workspace cleanup under failure
- API endpoint functionality
- Database operations
- Redis operations

### Performance Tests (`tests/performance_test.go`)

Benchmarks and performance tests:
- Baseline performance metrics
- APK scan performance
- Pattern scan performance
- Parallel decompile performance
- Batch pattern scan performance

### Scaling Tests (`tests/scaling_test.go`)

Tests for horizontal scaling:
- Multi-instance deployment
- Job distribution across instances
- Failover scenarios
- Concurrent job creation

### Chaos Tests (`tests/chaos_test.go`)

Resilience and failure recovery tests:
- Worker failure recovery
- Redis failure handling
- Job retry on failure
- Dead letter queue testing
- Concurrent job processing

### Load Tests (`tests/load/k6-script.js`)

Load testing with k6:
- 100 concurrent uploads
- 1000 total scans
- Measures: p50/p95/p99 latency, throughput, error rate

## Continuous Integration

Tests are run automatically in CI/CD:
- Unit tests run on every commit
- Integration tests run on pull requests
- Performance tests run nightly
- Load tests run weekly
- Chaos tests run monthly

## Writing New Tests

### Unit Test Template

```go
package utils

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestFunctionName(t *testing.T) {
    // Arrange
    input := "test input"
    
    // Act
    result := FunctionName(input)
    
    // Assert
    assert.Equal(t, "expected", result)
}
```

### Integration Test Template

```go
func TestIntegrationFeature(t *testing.T) {
    // Skip if dependencies not available
    if !checkDependencies() {
        t.Skip("Dependencies not available")
    }
    
    // Setup
    setup()
    defer teardown()
    
    // Test
    // ...
}
```

## Test Data

Test data should be:
- Minimal and focused
- Realistic but not production data
- Cleaned up after tests
- Stored in `tests/fixtures/` if needed

## Troubleshooting

### Tests failing due to missing dependencies

Some tests require Redis or Database. Skip them if dependencies are not available:
```go
if !checkRedis() {
    t.Skip("Redis not available")
}
```

### Tests timing out

Increase timeout for slow tests:
```go
t := &testing.T{}
t.Deadline() // Check if deadline is set
```

### Flaky tests

If tests are flaky:
1. Check for race conditions
2. Add proper synchronization
3. Use deterministic test data
4. Add retries for external dependencies

## Contributing

When adding new features:
1. Write unit tests first (TDD)
2. Add integration tests for workflows
3. Update performance baselines if needed
4. Document test requirements in README

