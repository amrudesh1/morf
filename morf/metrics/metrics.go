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

package metrics

import (
	"context"
	"database/sql"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

var (
	// ScansTotal tracks total number of scans by status
	ScansTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "morf_scans_total",
			Help: "Total number of APK scans by status",
		},
		[]string{"status"}, // status: success, failed, duplicate
	)

	// ScanDuration tracks scan duration by phase
	ScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "morf_scan_duration_seconds",
			Help:    "Duration of APK scan phases in seconds",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"phase"}, // phase: decompile, metadata, pattern_scan, total
	)

	// SecretsFound tracks number of secrets found per scan
	SecretsFound = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "morf_secrets_found",
			Help:    "Number of secrets found per scan",
			Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 500, 1000},
		},
	)

	// QueueDepth tracks current queue depth (for future job queue implementation)
	QueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "morf_queue_depth",
			Help: "Current number of jobs in queue",
		},
	)

	// DBPoolConnections tracks database connection pool state
	DBPoolConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "morf_db_pool_connections",
			Help: "Database connection pool connections by state",
		},
		[]string{"state"}, // state: open, idle, in_use
	)

	// DBPoolWaitCount tracks total number of connections waited for
	DBPoolWaitCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "morf_db_pool_wait_count_total",
			Help: "Total number of times a connection was waited for in the pool",
		},
	)

	// DBPoolWaitDuration tracks total time spent waiting for a pool connection
	DBPoolWaitDuration = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "morf_db_pool_wait_duration_seconds",
			Help: "Total time blocked waiting for a new connection from the pool",
		},
	)

	// ToolExecutionDuration tracks external tool execution duration
	ToolExecutionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "morf_tool_execution_duration_seconds",
			Help:    "Duration of external tool execution in seconds",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"tool"}, // tool: apktool, apkanalyzer, aapt, ripgrep
	)

	// HTTPRequestsTotal tracks HTTP requests by method and status
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "morf_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"}, // method: GET, POST, etc., endpoint: /upload, /results, etc., status: 200, 400, 500, etc.
	)

	// HTTPRequestDuration tracks HTTP request duration
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "morf_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60},
		},
		[]string{"method", "endpoint"},
	)

	// ErrorsTotal tracks errors by type
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "morf_errors_total",
			Help: "Total number of errors by type",
		},
		[]string{"type"}, // type: database, tool_execution, file_upload, validation, etc.
	)

	// ActiveScans tracks currently active scans
	ActiveScans = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "morf_active_scans",
			Help: "Number of currently active scans",
		},
	)

	// FileUploadSize tracks uploaded file sizes
	FileUploadSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "morf_file_upload_size_bytes",
			Help:    "Size of uploaded files in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824}, // 1KB to 1GB
		},
	)

	// CircuitBreakerState tracks the current state of each circuit breaker
	// (0=closed, 1=open, 2=half-open).
	CircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "morf_circuit_breaker_state",
			Help: "Current circuit breaker state (0=closed, 1=open, 2=half-open)",
		},
		[]string{"name"},
	)

	// CircuitBreakerTrips tracks the total number of times each circuit breaker
	// has tripped (transitioned to open).
	CircuitBreakerTrips = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "morf_circuit_breaker_trips_total",
			Help: "Total number of times a circuit breaker has tripped to open",
		},
		[]string{"name"},
	)
)

// RecordScan records a scan completion
func RecordScan(status string) {
	ScansTotal.WithLabelValues(status).Inc()
}

// RecordScanDuration records scan duration for a phase
func RecordScanDuration(phase string, duration float64) {
	ScanDuration.WithLabelValues(phase).Observe(duration)
}

// RecordSecretsFound records number of secrets found
func RecordSecretsFound(count float64) {
	SecretsFound.Observe(count)
}

// SetQueueDepth sets the current queue depth
func SetQueueDepth(depth float64) {
	QueueDepth.Set(depth)
}

// RecordToolExecution records tool execution duration
func RecordToolExecution(tool string, duration float64) {
	ToolExecutionDuration.WithLabelValues(tool).Observe(duration)
}

// RecordHTTPRequest records an HTTP request
func RecordHTTPRequest(method, endpoint, status string) {
	HTTPRequestsTotal.WithLabelValues(method, endpoint, status).Inc()
}

// RecordHTTPRequestDuration records HTTP request duration
func RecordHTTPRequestDuration(method, endpoint string, duration float64) {
	HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration)
}

// RecordError records an error by type
func RecordError(errorType string) {
	ErrorsTotal.WithLabelValues(errorType).Inc()
}

// IncrementActiveScans increments active scans counter
func IncrementActiveScans() {
	ActiveScans.Inc()
}

// DecrementActiveScans decrements active scans counter
func DecrementActiveScans() {
	ActiveScans.Dec()
}

// RecordFileUploadSize records uploaded file size
func RecordFileUploadSize(size float64) {
	FileUploadSize.Observe(size)
}

// SetDBPoolStats updates all DB connection-pool gauges from a sql.DBStats snapshot.
func SetDBPoolStats(s sql.DBStats) {
	DBPoolConnections.WithLabelValues("in_use").Set(float64(s.InUse))
	DBPoolConnections.WithLabelValues("idle").Set(float64(s.Idle))
	DBPoolConnections.WithLabelValues("open").Set(float64(s.OpenConnections))
	DBPoolWaitCount.Set(float64(s.WaitCount))
	DBPoolWaitDuration.Set(s.WaitDuration.Seconds())
}

// SetCircuitBreakerState sets the state gauge for the named circuit breaker
// (0=closed, 1=open, 2=half-open).
func SetCircuitBreakerState(name string, state float64) {
	CircuitBreakerState.WithLabelValues(name).Set(state)
}

// RecordCircuitBreakerTrip increments the trip counter for the named circuit
// breaker. Call this on a transition to the open state.
func RecordCircuitBreakerTrip(name string) {
	CircuitBreakerTrips.WithLabelValues(name).Inc()
}

// StartDBPoolStatsReporter launches a background goroutine that calls dbStats on
// each tick and updates the DB connection-pool gauges via SetDBPoolStats. The
// goroutine exits when ctx is cancelled. dbStats is injected to avoid an import
// cycle with the db package. If interval is ≤ 0 it defaults to 10 seconds.
func StartDBPoolStatsReporter(ctx context.Context, dbStats func() sql.DBStats, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				SetDBPoolStats(dbStats())
			}
		}
	}()
}

// StartQueueDepthReporter launches a background goroutine that calls depthFn on
// each tick and updates the QueueDepth gauge via SetQueueDepth. The goroutine
// exits when ctx is cancelled. depthFn is injected to avoid an import cycle with
// the queue package. If interval is ≤ 0 it defaults to 10 seconds.
func StartQueueDepthReporter(ctx context.Context, depthFn func() (int64, error), interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := depthFn()
				if err != nil {
					logrus.WithError(err).Error("metrics: queue depth reporter error")
					continue
				}
				SetQueueDepth(float64(n))
			}
		}
	}()
}
