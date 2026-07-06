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
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gaugeValue reads the current float64 value from a prometheus.Gauge via
// the Write method (no registry gather needed for simple gauges).
func gaugeValue(t *testing.T, g interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func TestSetDBPoolStats(t *testing.T) {
	stats := sql.DBStats{
		OpenConnections: 5,
		InUse:           3,
		Idle:            2,
		WaitCount:       10,
		WaitDuration:    250 * time.Millisecond,
	}

	// Must not panic
	SetDBPoolStats(stats)

	// Verify the individual label gauges
	inUseGauge, err := DBPoolConnections.GetMetricWithLabelValues("in_use")
	require.NoError(t, err)
	assert.InDelta(t, 3.0, gaugeValue(t, inUseGauge), 0.001, "in_use gauge")

	idleGauge, err := DBPoolConnections.GetMetricWithLabelValues("idle")
	require.NoError(t, err)
	assert.InDelta(t, 2.0, gaugeValue(t, idleGauge), 0.001, "idle gauge")

	openGauge, err := DBPoolConnections.GetMetricWithLabelValues("open")
	require.NoError(t, err)
	assert.InDelta(t, 5.0, gaugeValue(t, openGauge), 0.001, "open connections gauge")

	assert.InDelta(t, 10.0, gaugeValue(t, DBPoolWaitCount), 0.001, "wait count gauge")
	assert.InDelta(t, 0.25, gaugeValue(t, DBPoolWaitDuration), 0.001, "wait duration gauge")
}

func TestStartQueueDepthReporter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const fixedDepth int64 = 42
	depthFn := func() (int64, error) { return fixedDepth, nil }

	StartQueueDepthReporter(ctx, depthFn, 5*time.Millisecond)

	// Wait long enough for at least one tick to fire.
	time.Sleep(30 * time.Millisecond)

	assert.InDelta(t, float64(fixedDepth), gaugeValue(t, QueueDepth), 0.001,
		"QueueDepth should be set to the fixed depth after reporter fires")

	// Cancel ctx and give the goroutine a moment to exit.
	cancel()
	time.Sleep(20 * time.Millisecond)
	// If the goroutine leaked it would not cause a test failure directly, but
	// the context cancellation path is exercised above without hanging.
}

func TestStartQueueDepthReporter_DefaultInterval(t *testing.T) {
	// Passing interval=0 should not panic and should use the 10s default
	// (we don't wait 10s; just confirm it starts without error).
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the goroutine exits right away
	StartQueueDepthReporter(ctx, func() (int64, error) { return 0, nil }, 0)
}
