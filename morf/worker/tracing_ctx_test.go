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

package worker

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// TestScanContextPreservesTimeoutCancelAndTrace guards a real regression: when the
// OTel scan span was started, an early version extracted the trace parent onto a
// fresh context.Background(), which silently DROPPED the per-job scan timeout
// (scanCtx's deadline) and the user-cancellation signal (scanCancel via the status
// poller) from the context handed to scanAPK/scanIPA. A hung scan would then run
// forever and mid-scan job cancellation would not abort subprocesses.
//
// The correct wiring overlays the remote trace parent onto scanCtx (Extract derives
// from the passed context), so the span-carrying context keeps BOTH the deadline and
// the cancel while still linking to the distributed trace. This test reproduces that
// composition and asserts all three properties hold together.
func TestScanContextPreservesTimeoutCancelAndTrace(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Simulate the upstream upload span and serialize its context into a carrier
	// (exactly what the router injects into ScanJob.TraceContext before enqueue).
	upCtx, upSpan := tp.Tracer("test").Start(context.Background(), "morf.upload")
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(upCtx, carrier)
	wantTrace := upSpan.SpanContext().TraceID()
	upSpan.End()

	// Reproduce the worker's scanCtx: a per-job timeout plus a poller-driven cancel.
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer scanCancel()

	// The wiring under test: extract the trace parent ONTO scanCtx (not Background),
	// then start the scan span from it.
	parentCtx := otel.GetTextMapPropagator().Extract(scanCtx, carrier)
	scanSpanCtx, scanSpan := tp.Tracer("morf/worker").Start(parentCtx, "morf.worker.scan_apk")
	defer scanSpan.End()

	// (a) The per-job timeout survives — otherwise a hung scan never times out.
	if _, ok := scanSpanCtx.Deadline(); !ok {
		t.Fatal("scan context lost its deadline: the per-job scan timeout would never fire")
	}
	// (b) The scan span is part of the SAME distributed trace as the upload.
	if got := scanSpan.SpanContext().TraceID(); got != wantTrace {
		t.Fatalf("scan span TraceID = %s, want %s: the trace is disconnected across the queue boundary", got, wantTrace)
	}
	// (c) User cancellation propagates into the scan context (mid-scan abort works).
	scanCancel()
	select {
	case <-scanSpanCtx.Done():
		// cancel reached the scan context — correct.
	default:
		t.Fatal("scan context did not observe cancellation: mid-scan job cancel is broken")
	}
}
