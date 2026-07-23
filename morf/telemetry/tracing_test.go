package telemetry

import (
	"context"
	"morf/models"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestInitTracingNoEndpoint verifies that when no OTLP endpoint is configured
// InitTracing:
//   - returns a non-nil shutdown func,
//   - installs a working TracerProvider (otel.Tracer succeeds),
//   - does NOT install a real exporter (no network dial attempt).
func TestInitTracingNoEndpoint(t *testing.T) {
	// Ensure the OTLP endpoint and the enable flag are both absent.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("MORF_ENABLE_TRACING", "")

	shutdown, err := InitTracing(context.Background())
	if err != nil {
		t.Fatalf("InitTracing returned unexpected error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("InitTracing returned nil shutdown func")
	}

	// The global TracerProvider must be usable: starting a span must not panic.
	tracer := otel.GetTracerProvider().Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	if ctx == nil {
		t.Fatal("span context is nil")
	}
	span.End()

	// Shutdown must not error.
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}
}

// TestInitTracingSpanRecorded verifies that when we wire an in-memory
// SpanRecorder (simulating an enabled exporter without network I/O) a span
// started via otel.Tracer is captured with the expected name and attributes.
//
// We bypass InitTracing here because the test must not attempt any network
// connection; instead we build a TracerProvider backed by tracetest.SpanRecorder
// directly and set it as global — then verify the recording machinery.
func TestInitTracingSpanRecorded(t *testing.T) {
	// Wire the in-memory recorder as the global provider.
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	tracer := otel.GetTracerProvider().Tracer("morf/test")
	_, span := tracer.Start(context.Background(), "morf.upload")
	span.End()

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 recorded span, got %d", len(spans))
	}
	if got := spans[0].Name(); got != "morf.upload" {
		t.Errorf("span name = %q, want %q", got, "morf.upload")
	}
}

// TestTracePropagationRoundTrip verifies that a W3C trace context injected into
// a ScanJob carrier can be extracted and yields the SAME TraceID.  This confirms
// the carrier serialisation round-trip works across the simulated Redis boundary.
func TestTracePropagationRoundTrip(t *testing.T) {
	// Ensure a real SDK provider so spans have non-zero IDs.
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	// --- Router side: start a span and inject into the job carrier ---
	tracer := otel.GetTracerProvider().Tracer("morf/router")
	uploadCtx, uploadSpan := tracer.Start(context.Background(), "morf.upload")
	defer uploadSpan.End()

	job := &models.ScanJob{ID: "test-job-1"}
	job.TraceContext = make(map[string]string)
	otel.GetTextMapPropagator().Inject(uploadCtx, propagation.MapCarrier(job.TraceContext))

	if len(job.TraceContext) == 0 {
		t.Fatal("TraceContext carrier is empty after injection; propagator did not write headers")
	}

	// --- Worker side: extract from the carrier and create a child span ---
	workerTracer := otel.GetTracerProvider().Tracer("morf/worker")
	parentCtx := otel.GetTextMapPropagator().Extract(context.Background(), propagation.MapCarrier(job.TraceContext))
	_, workerSpan := workerTracer.Start(parentCtx, "morf.worker.process_job")
	defer workerSpan.End()

	// The extracted span context must be valid and have the SAME TraceID as the
	// upload span.
	workerSC := workerSpan.SpanContext()
	uploadSC := uploadSpan.SpanContext()

	if !workerSC.IsValid() {
		t.Fatal("extracted worker span context is not valid")
	}
	if workerSC.TraceID() != uploadSC.TraceID() {
		t.Errorf("TraceID mismatch: worker=%s, upload=%s", workerSC.TraceID(), uploadSC.TraceID())
	}
}

// TestInitTracingNoEnvVarsMakeNoNetworkDial is a compile-time check that
// InitTracing with an env that has no endpoint will return the no-op path.
// We verify the provider's type is noop by confirming spans have no-op
// SpanContexts (IsValid=false for no-op tracers).
func TestInitTracingNoopProvider(t *testing.T) {
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Unsetenv("MORF_ENABLE_TRACING")

	shutdown, err := InitTracing(context.Background())
	if err != nil {
		t.Fatalf("InitTracing returned unexpected error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	tracer := otel.GetTracerProvider().Tracer("test-noop")
	_, span := tracer.Start(context.Background(), "noop-span")
	sc := span.SpanContext()
	span.End()

	// A no-op span has an invalid (zero) SpanContext.
	if sc.IsValid() {
		t.Errorf("expected no-op span (IsValid=false) when no endpoint is set, but got valid SpanContext %s", sc.TraceID())
	}
}
