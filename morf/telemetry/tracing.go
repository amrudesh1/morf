// Package telemetry provides OpenTelemetry tracing initialization for MORF.
//
// Safety contract:
//   - DEFAULT (OTEL_EXPORTER_OTLP_ENDPOINT unset AND MORF_ENABLE_TRACING!="true"):
//     installs a no-op TracerProvider so otel.Tracer() works everywhere but ZERO
//     bytes leave the process and NO network connection is attempted.
//   - When OTEL_EXPORTER_OTLP_ENDPOINT is set (or MORF_ENABLE_TRACING=="true"):
//     wires an OTLP HTTP exporter, batch span processor, and a resource carrying
//     service.name="morf" and service.version from morf/version.  Sets the
//     global TracerProvider + a W3C TraceContext/Baggage propagator.
//
// The shutdown func returned by InitTracing flushes/stops the provider; always
// defer it in main.
package telemetry

import (
	"context"
	"morf/version"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace/noop"
)

const serviceName = "morf"

// InitTracing initialises the global OpenTelemetry TracerProvider.
//
// When neither OTEL_EXPORTER_OTLP_ENDPOINT nor MORF_ENABLE_TRACING="true" is
// set the function installs a no-op provider: otel.Tracer() calls succeed but
// no exporter exists and no dial is attempted.
//
// When an OTLP endpoint is configured the function builds a real SDK provider
// with an OTLP HTTP exporter + batch processor.
//
// The returned shutdown func is always non-nil; defer it to flush spans on exit.
func InitTracing(ctx context.Context) (shutdown func(context.Context) error, err error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	enabled := os.Getenv("MORF_ENABLE_TRACING") == "true"

	// Install the W3C propagator unconditionally so context injection/extraction
	// work even when the no-op provider is active (carrier maps are written/read
	// but the resulting spans are no-ops).
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if endpoint == "" && !enabled {
		// No exporter: install a true no-op provider.  Zero network, zero
		// allocation pressure beyond the noop span objects.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(_ context.Context) error { return nil }, nil
	}

	// Build the OTLP HTTP exporter.  otlptracehttp.New reads
	// OTEL_EXPORTER_OTLP_ENDPOINT (and headers/TLS/timeout overrides) from env
	// automatically.
	exp, expErr := otlptracehttp.New(ctx)
	if expErr != nil {
		return func(_ context.Context) error { return nil }, expErr
	}

	// Resource: stamps every span with service.name and service.version.
	res, resErr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version.Version),
		),
	)
	if resErr != nil {
		// resource.Merge only errors on schema conflicts; fall back gracefully.
		res = resource.Default()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)

	return func(shutCtx context.Context) error {
		return tp.Shutdown(shutCtx)
	}, nil
}
