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

// Package ingest provides a pluggable, scheme-keyed framework for fetching a
// mobile artifact (APK/IPA) from a remote source into a local file so the rest
// of MORF's pipeline (which consumes a local filesystem path) can scan it.
//
// An artifact is named by a scheme-prefixed reference, e.g.
//
//	s3://my-bucket-key/path/app.apk        (object in the configured S3 store)
//	https://host/signed?...&sha256=<hex>   (pre-signed URL, SSRF-guarded)
//	appstoreconnect://<build-id>           (vendor stub; see docs/INGESTION.md)
//	./local/app.apk                        (bare local path; passthrough)
//
// Each scheme is served by an Adapter registered in a process-wide registry.
// Adapters MUST download into the caller-provided destination directory, MUST
// enforce a byte cap, and MUST NOT be steerable to an internal host (SSRF).
//
// The concrete, credential-free-testable adapters are S3 (reusing the existing
// storage.S3Storage) and HTTPS (a generic pre-signed-URL downloader reusing the
// codebase's SSRF/size guards). Vendor adapters (App Store Connect, TestFlight,
// Xcode Cloud, Google Play) are registered as documented stubs that return a
// precise "not configured" error rather than half-built, untestable auth.
package ingest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Adapter fetches the artifact named by a scheme-specific reference into a
// local file and returns its path. Implementations are constructed by a Factory
// bound to a resolved Options (destination dir + byte cap) so the Fetch
// signature can stay minimal.
//
// Contract for every implementation:
//   - MUST write only inside the configured destination directory.
//   - MUST enforce the configured byte cap (Options.MaxBytes) and abort an
//     over-cap or lying-Content-Length download mid-stream.
//   - MUST NOT follow the reference to an internal/non-routable host (SSRF).
type Adapter interface {
	// Scheme is the reference scheme this adapter serves (e.g. "s3", "https").
	Scheme() string
	// Fetch downloads the artifact named by ref and returns the local path.
	Fetch(ctx context.Context, ref string) (localPath string, err error)
}

// Options carries the per-fetch configuration handed to an Adapter Factory. A
// zero Options is valid: DestDir empty means "create a temp dir", MaxBytes <= 0
// means "use the default cap".
type Options struct {
	// DestDir is the directory downloads are written into. When empty the
	// adapter creates an os.MkdirTemp dir (mirroring the worker/CLI behaviour).
	DestDir string
	// MaxBytes caps a single download. <= 0 falls back to DefaultMaxBytes.
	MaxBytes int64
}

// Factory constructs an Adapter bound to the given Options. Registering a
// factory (rather than a singleton) lets each fetch carry its own destination
// directory and size cap while the scheme→adapter mapping stays global.
type Factory func(Options) (Adapter, error)

// registry maps a scheme to the Factory that builds its Adapter. It is guarded
// by mu for concurrent Register/Get, matching the pattern-registry style used
// elsewhere in the codebase.
var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register installs factory under scheme (case-insensitive). A second
// registration for the same scheme panics, surfacing a duplicate-adapter bug at
// startup rather than silently shadowing. Adapters self-register from init().
func Register(scheme string, factory Factory) {
	s := normalizeScheme(scheme)
	if s == "" {
		panic("ingest: Register called with empty scheme")
	}
	if factory == nil {
		panic("ingest: Register called with nil factory for scheme " + s)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[s]; dup {
		panic("ingest: duplicate adapter registration for scheme " + s)
	}
	registry[s] = factory
}

// Schemes returns the sorted list of registered schemes (for help text/errors).
func Schemes() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for s := range registry {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// normalizeScheme lower-cases and trims a scheme for case-insensitive matching.
func normalizeScheme(scheme string) string {
	return strings.ToLower(strings.TrimSpace(scheme))
}

// SchemeOf returns the scheme of a reference. A bare local path (no "scheme://"
// prefix, or a Windows-style drive/relative path) resolves to the builtin
// "file" scheme so existing local-path callers keep working. The split is on
// the first "://" so a URL query/fragment can freely contain colons.
func SchemeOf(ref string) string {
	r := strings.TrimSpace(ref)
	if i := strings.Index(r, "://"); i > 0 {
		// Guard against a "path" that merely contains "://" after a slash (a
		// bare local path can't have a scheme before its first separator).
		scheme := r[:i]
		if isSchemeToken(scheme) {
			return normalizeScheme(scheme)
		}
	}
	return fileScheme
}

// isSchemeToken reports whether s is a syntactically valid URI scheme token
// (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )), which distinguishes a real
// scheme from a local path fragment that happens to contain "://".
func isSchemeToken(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			// always allowed
		case (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return false // scheme must start with a letter
			}
		default:
			return false
		}
	}
	return true
}

// Get resolves the adapter for ref's scheme, constructing it with opts. It
// returns a clear, listing error when no adapter serves the scheme.
func Get(ref string, opts Options) (Adapter, error) {
	scheme := SchemeOf(ref)
	mu.RLock()
	factory, ok := registry[scheme]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("ingest: no adapter registered for scheme %q (known: %s)",
			scheme, strings.Join(Schemes(), ", "))
	}
	return factory(opts)
}

// Fetch is the top-level entry point: it resolves the adapter for ref's scheme,
// constructs it with opts, and fetches. This is what `morf fetch` and any future
// programmatic caller use.
func Fetch(ctx context.Context, ref string, opts Options) (localPath string, err error) {
	adapter, err := Get(ref, opts)
	if err != nil {
		return "", err
	}
	return adapter.Fetch(ctx, ref)
}
