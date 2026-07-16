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

package ingest

import (
	"context"
	"testing"
)

func TestSchemeOf(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"s3://bucket/key.apk", "s3"},
		{"S3://bucket/key.apk", "s3"}, // case-insensitive
		{"https://host/app.apk", "https"},
		{"http://host/app.apk", "http"},
		{"appstoreconnect://123", "appstoreconnect"},
		{"file:///tmp/app.apk", "file"},
		{"./relative/app.apk", "file"},      // bare path
		{"/abs/path/app.apk", "file"},       // bare abs path
		{"app.apk", "file"},                 // no separator
		{"C:\\Users\\a\\app.apk", "file"},   // windows-ish path, not a scheme
		{"weird path://with space", "file"}, // not a valid scheme token
	}
	for _, c := range cases {
		if got := SchemeOf(c.ref); got != c.want {
			t.Errorf("SchemeOf(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

func TestRegistryResolvesKnownSchemes(t *testing.T) {
	// Every scheme we register in init() must resolve to an adapter whose
	// Scheme() reports back the same scheme.
	for _, scheme := range []string{"file", "https", "http", "s3",
		"appstoreconnect", "testflight", "xcodecloud", "googleplay"} {
		ref := scheme + "://x"
		if scheme == "file" {
			ref = "/tmp/x.apk"
		}
		a, err := Get(ref, Options{})
		if err != nil {
			t.Fatalf("Get(%q): unexpected error %v", ref, err)
		}
		if a.Scheme() != scheme {
			t.Errorf("Get(%q).Scheme() = %q, want %q", ref, a.Scheme(), scheme)
		}
	}
}

func TestGetUnknownSchemeErrors(t *testing.T) {
	_, err := Get("ftp://host/app.apk", Options{})
	if err == nil {
		t.Fatal("expected error for unknown scheme, got nil")
	}
}

func TestSchemesIncludesRegistered(t *testing.T) {
	got := Schemes()
	want := map[string]bool{"file": true, "https": true, "s3": true, "googleplay": true}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s] = true
	}
	for w := range want {
		if !seen[w] {
			t.Errorf("Schemes() missing %q; got %v", w, got)
		}
	}
}

// TestDefaultMaxBytesEnvOverride confirms the env override is honoured and the
// fallback is the shared APK-download cap.
func TestDefaultMaxBytesEnvOverride(t *testing.T) {
	t.Setenv("MORF_INGEST_MAX_BYTES", "12345")
	if got := DefaultMaxBytes(); got != 12345 {
		t.Errorf("DefaultMaxBytes() with override = %d, want 12345", got)
	}
	t.Setenv("MORF_INGEST_MAX_BYTES", "0") // non-positive => fallback
	if got := DefaultMaxBytes(); got != 500<<20 {
		t.Errorf("DefaultMaxBytes() fallback = %d, want %d", got, int64(500<<20))
	}
}

func TestStubAdaptersReturnNotConfigured(t *testing.T) {
	cases := []struct {
		ref     string
		envHint string
	}{
		{"appstoreconnect://build-1", "MORF_ASC_ISSUER_ID"},
		{"testflight://build-2", "MORF_ASC_ISSUER_ID"},
		{"xcodecloud://build-3", "MORF_XCODE_CLOUD_PRODUCT_ID"},
		{"googleplay://com.example.app", "MORF_GOOGLE_PLAY_SA_JSON"},
	}
	for _, c := range cases {
		_, err := Fetch(context.Background(), c.ref, Options{})
		if err == nil {
			t.Fatalf("Fetch(%q): expected not-configured error, got nil", c.ref)
		}
		if !isNotConfigured(err) {
			t.Errorf("Fetch(%q): error %v does not wrap ErrAdapterNotConfigured", c.ref, err)
		}
		if !contains(err.Error(), c.envHint) {
			t.Errorf("Fetch(%q): error %q does not mention %q", c.ref, err.Error(), c.envHint)
		}
		if !contains(err.Error(), "docs/INGESTION.md") {
			t.Errorf("Fetch(%q): error %q does not point at docs/INGESTION.md", c.ref, err.Error())
		}
	}
}
