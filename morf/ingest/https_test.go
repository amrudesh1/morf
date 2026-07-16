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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withInternalHostsAllowed flips the SSRF bypass for the duration of fn so a
// test can hit an httptest.Server on 127.0.0.1. It also enables
// MORF_INGEST_ALLOW_HTTP because httptest.Server serves plaintext http://. Both
// are exclusively test affordances (see allowInternalHosts).
func withInternalHostsAllowed(t *testing.T, fn func()) {
	t.Helper()
	t.Setenv("MORF_INGEST_ALLOW_HTTP", "true")
	prev := allowInternalHosts
	allowInternalHosts = true
	defer func() { allowInternalHosts = prev }()
	fn()
}

func TestHTTPSFetchSuccess(t *testing.T) {
	payload := []byte("PK\x03\x04 this is a fake apk body")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/builds/app.apk" {
			http.NotFound(w, r)
			return
		}
		w.Write(payload)
	}))
	defer srv.Close()

	destDir := t.TempDir()
	withInternalHostsAllowed(t, func() {
		got, err := Fetch(context.Background(), srv.URL+"/builds/app.apk", Options{DestDir: destDir})
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if filepath.Dir(got) != destDir {
			t.Errorf("downloaded to %q, want inside %q", got, destDir)
		}
		if !strings.HasSuffix(got, ".apk") {
			t.Errorf("downloaded path %q does not have .apk extension", got)
		}
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != string(payload) {
			t.Errorf("downloaded content mismatch: got %d bytes", len(data))
		}
	})
}

func TestHTTPSFetchSizeCapExceeded(t *testing.T) {
	payload := make([]byte, 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do not set Content-Length so the cap must be enforced mid-stream.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
	}))
	defer srv.Close()

	destDir := t.TempDir()
	withInternalHostsAllowed(t, func() {
		_, err := Fetch(context.Background(), srv.URL+"/app.apk", Options{DestDir: destDir, MaxBytes: 1024})
		if err == nil {
			t.Fatal("expected size-cap error, got nil")
		}
		if !contains(err.Error(), "maximum allowed size") && !contains(err.Error(), "exceeds") {
			t.Errorf("error %q is not a size-cap error", err.Error())
		}
		// No artifact should be left behind.
		entries, _ := os.ReadDir(destDir)
		if len(entries) != 0 {
			t.Errorf("over-cap download left %d file(s) behind", len(entries))
		}
	})
}

func TestHTTPSFetchSizeCapViaContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5000")
		w.Write(make([]byte, 5000))
	}))
	defer srv.Close()

	withInternalHostsAllowed(t, func() {
		_, err := Fetch(context.Background(), srv.URL+"/app.apk", Options{DestDir: t.TempDir(), MaxBytes: 1024})
		if err == nil {
			t.Fatal("expected Content-Length pre-check to reject, got nil")
		}
		if !contains(err.Error(), "exceeds") {
			t.Errorf("error %q is not the Content-Length pre-check", err.Error())
		}
	})
}

func TestHTTPSFetchBlocksLocalhostWhenGuardOn(t *testing.T) {
	// Guard ON (default, allowInternalHosts=false): an https loopback URL must be
	// refused by the up-front SSRF validation before any connection is attempted.
	// A live httptest.Server is started only to obtain a real loopback port; the
	// handler must never be reached.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SSRF guard failed: handler was reached for a loopback URL")
	}))
	defer srv.Close()

	// Force https so the scheme check passes and SSRF is the rejection under test.
	loopbackURL := strings.Replace(srv.URL, "http://", "https://", 1) + "/app.apk"
	_, err := Fetch(context.Background(), loopbackURL, Options{DestDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected SSRF rejection for localhost, got nil")
	}
	if !contains(err.Error(), "SSRF") && !contains(err.Error(), "disallowed") {
		t.Errorf("error %q is not an SSRF rejection", err.Error())
	}
}

func TestHTTPSFetchBlocksMetadataIP(t *testing.T) {
	// The cloud metadata endpoint (link-local) must be refused up front.
	_, err := Fetch(context.Background(), "https://169.254.169.254/latest/meta-data/app.apk", Options{DestDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected SSRF rejection for 169.254.169.254, got nil")
	}
}

func TestHTTPSFetchRefusesRedirect(t *testing.T) {
	// A 3xx must not be followed (redirect-to-internal defense).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/elsewhere.apk", http.StatusFound)
	}))
	defer srv.Close()

	withInternalHostsAllowed(t, func() {
		_, err := Fetch(context.Background(), srv.URL+"/app.apk", Options{DestDir: t.TempDir()})
		if err == nil {
			t.Fatal("expected redirect to be refused, got nil")
		}
	})
}

func TestHTTPSFetchRefusesHTTPByDefault(t *testing.T) {
	// http:// is refused unless MORF_INGEST_ALLOW_HTTP=true. Bypass only the SSRF
	// host check (not the http toggle) so the failure under test is the scheme
	// gate, and assert MORF_INGEST_ALLOW_HTTP is unset for this case.
	t.Setenv("MORF_INGEST_ALLOW_HTTP", "false")
	prev := allowInternalHosts
	allowInternalHosts = true
	defer func() { allowInternalHosts = prev }()

	_, err := Fetch(context.Background(), "http://example.com/app.apk", Options{DestDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected http:// to be refused by default")
	}
	if !contains(err.Error(), "MORF_INGEST_ALLOW_HTTP") {
		t.Errorf("error %q does not mention the allow-http toggle", err.Error())
	}
}

func TestHTTPSFetchNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	withInternalHostsAllowed(t, func() {
		_, err := Fetch(context.Background(), srv.URL+"/app.apk", Options{DestDir: t.TempDir()})
		if err == nil {
			t.Fatal("expected error for non-2xx, got nil")
		}
		if !contains(err.Error(), "410") {
			t.Errorf("error %q does not carry the status code", err.Error())
		}
	})
}

func TestHTTPSFetchSHA256Verification(t *testing.T) {
	payload := []byte("PK\x03\x04 verifiable body")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The sha256 param must have been stripped from the request the server sees.
		if r.URL.Query().Get("sha256") != "" {
			t.Errorf("server received sha256 query param; it should be stripped")
		}
		w.Write(payload)
	}))
	defer srv.Close()

	withInternalHostsAllowed(t, func() {
		// Correct digest: success.
		good := srv.URL + "/app.apk?sha256=" + digest
		if _, err := Fetch(context.Background(), good, Options{DestDir: t.TempDir()}); err != nil {
			t.Fatalf("Fetch with correct sha256: %v", err)
		}
		// Wrong digest: rejected, no file left.
		destDir := t.TempDir()
		bad := srv.URL + "/app.apk?sha256=" + strings.Repeat("00", 32)
		_, err := Fetch(context.Background(), bad, Options{DestDir: destDir})
		if err == nil {
			t.Fatal("expected sha256 mismatch error, got nil")
		}
		if !contains(err.Error(), "sha256 mismatch") {
			t.Errorf("error %q is not a sha256 mismatch", err.Error())
		}
		if entries, _ := os.ReadDir(destDir); len(entries) != 0 {
			t.Errorf("sha256 mismatch left %d file(s) behind", len(entries))
		}
	})
}
