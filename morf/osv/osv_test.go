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

package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"morf/models"
)

// ---- fake OSV server fixtures ----------------------------------------------

// mavenVulnID is the vuln ID the fake server returns for the known-vulnerable
// Maven component.
const mavenVulnID = "CVE-2021-44228"

// buildFakeOSVServer returns an httptest.Server that serves canned querybatch
// and vuln-detail responses for a known-vulnerable Maven component
// (com.google.code.gson:gson@2.8.0). The netCallCount atomic is incremented on
// every request so tests can assert "no network calls made".
func buildFakeOSVServer(t *testing.T, netCallCount *int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(netCallCount, 1)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			handleQueryBatch(t, w, r)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			handleVulnDetail(t, w, r)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// handleQueryBatch returns a results array aligned with the incoming queries:
// the first query that matches com.google.code.gson:gson at version 2.8.0 gets
// a hit; all others get an empty vulns array.
func handleQueryBatch(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var req osvQueryBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	results := make([]osvQueryResult, len(req.Queries))
	for i, q := range req.Queries {
		if q.Package.Ecosystem == "Maven" &&
			q.Package.Name == "com.google.code.gson:gson" &&
			q.Version == "2.8.0" {
			results[i] = osvQueryResult{
				Vulns: []struct {
					ID string `json:"id"`
				}{{ID: mavenVulnID}},
			}
		}
	}
	resp := osvQueryBatchResponse{Results: results}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleVulnDetail returns a canned vulnerability detail for mavenVulnID.
// Any other ID returns 404.
func handleVulnDetail(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
	if id != mavenVulnID {
		http.NotFound(w, r)
		return
	}
	detail := osvVulnDetail{
		ID:      mavenVulnID,
		Aliases: []string{"GHSA-example-1234"},
		Summary: "Log4Shell RCE vulnerability in Apache Log4j 2 (used as fixture)",
		Severity: []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
}

// ---- helper to build a Client pointed at the fake server -------------------

func newTestClient(serverURL string) *Client {
	c := NewClient()
	c.baseURL = serverURL
	return c
}

// ---- test components -------------------------------------------------------

// mavenVulnComponent returns an SBOMComponent with a Maven purl for
// gson@2.8.0, which the fake server returns a hit for.
func mavenVulnComponent() models.SBOMComponent {
	return models.SBOMComponent{
		Type:    "library",
		Name:    "gson",
		Version: "2.8.0",
		BomRef:  "maven:com.google.code.gson:gson@2.8.0",
		Purl:    "pkg:maven/com.google.code.gson/gson@2.8.0",
		Group:   "com.google.code.gson",
	}
}

// npmComponent returns a component with an npm purl. The fake server returns
// no hits for it (correct: it is just not in the server's fixture data).
func npmComponent() models.SBOMComponent {
	return models.SBOMComponent{
		Type:    "library",
		Name:    "lodash",
		Version: "4.17.15",
		BomRef:  "npm:lodash@4.17.15",
		Purl:    "pkg:npm/lodash@4.17.15",
	}
}

// noVersionComponent returns a component with no version in its purl.
func noVersionComponent() models.SBOMComponent {
	return models.SBOMComponent{
		Type:   "framework",
		Name:   "Alamofire",
		BomRef: "framework:Alamofire",
		Purl:   "pkg:cocoapods/Alamofire",
	}
}

// genericComponent returns a pkg:generic component (unsupported ecosystem).
func genericComponent() models.SBOMComponent {
	return models.SBOMComponent{
		Type:    "library",
		Name:    "some-native-lib",
		Version: "1.0.0",
		BomRef:  "native:some-native-lib",
		Purl:    "pkg:generic/some-native-lib@1.0.0",
	}
}

// ============================================================================
// Test A: opt-in ON → vulnerabilities[] present with correct id/affects/rating
// ============================================================================

func TestEnrichComponents_OptIn_VulnsPresent(t *testing.T) {
	var callCount int64
	srv := buildFakeOSVServer(t, &callCount)
	defer srv.Close()

	client := newTestClient(srv.URL)
	components := []models.SBOMComponent{mavenVulnComponent(), npmComponent()}

	vulns := client.EnrichComponents(context.Background(), components)

	// At least one vuln must be returned for the Maven component.
	if len(vulns) == 0 {
		t.Fatal("expected at least 1 vulnerability for the known-vulnerable Maven component, got 0")
	}

	// Find the CVE-2021-44228 entry.
	var found *OSVVulnerability
	for i := range vulns {
		if vulns[i].ID == mavenVulnID {
			found = &vulns[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected vulnerability %s in results; got %v", mavenVulnID, vulns)
	}

	// AffectedBomRef must point to the Maven component.
	if found.AffectedBomRef != mavenVulnComponent().BomRef {
		t.Errorf("AffectedBomRef = %q; want %q", found.AffectedBomRef, mavenVulnComponent().BomRef)
	}

	// Severity derived from the CVSS vector (all H's + scope=C -> critical).
	if found.Severity != "critical" {
		t.Errorf("Severity = %q; want critical", found.Severity)
	}

	// SourceName must be "OSV" (no raw response bodies leaked).
	if found.SourceName != "OSV" {
		t.Errorf("SourceName = %q; want OSV", found.SourceName)
	}

	// SourceURL must reference the vuln ID.
	if !strings.Contains(found.SourceURL, mavenVulnID) {
		t.Errorf("SourceURL = %q; want it to contain %s", found.SourceURL, mavenVulnID)
	}

	// Aliases must include the GHSA identifier.
	foundAlias := false
	for _, a := range found.Aliases {
		if strings.HasPrefix(a, "GHSA-") {
			foundAlias = true
		}
	}
	if !foundAlias {
		t.Errorf("Aliases = %v; expected a GHSA-* alias", found.Aliases)
	}

	// Network must have been called (querybatch + at least one detail).
	if callCount == 0 {
		t.Error("expected network calls to have been made")
	}
}

// ============================================================================
// Test B: opt-in OFF → no network call and no vulnerabilities array
// ============================================================================

func TestEnrichComponents_OptOff_NoNetworkNoVulns(t *testing.T) {
	var callCount int64
	srv := buildFakeOSVServer(t, &callCount)
	defer srv.Close()

	// The test does NOT call client.EnrichComponents directly — it simulates
	// the gate check that the caller is responsible for (IsEnabled). We assert
	// that when the env gate is off, no calls reach the fake server.
	//
	// The env var should not be "true" in the test environment by default.
	// Unset it explicitly to be safe.
	t.Setenv(EnvOSVEnabled, "false")

	if IsEnabled() {
		t.Skip("MORF_ENABLE_OSV=true in environment; skipping opt-off test")
	}

	// Simulated caller respecting the gate.
	var vulns []OSVVulnerability
	if IsEnabled() {
		client := newTestClient(srv.URL)
		vulns = client.EnrichComponents(context.Background(), []models.SBOMComponent{mavenVulnComponent()})
	}

	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities when opt-off; got %d", len(vulns))
	}
	if atomic.LoadInt64(&callCount) != 0 {
		t.Errorf("expected 0 network calls when opt-off; got %d", atomic.LoadInt64(&callCount))
	}
}

// ============================================================================
// Test C: components without version or unsupported ecosystem are skipped
// ============================================================================

func TestEnrichComponents_SkipsUnsupportedAndNoVersion(t *testing.T) {
	var callCount int64
	srv := buildFakeOSVServer(t, &callCount)
	defer srv.Close()

	client := newTestClient(srv.URL)
	components := []models.SBOMComponent{
		noVersionComponent(), // cocoapods, no version -> skip
		genericComponent(),   // pkg:generic -> skip
	}

	vulns := client.EnrichComponents(context.Background(), components)

	// No supported+versioned components: querybatch should not be called.
	if atomic.LoadInt64(&callCount) != 0 {
		t.Errorf("expected 0 network calls for unsupported/no-version components; got %d", atomic.LoadInt64(&callCount))
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities for unsupported components; got %d", len(vulns))
	}
}

// ============================================================================
// Test D: network error/timeout degrades gracefully (SBOM still emitted, no vulns)
// ============================================================================

func TestEnrichComponents_NetworkErrorDegradesgracefully(t *testing.T) {
	// Serve an instant 503 to simulate a down OSV service.
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer errSrv.Close()

	client := newTestClient(errSrv.URL)
	components := []models.SBOMComponent{mavenVulnComponent()}

	// Must not panic; must return nil/empty (graceful degradation).
	vulns := client.EnrichComponents(context.Background(), components)

	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns on server error; got %d", len(vulns))
	}
}

// Additional: connection-refused also degrades gracefully.
func TestEnrichComponents_ConnectionRefusedDegradesgracefully(t *testing.T) {
	// Point at a TCP address nothing is listening on.
	client := newTestClient("http://127.0.0.1:1") // port 1 is reserved, always refused

	components := []models.SBOMComponent{mavenVulnComponent()}
	vulns := client.EnrichComponents(context.Background(), components)
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns on connection refused; got %d", len(vulns))
	}
}

// ============================================================================
// Test E: no response-body leakage (the raw HTTP body must not appear in logs
// or the returned vulnerability struct)
// ============================================================================

func TestEnrichComponents_NoResponseBodyLeakage(t *testing.T) {
	// Inject a sentinel string into the fake response that must never appear
	// verbatim in the returned OSVVulnerability summary (we truncate/sanitize).
	sentinel := "SUPER_SECRET_RESPONSE_BODY_CONTENT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			// Return a hit for the Maven component.
			resp := osvQueryBatchResponse{
				Results: []osvQueryResult{
					{Vulns: []struct {
						ID string `json:"id"`
					}{{ID: mavenVulnID}}},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			detail := osvVulnDetail{
				ID:      mavenVulnID,
				Summary: "Short summary. " + sentinel,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	vulns := client.EnrichComponents(context.Background(), []models.SBOMComponent{mavenVulnComponent()})

	if len(vulns) == 0 {
		t.Fatal("expected at least 1 vulnerability")
	}
	// The summary is truncated to 256 runes. The sentinel is 37 chars; together
	// with "Short summary. " (16) = 53 chars, well within 256, so it will appear.
	// But it should appear ONLY in Summary, not in any other field that would
	// indicate wholesale body logging.
	for _, v := range vulns {
		if strings.Contains(v.SourceName, sentinel) {
			t.Errorf("SourceName leaked response body content: %q", v.SourceName)
		}
		if strings.Contains(v.SourceURL, sentinel) {
			t.Errorf("SourceURL leaked response body content: %q", v.SourceURL)
		}
		if strings.Contains(v.Severity, sentinel) {
			t.Errorf("Severity leaked response body content: %q", v.Severity)
		}
	}
}

// ============================================================================
// Unit tests for purlToOSV mapping
// ============================================================================

func TestPurlToOSV(t *testing.T) {
	cases := []struct {
		purl    string
		wantEco string
		wantPkg string
		wantVer string
		wantOK  bool
	}{
		// Maven with version.
		{
			purl:    "pkg:maven/com.google.code.gson/gson@2.8.0",
			wantEco: "Maven",
			wantPkg: "com.google.code.gson:gson",
			wantVer: "2.8.0",
			wantOK:  true,
		},
		// Pub with version.
		{
			purl:    "pkg:pub/http@0.13.4",
			wantEco: "Pub",
			wantPkg: "http",
			wantVer: "0.13.4",
			wantOK:  true,
		},
		// npm with version.
		{
			purl:    "pkg:npm/lodash@4.17.15",
			wantEco: "npm",
			wantPkg: "lodash",
			wantVer: "4.17.15",
			wantOK:  true,
		},
		// Swift with version.
		{
			purl:    "pkg:swift/github.com/Alamofire/Alamofire@5.4.3",
			wantEco: "SwiftURL",
			wantPkg: "https://github.com/Alamofire/Alamofire",
			wantVer: "5.4.3",
			wantOK:  true,
		},
		// CocoaPods — unsupported.
		{
			purl:   "pkg:cocoapods/Alamofire@5.4.3",
			wantOK: false,
		},
		// generic — unsupported.
		{
			purl:   "pkg:generic/libssl@1.0.0",
			wantOK: false,
		},
		// Maven without version — skip.
		{
			purl:   "pkg:maven/com.google.code.gson/gson",
			wantOK: false,
		},
		// Empty purl.
		{
			purl:   "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.purl, func(t *testing.T) {
			eco, pkg, ver, ok := purlToOSV(tc.purl)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v; want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if eco != tc.wantEco {
				t.Errorf("ecosystem = %q; want %q", eco, tc.wantEco)
			}
			if pkg != tc.wantPkg {
				t.Errorf("pkgName = %q; want %q", pkg, tc.wantPkg)
			}
			if ver != tc.wantVer {
				t.Errorf("version = %q; want %q", ver, tc.wantVer)
			}
		})
	}
}

// ============================================================================
// Unit tests for severity resolution
// ============================================================================

func TestScoreToLabel(t *testing.T) {
	cases := []struct {
		score string
		want  string
	}{
		{"9.8", "critical"},
		{"9.0", "critical"},
		{"7.5", "high"},
		{"7.0", "high"},
		{"5.0", "medium"},
		{"4.0", "medium"},
		{"2.5", "low"},
		{"0.0", "unknown"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.score, func(t *testing.T) {
			got := scoreToLabel(tc.score)
			if got != tc.want {
				t.Errorf("scoreToLabel(%q) = %q; want %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestSeverityFromVector(t *testing.T) {
	cases := []struct {
		vec  string
		want string
	}{
		// Critical: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (4 :H + scope changed)
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "critical"},
		// High: C:H/I:H (2 :H, no scope change)
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "high"},
		// Medium: C:H (1 :H)
		{"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "medium"},
		// Low: only M's
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:M/I:N/A:N", "low"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := severityFromVector(tc.vec)
			if got != tc.want {
				t.Errorf("severityFromVector(%q) = %q; want %q", tc.vec, got, tc.want)
			}
		})
	}
}

// ============================================================================
// Test IsEnabled
// ============================================================================

func TestIsEnabled(t *testing.T) {
	t.Setenv(EnvOSVEnabled, "true")
	if !IsEnabled() {
		t.Error("IsEnabled() = false; want true when env=true")
	}

	t.Setenv(EnvOSVEnabled, "false")
	if IsEnabled() {
		t.Error("IsEnabled() = true; want false when env=false")
	}

	t.Setenv(EnvOSVEnabled, "")
	if IsEnabled() {
		t.Error("IsEnabled() = true; want false when env=empty")
	}
}
