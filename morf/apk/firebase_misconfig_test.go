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

package apk

// Unit tests for firebase_misconfig.go (unit P2b — Android side).
//
// All four required scenarios:
//   (a) Passive: config with RTDB URL → INFO finding, no HTTP call made.
//   (b) Active (MORF_ENABLE_VERIFICATION=true) + httptest server returning 200+JSON
//       → world-readable HIGH finding.
//   (c) Active (MORF_ENABLE_VERIFICATION=true) + httptest server returning 401
//       → only passive finding, no world-readable finding.
//   (d) Active NOT run when env unset → only passive finding, httptest server never called.
//
// Evidence must contain only resource identifiers (db host / bucket name), never
// server-returned data or secrets.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"morf/models"
)

// minimalGoogleServicesJSON returns a minimal google-services.json JSON payload
// with the given DATABASE_URL and STORAGE_BUCKET embedded in project_info.
// When dbURL is empty, the key is omitted, which exercises the project_id-derived
// URL fallback in AndroidFirebaseResourceConfig.
func minimalGoogleServicesJSON(projectID, dbURL, bucket string) []byte {
	if dbURL == "" {
		return []byte(`{"project_info":{"project_id":"` + projectID + `","project_number":"123"}}`)
	}
	return []byte(`{"project_info":{"project_id":"` + projectID + `","project_number":"123","database_url":"` + dbURL + `","storage_bucket":"` + bucket + `"}}`)
}

// makeGoogleServicesConfig returns a populated googleServicesConfig for use in
// AnalyzeAndroidFirebaseMisconfig calls.
func makeGoogleServicesConfig(projectID string) *googleServicesConfig {
	cfg := &googleServicesConfig{}
	cfg.ProjectInfo.ProjectID = projectID
	cfg.ProjectInfo.ProjectNumber = "123456789"
	return cfg
}

// --------------------------------------------------------------------------
// Scenario (a) — Passive: RTDB URL present → INFO finding, no HTTP call.
// --------------------------------------------------------------------------

func TestAndroidFirebasePassiveFinding_RTDBPresent(t *testing.T) {
	t.Setenv(firebaseEnvVerificationEnabled, "") // ensure active probe is off

	const projectID = "myproject"
	const dbURL = "https://myproject-default-rtdb.firebaseio.com"
	const bucket = "myproject.appspot.com"

	rawJSON := minimalGoogleServicesJSON(projectID, dbURL, bucket)
	cfg := makeGoogleServicesConfig(projectID)

	// Provide a never-called HTTP client to assert no network access.
	called := false
	safeClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			t.Errorf("unexpected HTTP call to %s (passive mode — no network expected)", r.URL)
			return nil, http.ErrHandlerTimeout
		}),
	}

	ctx := context.Background()
	findings := AnalyzeAndroidFirebaseMisconfig(ctx, rawJSON, cfg, "job-a", safeClient)

	if called {
		t.Fatal("HTTP client was invoked in passive mode — should not make any network calls")
	}

	rtdb := findFindingByRuleID(findings, ruleFirebaseRTDBPresent)
	if rtdb == nil {
		t.Fatalf("expected %q finding but got none; all findings: %v", ruleFirebaseRTDBPresent, findings)
	}
	if rtdb.Severity != models.SeverityInfo {
		t.Errorf("RTDB present: severity = %v, want SeverityInfo", rtdb.Severity)
	}
	if rtdb.MASVSID != masvsIDPlatform1 {
		t.Errorf("RTDB present: MASVSID = %q, want %q", rtdb.MASVSID, masvsIDPlatform1)
	}

	// Evidence must contain only the db host, not any secret or server data.
	if !strings.Contains(rtdb.Evidence, "firebaseio.com") {
		t.Errorf("RTDB present: Evidence %q does not mention the db host", rtdb.Evidence)
	}

	// Storage finding also expected.
	storage := findFindingByRuleID(findings, ruleFirebaseStoragePresent)
	if storage == nil {
		t.Fatalf("expected %q finding but got none", ruleFirebaseStoragePresent)
	}
	if !strings.Contains(storage.Evidence, bucket) {
		t.Errorf("storage present: Evidence %q does not contain bucket name %q", storage.Evidence, bucket)
	}

	// No world-readable finding (active probe is off).
	if wr := findFindingByRuleID(findings, ruleFirebaseRTDBWorldReadable); wr != nil {
		t.Errorf("unexpected %q finding in passive mode", ruleFirebaseRTDBWorldReadable)
	}
}

// --------------------------------------------------------------------------
// Scenario (b) — Active: httptest server returns 200+JSON → world-readable HIGH.
// --------------------------------------------------------------------------

func TestAndroidFirebaseActiveFinding_WorldReadable(t *testing.T) {
	// httptest server that returns a 200 with JSON (simulates unprotected RTDB).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return fake RTDB data — the probe must NOT include this in Evidence.
		_, _ = w.Write([]byte(`{"secret_data":"super_secret_value_12345"}`))
	}))
	defer ts.Close()

	t.Setenv(firebaseEnvVerificationEnabled, "true")

	// Build a FirebaseResourceConfig with a Firebase-looking URL so isFirebaseRTDB
	// passes, but override the actual HTTP call via a host-rewriting transport
	// that routes to the test server.
	const fakeRTDBURL = "https://testproject-default-rtdb.firebaseio.com"
	res := FirebaseResourceConfig{
		RTDBURL: fakeRTDBURL,
	}

	// Build a transport that rewrites the host to ts.URL.
	hostRewrite := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Replace scheme+host with the test server URL.
		newReq := req.Clone(req.Context())
		newURL := *req.URL
		newURL.Scheme = "http"
		newURL.Host = strings.TrimPrefix(ts.URL, "http://")
		newReq.URL = &newURL
		newReq.Host = newURL.Host
		return http.DefaultTransport.RoundTrip(newReq)
	})
	client := &http.Client{Transport: hostRewrite}

	ctx := context.Background()
	findings := FirebaseMisconfigFindings(ctx, res, locationGoogleServices, "job-b", client)

	// Passive finding must be present.
	passive := findFindingByRuleID(findings, ruleFirebaseRTDBPresent)
	if passive == nil {
		t.Fatalf("expected passive %q finding", ruleFirebaseRTDBPresent)
	}

	// Active world-readable finding must be present.
	wr := findFindingByRuleID(findings, ruleFirebaseRTDBWorldReadable)
	if wr == nil {
		t.Fatalf("expected %q finding for HTTP 200 response", ruleFirebaseRTDBWorldReadable)
	}
	if wr.Severity != models.SeverityHigh {
		t.Errorf("world-readable: severity = %v, want SeverityHigh", wr.Severity)
	}

	// Evidence must NOT contain server-returned data ("super_secret_value_12345").
	for _, f := range findings {
		if strings.Contains(f.Evidence, "super_secret_value_12345") {
			t.Errorf("finding %q Evidence %q leaks server-returned secret data", f.RuleID, f.Evidence)
		}
	}
	// Evidence should mention the db host, not raw response body content.
	if !strings.Contains(wr.Evidence, "firebaseio.com") {
		t.Errorf("world-readable Evidence %q should reference the Firebase host", wr.Evidence)
	}
}

// --------------------------------------------------------------------------
// Scenario (c) — Active: httptest server returns 401 → no world-readable finding.
// --------------------------------------------------------------------------

func TestAndroidFirebaseActiveFinding_401NoWorldReadable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	t.Setenv(firebaseEnvVerificationEnabled, "true")

	const fakeRTDBURL = "https://locked-project-default-rtdb.firebaseio.com"
	res := FirebaseResourceConfig{
		RTDBURL: fakeRTDBURL,
	}

	hostRewrite := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		newReq := req.Clone(req.Context())
		newURL := *req.URL
		newURL.Scheme = "http"
		newURL.Host = strings.TrimPrefix(ts.URL, "http://")
		newReq.URL = &newURL
		newReq.Host = newURL.Host
		return http.DefaultTransport.RoundTrip(newReq)
	})
	client := &http.Client{Transport: hostRewrite}

	ctx := context.Background()
	findings := FirebaseMisconfigFindings(ctx, res, locationGoogleServices, "job-c", client)

	// Passive finding must still be present.
	passive := findFindingByRuleID(findings, ruleFirebaseRTDBPresent)
	if passive == nil {
		t.Fatalf("expected passive %q finding even for 401 response", ruleFirebaseRTDBPresent)
	}

	// No world-readable finding — 401 means the rules are locked.
	if wr := findFindingByRuleID(findings, ruleFirebaseRTDBWorldReadable); wr != nil {
		t.Errorf("unexpected %q finding for 401 response — DB is locked", ruleFirebaseRTDBWorldReadable)
	}
}

// --------------------------------------------------------------------------
// Scenario (d) — Active NOT run when env unset → only passive, server never called.
// --------------------------------------------------------------------------

func TestAndroidFirebaseActiveNotRunWhenEnvUnset(t *testing.T) {
	t.Setenv(firebaseEnvVerificationEnabled, "") // explicitly unset

	var callCount int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"should_not_be_called"}`))
	}))
	defer ts.Close()

	const fakeRTDBURL = "https://noenv-project-default-rtdb.firebaseio.com"
	res := FirebaseResourceConfig{
		RTDBURL: fakeRTDBURL,
	}

	// Even if client is provided, the env gate should prevent any HTTP call.
	hostRewrite := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt64(&callCount, 1)
		newReq := req.Clone(req.Context())
		newURL := *req.URL
		newURL.Scheme = "http"
		newURL.Host = strings.TrimPrefix(ts.URL, "http://")
		newReq.URL = &newURL
		newReq.Host = newURL.Host
		return http.DefaultTransport.RoundTrip(newReq)
	})
	client := &http.Client{Transport: hostRewrite}

	ctx := context.Background()
	findings := FirebaseMisconfigFindings(ctx, res, locationGoogleServices, "job-d", client)

	if n := atomic.LoadInt64(&callCount); n != 0 {
		t.Errorf("HTTP server was called %d time(s) — active probe must not run when env unset", n)
	}

	// Passive finding must still be present.
	passive := findFindingByRuleID(findings, ruleFirebaseRTDBPresent)
	if passive == nil {
		t.Fatalf("expected passive %q finding", ruleFirebaseRTDBPresent)
	}

	// No world-readable finding.
	if wr := findFindingByRuleID(findings, ruleFirebaseRTDBWorldReadable); wr != nil {
		t.Errorf("unexpected %q finding when env is unset", ruleFirebaseRTDBWorldReadable)
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// findFindingByRuleID returns the first PlatformFinding with the given ruleID,
// or nil when none is present.
func findFindingByRuleID(findings []models.PlatformFinding, ruleID string) *models.PlatformFinding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// roundTripFunc is an http.RoundTripper implementation backed by a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
