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

package ios

// Unit tests for firebase_misconfig.go (unit P2b — iOS side).
//
// All four required scenarios:
//   (a) Passive: plist with DATABASE_URL → INFO finding, no HTTP call made.
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

	"morf/apk"
	"morf/models"
)

// makeGoogleServiceInfoPlist constructs a minimal GoogleService-Info.plist XML
// that parseable by ParseGoogleServiceInfoPlist and IOSFirebaseResourceConfig.
// When dbURL is empty, DATABASE_URL is omitted from the plist.
func makeGoogleServiceInfoPlist(projectID, dbURL, bucket string) []byte {
	var extraKeys string
	if dbURL != "" {
		extraKeys += "\t<key>DATABASE_URL</key>\n\t<string>" + dbURL + "</string>\n"
	}
	if bucket != "" {
		extraKeys += "\t<key>STORAGE_BUCKET</key>\n\t<string>" + bucket + "</string>\n"
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PROJECT_ID</key>
	<string>` + projectID + `</string>
	<key>BUNDLE_ID</key>
	<string>com.example.testapp</string>
	<key>GCM_SENDER_ID</key>
	<string>123456789</string>
	<key>GOOGLE_APP_ID</key>
	<string>1:123456789:ios:abcdef</string>
` + extraKeys + `</dict>
</plist>`)
}

// iosRoundTripFunc is an http.RoundTripper backed by a function (iOS test helper).
type iosRoundTripFunc func(*http.Request) (*http.Response, error)

func (f iosRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// findIOSFindingByRuleID returns the first PlatformFinding with the given ruleID,
// or nil when none is present.
func findIOSFindingByRuleID(findings []models.PlatformFinding, ruleID string) *models.PlatformFinding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Scenario (a) — Passive: DATABASE_URL in plist → INFO finding, no HTTP call.
// --------------------------------------------------------------------------

func TestIOSFirebasePassiveFinding_RTDBPresent(t *testing.T) {
	t.Setenv("MORF_ENABLE_VERIFICATION", "") // ensure active probe is off

	const projectID = "my-ios-project"
	const dbURL = "https://my-ios-project-default-rtdb.firebaseio.com"
	const bucket = "my-ios-project.appspot.com"

	plistData := makeGoogleServiceInfoPlist(projectID, dbURL, bucket)

	fc, err := ParseGoogleServiceInfoPlist(plistData)
	if err != nil {
		t.Fatalf("ParseGoogleServiceInfoPlist: %v", err)
	}

	// Provide a never-called HTTP client to assert no network access.
	called := false
	safeClient := &http.Client{
		Transport: iosRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			t.Errorf("unexpected HTTP call to %s (passive mode — no network expected)", r.URL)
			return nil, http.ErrHandlerTimeout
		}),
	}

	ctx := context.Background()
	findings := AnalyzeIOSFirebaseMisconfig(ctx, plistData, fc, "ios-job-a", safeClient)

	if called {
		t.Fatal("HTTP client was invoked in passive mode — should not make any network calls")
	}

	rtdb := findIOSFindingByRuleID(findings, "firebase-rtdb-present")
	if rtdb == nil {
		t.Fatalf("expected firebase-rtdb-present finding but got none; all findings: %v", findings)
	}
	if rtdb.Severity != models.SeverityInfo {
		t.Errorf("RTDB present: severity = %v, want SeverityInfo", rtdb.Severity)
	}
	if !strings.Contains(rtdb.Evidence, "firebaseio.com") {
		t.Errorf("RTDB present: Evidence %q does not mention the db host", rtdb.Evidence)
	}

	// Storage finding also expected.
	storage := findIOSFindingByRuleID(findings, "firebase-storage-present")
	if storage == nil {
		t.Fatalf("expected firebase-storage-present finding but got none")
	}
	if !strings.Contains(storage.Evidence, bucket) {
		t.Errorf("storage present: Evidence %q does not contain bucket name %q", storage.Evidence, bucket)
	}

	// No world-readable finding (active probe is off).
	if wr := findIOSFindingByRuleID(findings, "firebase-rtdb-world-readable"); wr != nil {
		t.Errorf("unexpected firebase-rtdb-world-readable finding in passive mode")
	}
}

// --------------------------------------------------------------------------
// Scenario (b) — Active: httptest server returns 200+JSON → world-readable HIGH.
// --------------------------------------------------------------------------

func TestIOSFirebaseActiveFinding_WorldReadable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return fake RTDB data — the probe must NOT include this in Evidence.
		_, _ = w.Write([]byte(`{"ios_secret_data":"ios_super_secret_value_12345"}`))
	}))
	defer ts.Close()

	t.Setenv("MORF_ENABLE_VERIFICATION", "true")

	// Build a FirebaseResourceConfig directly with a Firebase-looking URL, using
	// a host-rewriting transport so the actual HTTP call goes to ts.
	const fakeRTDBURL = "https://ios-testproject-default-rtdb.firebaseio.com"
	res := apk.FirebaseResourceConfig{
		RTDBURL: fakeRTDBURL,
	}

	hostRewrite := iosRoundTripFunc(func(req *http.Request) (*http.Response, error) {
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
	findings := apk.FirebaseMisconfigFindings(ctx, res, locationGoogleServiceInfoPlist, "ios-job-b", client)

	// Passive finding must be present.
	passive := findIOSFindingByRuleID(findings, "firebase-rtdb-present")
	if passive == nil {
		t.Fatalf("expected passive firebase-rtdb-present finding")
	}

	// Active world-readable finding must be present.
	wr := findIOSFindingByRuleID(findings, "firebase-rtdb-world-readable")
	if wr == nil {
		t.Fatalf("expected firebase-rtdb-world-readable finding for HTTP 200 response")
	}
	if wr.Severity != models.SeverityHigh {
		t.Errorf("world-readable: severity = %v, want SeverityHigh", wr.Severity)
	}

	// Evidence must NOT contain server-returned data.
	for _, f := range findings {
		if strings.Contains(f.Evidence, "ios_super_secret_value_12345") {
			t.Errorf("finding %q Evidence %q leaks server-returned secret data", f.RuleID, f.Evidence)
		}
	}
	if !strings.Contains(wr.Evidence, "firebaseio.com") {
		t.Errorf("world-readable Evidence %q should reference the Firebase host", wr.Evidence)
	}
}

// --------------------------------------------------------------------------
// Scenario (c) — Active: httptest server returns 401 → no world-readable finding.
// --------------------------------------------------------------------------

func TestIOSFirebaseActiveFinding_401NoWorldReadable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	t.Setenv("MORF_ENABLE_VERIFICATION", "true")

	const fakeRTDBURL = "https://locked-ios-project-default-rtdb.firebaseio.com"
	res := apk.FirebaseResourceConfig{
		RTDBURL: fakeRTDBURL,
	}

	hostRewrite := iosRoundTripFunc(func(req *http.Request) (*http.Response, error) {
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
	findings := apk.FirebaseMisconfigFindings(ctx, res, locationGoogleServiceInfoPlist, "ios-job-c", client)

	// Passive finding must still be present.
	passive := findIOSFindingByRuleID(findings, "firebase-rtdb-present")
	if passive == nil {
		t.Fatalf("expected passive firebase-rtdb-present finding even for 401 response")
	}

	// No world-readable finding — 401 means the rules are locked.
	if wr := findIOSFindingByRuleID(findings, "firebase-rtdb-world-readable"); wr != nil {
		t.Errorf("unexpected firebase-rtdb-world-readable finding for 401 response — DB is locked")
	}
}

// --------------------------------------------------------------------------
// Scenario (d) — Active NOT run when env unset → only passive, server never called.
// --------------------------------------------------------------------------

func TestIOSFirebaseActiveNotRunWhenEnvUnset(t *testing.T) {
	t.Setenv("MORF_ENABLE_VERIFICATION", "") // explicitly unset

	var callCount int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"should_not_be_called"}`))
	}))
	defer ts.Close()

	const fakeRTDBURL = "https://noenv-ios-project-default-rtdb.firebaseio.com"
	res := apk.FirebaseResourceConfig{
		RTDBURL: fakeRTDBURL,
	}

	// Even if client is provided, the env gate should prevent any HTTP call.
	hostRewrite := iosRoundTripFunc(func(req *http.Request) (*http.Response, error) {
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
	findings := apk.FirebaseMisconfigFindings(ctx, res, locationGoogleServiceInfoPlist, "ios-job-d", client)

	if n := atomic.LoadInt64(&callCount); n != 0 {
		t.Errorf("HTTP server was called %d time(s) — active probe must not run when env unset", n)
	}

	// Passive finding must still be present.
	passive := findIOSFindingByRuleID(findings, "firebase-rtdb-present")
	if passive == nil {
		t.Fatalf("expected passive firebase-rtdb-present finding")
	}

	// No world-readable finding.
	if wr := findIOSFindingByRuleID(findings, "firebase-rtdb-world-readable"); wr != nil {
		t.Errorf("unexpected firebase-rtdb-world-readable finding when env is unset")
	}
}
