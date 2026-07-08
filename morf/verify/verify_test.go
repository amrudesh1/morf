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

package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"morf/models"
)

// newTestClient builds a client with an unthrottled limiter and no timeout
// pressure so tests exercise verifier logic, not the rate limiter.
func newTestClient() *client {
	c := newClient()
	c.limiter = rate.NewLimiter(rate.Inf, 1)
	return c
}

// assertNoMutation fails if the mock server ever sees a non-safe HTTP method.
// This guards the package-wide invariant that verification is READ-ONLY.
func assertNoMutation(t *testing.T, method string) {
	t.Helper()
	if method != http.MethodGet && method != http.MethodHead {
		t.Fatalf("verifier issued non-read-only request: %s", method)
	}
}

// --- Disabled-by-default -----------------------------------------------------

func TestVerifySecrets_DisabledByDefault(t *testing.T) {
	// Ensure the gate is OFF regardless of ambient env.
	t.Setenv(envVerificationEnabled, "")

	// A live server that would fail the test if contacted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("network call made while verification disabled: %s %s", r.Method, r.URL)
	}))
	defer srv.Close()
	restore := swapEndpoints(srv.URL)
	defer restore()

	in := []models.SecretModel{
		{SecretType: "GitHub", SecretString: "ghp_example"},
		{SecretType: "Slack Token", SecretString: "xoxb-example"},
	}
	out := VerifySecrets(context.Background(), in)
	for _, s := range out {
		if s.VerificationStatus != statusUnchecked {
			t.Fatalf("expected %q, got %q", statusUnchecked, s.VerificationStatus)
		}
	}
}

func TestVerifySecrets_DisabledForNonTrueValue(t *testing.T) {
	t.Setenv(envVerificationEnabled, "TRUE") // not exactly "true"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("network call made for MORF_ENABLE_VERIFICATION=TRUE: %s", r.URL)
	}))
	defer srv.Close()
	restore := swapEndpoints(srv.URL)
	defer restore()

	out := VerifySecrets(context.Background(), []models.SecretModel{{SecretType: "GitHub", SecretString: "x"}})
	if out[0].VerificationStatus != statusUnchecked {
		t.Fatalf("expected unchecked for non-true gate, got %q", out[0].VerificationStatus)
	}
}

// --- GitHub ------------------------------------------------------------------

func TestGithubVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		expect string
	}{
		{"active", http.StatusOK, statusActive},
		{"inactive", http.StatusUnauthorized, statusInactive},
		{"unknown", http.StatusInternalServerError, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Path != "/user" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer tok" {
					t.Fatalf("unexpected auth header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			c := newTestClient()
			githubAPIBase = srv.URL
			v := &githubVerifier{c: c}
			got, err := v.Verify(context.Background(), "tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- Slack -------------------------------------------------------------------

func TestSlackVerifier(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		expect string
	}{
		{"active", `{"ok":true}`, statusActive},
		{"inactive", `{"ok":false,"error":"invalid_auth"}`, statusInactive},
		{"unknown", `{"ok":false}`, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Path != "/api/auth.test" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := newTestClient()
			slackAPIBase = srv.URL
			v := &slackVerifier{c: c}
			got, err := v.Verify(context.Background(), "xoxb-tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- Stripe ------------------------------------------------------------------

func TestStripeVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		expect string
	}{
		{"active", http.StatusOK, statusActive},
		{"inactive", http.StatusUnauthorized, statusInactive},
		{"unknown", http.StatusTooManyRequests, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Path != "/v1/balance" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				user, _, ok := r.BasicAuth()
				if !ok || user != "sk_test_123" {
					t.Fatalf("expected key as basic-auth username, got user=%q ok=%v", user, ok)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			c := newTestClient()
			stripeAPIBase = srv.URL
			v := &stripeVerifier{c: c}
			got, err := v.Verify(context.Background(), "sk_test_123")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- Twilio ------------------------------------------------------------------

func TestTwilioVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		expect string
	}{
		{"active", http.StatusOK, statusActive},
		{"inactive", http.StatusUnauthorized, statusInactive},
		{"unknown", http.StatusBadGateway, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			c := newTestClient()
			twilioAPIBase = srv.URL
			v := &twilioVerifier{c: c}
			got, err := v.Verify(context.Background(), "SK123")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- Google ------------------------------------------------------------------

func TestGoogleVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		expect string
	}{
		{"active", http.StatusOK, `{"kind":"books#volumes"}`, statusActive},
		{"inactive_invalid_key", http.StatusBadRequest,
			`{"error":{"status":"INVALID_ARGUMENT","message":"API key not valid. Please pass a valid API key.","errors":[{"reason":"keyInvalid"}]}}`,
			statusInactive},
		{"unknown_permission", http.StatusForbidden,
			`{"error":{"status":"PERMISSION_DENIED","message":"requests to this API are blocked"}}`,
			statusUnknown},
		{"unknown_ambiguous_400", http.StatusBadRequest,
			`{"error":{"status":"INVALID_ARGUMENT","message":"missing required parameter"}}`,
			statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Query().Get("key") != "AIzaKEY" {
					t.Fatalf("expected key query param, got %q", r.URL.Query().Get("key"))
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := newTestClient()
			googleAPIBase = srv.URL
			v := &googleVerifier{c: c}
			got, err := v.Verify(context.Background(), "AIzaKEY")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- AWS ---------------------------------------------------------------------

func TestAWSVerifier_NeverContactsNetwork(t *testing.T) {
	c := newTestClient()
	v := &awsVerifier{c: c}
	got, err := v.Verify(context.Background(), "AKIAEXAMPLE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != statusUnknown {
		t.Fatalf("AWS access key ID alone must be unknown, got %q", got)
	}
}

// --- Registry / orchestrator -------------------------------------------------

func TestLookup_SubstringCaseInsensitive(t *testing.T) {
	c := newTestClient()
	reg := defaultRegistry(c)
	if lookup(reg, "Github Personal Access Token") == nil {
		t.Fatal("expected GitHub match")
	}
	if lookup(reg, "Stripe Restricted API Key") == nil {
		t.Fatal("expected Stripe match")
	}
	if lookup(reg, "Google Cloud Platform API Key") == nil {
		t.Fatal("expected Google match")
	}
	if lookup(reg, "Random RSA Private Key") != nil {
		t.Fatal("expected no verifier for unrelated type")
	}
	if lookup(reg, "") != nil {
		t.Fatal("expected no verifier for empty type")
	}
}

func TestVerifyWithRegistry_NoVerifierIsUnknown(t *testing.T) {
	c := newTestClient()
	reg := defaultRegistry(c)
	out := verifyWithRegistry(context.Background(),
		[]models.SecretModel{{SecretType: "RSA private key", SecretString: "-----BEGIN"}}, reg)
	if out[0].VerificationStatus != statusUnknown {
		t.Fatalf("expected unknown, got %q", out[0].VerificationStatus)
	}
}

func TestVerifyWithRegistry_EmptySecretIsUnknown(t *testing.T) {
	c := newTestClient()
	reg := defaultRegistry(c)
	out := verifyWithRegistry(context.Background(),
		[]models.SecretModel{{SecretType: "GitHub", SecretString: ""}}, reg)
	if out[0].VerificationStatus != statusUnknown {
		t.Fatalf("expected unknown for empty secret, got %q", out[0].VerificationStatus)
	}
}

func TestVerifyWithRegistry_CacheAvoidsSecondCall(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient()
	githubAPIBase = srv.URL
	reg := defaultRegistry(c)

	in := []models.SecretModel{
		{SecretType: "GitHub", SecretString: "same-token"},
		{SecretType: "GitHub", SecretString: "same-token"},
	}
	out := verifyWithRegistry(context.Background(), in, reg)
	for _, s := range out {
		if s.VerificationStatus != statusActive {
			t.Fatalf("expected active, got %q", s.VerificationStatus)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 provider hit due to cache, got %d", got)
	}
}

func TestVerifyWithRegistry_ExpiredCacheReVerifies(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient()
	// Freeze/advance time to force cache expiry between the two findings.
	base := time.Now()
	var advance time.Duration
	c.now = func() time.Time { return base.Add(advance) }
	githubAPIBase = srv.URL
	reg := defaultRegistry(c)

	_ = verifyWithRegistry(context.Background(),
		[]models.SecretModel{{SecretType: "GitHub", SecretString: "tok"}}, reg)
	advance = cacheTTL + time.Second
	_ = verifyWithRegistry(context.Background(),
		[]models.SecretModel{{SecretType: "GitHub", SecretString: "tok"}}, reg)

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 provider hits across cache expiry, got %d", got)
	}
}

func TestHashSecret_DoesNotEqualRawSecret(t *testing.T) {
	secret := "super-secret-value"
	h := hashSecret(secret)
	if h == secret {
		t.Fatal("hash must not equal the raw secret")
	}
	if len(h) != 64 {
		t.Fatalf("expected 64-char sha256 hex, got %d", len(h))
	}
}

// swapEndpoints points every provider base at base and returns a restore func.
func swapEndpoints(base string) func() {
	pg, ps, pst, pgo, pt := githubAPIBase, slackAPIBase, stripeAPIBase, googleAPIBase, twilioAPIBase
	githubAPIBase, slackAPIBase, stripeAPIBase, googleAPIBase, twilioAPIBase = base, base, base, base, base
	return func() {
		githubAPIBase, slackAPIBase, stripeAPIBase, googleAPIBase, twilioAPIBase = pg, ps, pst, pgo, pt
	}
}
