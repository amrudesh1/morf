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
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"morf/models"
)

// hexEncode is a tiny test helper for asserting on signing-key bytes.
func hexEncode(b []byte) string { return hex.EncodeToString(b) }

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
	got, err := v.Verify(context.Background(), "AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != statusUnknown {
		t.Fatalf("AWS access key ID alone must be unknown, got %q", got)
	}
}

// fakeSTSHandler returns an httptest handler that asserts the request is a
// signed, read-only GET and responds per the given mode.
func fakeSTSHandler(t *testing.T, mode string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		assertNoMutation(t, r.Method)
		q := r.URL.Query()
		if q.Get("Action") != "GetCallerIdentity" {
			t.Fatalf("expected GetCallerIdentity action, got %q", q.Get("Action"))
		}
		if q.Get("X-Amz-Signature") == "" {
			t.Fatal("expected an X-Amz-Signature query param")
		}
		if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
			t.Fatalf("unexpected algorithm %q", q.Get("X-Amz-Algorithm"))
		}
		if !strings.HasPrefix(q.Get("X-Amz-Credential"), "AKIA") {
			t.Fatalf("expected credential to start with the access key id, got %q", q.Get("X-Amz-Credential"))
		}
		switch mode {
		case "active":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/x</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`))
		case "invalid":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`))
		case "badsig":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`))
		default: // "error"
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func TestAWSVerifier_VerifyPair(t *testing.T) {
	cases := []struct {
		name   string
		mode   string
		expect string
	}{
		{"active", "active", statusActive},
		{"inactive_invalid_token", "invalid", statusInactive},
		{"inactive_bad_signature", "badsig", statusInactive},
		{"unknown_server_error", "error", statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(fakeSTSHandler(t, tc.mode))
			defer srv.Close()

			c := newTestClient()
			awsSTSBase = srv.URL
			defer func() { awsSTSBase = "https://sts.amazonaws.com" }()

			v := &awsVerifier{c: c}
			got, err := v.verifyPair(context.Background(),
				"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// TestAWSPairing_AttemptedWhenSecretPresent verifies the batch pre-pass pairs an
// AKIA id with a co-located 40-char secret and issues a signed STS call.
func TestAWSPairing_AttemptedWhenSecretPresent(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fakeSTSHandler(t, "active")(w, r)
	}))
	defer srv.Close()

	c := newTestClient()
	awsSTSBase = srv.URL
	defer func() { awsSTSBase = "https://sts.amazonaws.com" }()
	reg := defaultRegistry(c)

	in := []models.SecretModel{
		{SecretType: "AWS Access Key ID", SecretString: "AKIAIOSFODNN7EXAMPLE", FileLocation: "a.txt", LineNo: 10},
		{SecretType: "AWS Secret Key", SecretString: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", FileLocation: "a.txt", LineNo: 11},
	}
	out := verifyWithRegistry(context.Background(), in, reg)
	if out[0].VerificationStatus != statusActive {
		t.Fatalf("expected AKIA finding active, got %q", out[0].VerificationStatus)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("expected the STS endpoint to be contacted")
	}
}

// TestAWSPairing_AloneIsUnknown verifies an AKIA id with no candidate secret in
// the batch stays unknown and makes NO network call.
func TestAWSPairing_AloneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no network call expected for a lone AKIA id: %s", r.URL)
	}))
	defer srv.Close()

	c := newTestClient()
	awsSTSBase = srv.URL
	defer func() { awsSTSBase = "https://sts.amazonaws.com" }()
	reg := defaultRegistry(c)

	in := []models.SecretModel{
		{SecretType: "AWS Access Key ID", SecretString: "AKIAIOSFODNN7EXAMPLE", FileLocation: "a.txt", LineNo: 10},
	}
	out := verifyWithRegistry(context.Background(), in, reg)
	if out[0].VerificationStatus != statusUnknown {
		t.Fatalf("expected unknown for lone AKIA id, got %q", out[0].VerificationStatus)
	}
}

// TestAWSPairing_WrongSecretInactive verifies that when the only candidate
// secret is rejected by STS the AKIA finding is inactive, not a false active.
func TestAWSPairing_WrongSecretInactive(t *testing.T) {
	srv := httptest.NewServer(fakeSTSHandler(t, "invalid"))
	defer srv.Close()

	c := newTestClient()
	awsSTSBase = srv.URL
	defer func() { awsSTSBase = "https://sts.amazonaws.com" }()
	reg := defaultRegistry(c)

	in := []models.SecretModel{
		{SecretType: "AWS Access Key ID", SecretString: "AKIAIOSFODNN7EXAMPLE", FileLocation: "a.txt", LineNo: 10},
		{SecretType: "AWS Secret Key", SecretString: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", FileLocation: "a.txt", LineNo: 11},
	}
	out := verifyWithRegistry(context.Background(), in, reg)
	if out[0].VerificationStatus != statusInactive {
		t.Fatalf("expected inactive for rejected pair, got %q", out[0].VerificationStatus)
	}
}

// TestSigV4_SigningKeyDeterministic checks the signing-key derivation against
// the published AWS SigV4 test vector so signing correctness is verified offline
// without any network. See AWS docs "Examples of how to derive a signing key".
func TestSigV4_SigningKeyDeterministic(t *testing.T) {
	// AWS-published vector: secret "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	// date 20150830, region us-east-1, service iam.
	key := sigv4SigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
	got := hexEncode(key)
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got != want {
		t.Fatalf("signing key mismatch:\n got %s\nwant %s", got, want)
	}

	// Determinism: same inputs yield the same request signature twice.
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	r1, err := buildSTSGetCallerIdentityRequest(context.Background(), "https://sts.amazonaws.com", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now)
	if err != nil {
		t.Fatalf("build request 1: %v", err)
	}
	r2, err := buildSTSGetCallerIdentityRequest(context.Background(), "https://sts.amazonaws.com", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now)
	if err != nil {
		t.Fatalf("build request 2: %v", err)
	}
	s1 := r1.URL.Query().Get("X-Amz-Signature")
	s2 := r2.URL.Query().Get("X-Amz-Signature")
	if s1 == "" || s1 != s2 {
		t.Fatalf("signature not deterministic: %q vs %q", s1, s2)
	}
}

// --- New single-request providers -------------------------------------------

func TestGitlabVerifier(t *testing.T) {
	cases := []struct {
		code   int
		expect string
	}{
		{http.StatusOK, statusActive},
		{http.StatusUnauthorized, statusInactive},
		{http.StatusInternalServerError, statusUnknown},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertNoMutation(t, r.Method)
			if r.URL.Path != "/api/v4/user" {
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
			w.WriteHeader(tc.code)
		}))
		c := newTestClient()
		gitlabAPIBase = srv.URL
		v := &gitlabVerifier{c: c}
		got, err := v.Verify(context.Background(), "glpat-tok")
		srv.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.expect {
			t.Fatalf("code %d: expected %q, got %q", tc.code, tc.expect, got)
		}
	}
}

func TestSendgridVerifier(t *testing.T) {
	cases := []struct {
		code   int
		expect string
	}{
		{http.StatusOK, statusActive},
		{http.StatusUnauthorized, statusInactive},
		{http.StatusBadGateway, statusUnknown},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertNoMutation(t, r.Method)
			if r.URL.Path != "/v3/scopes" {
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
			w.WriteHeader(tc.code)
		}))
		c := newTestClient()
		sendgridAPIBase = srv.URL
		v := &sendgridVerifier{c: c}
		got, err := v.Verify(context.Background(), "SG.tok")
		srv.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.expect {
			t.Fatalf("code %d: expected %q, got %q", tc.code, tc.expect, got)
		}
	}
}

func TestNpmVerifier(t *testing.T) {
	cases := []struct {
		code   int
		expect string
	}{
		{http.StatusOK, statusActive},
		{http.StatusUnauthorized, statusInactive},
		{http.StatusTooManyRequests, statusUnknown},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertNoMutation(t, r.Method)
			if r.URL.Path != "/-/whoami" {
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
			w.WriteHeader(tc.code)
		}))
		c := newTestClient()
		npmAPIBase = srv.URL
		v := &npmVerifier{c: c}
		got, err := v.Verify(context.Background(), "npm_tok")
		srv.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.expect {
			t.Fatalf("code %d: expected %q, got %q", tc.code, tc.expect, got)
		}
	}
}

func TestCloudflareVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		expect string
	}{
		{"active", http.StatusOK, `{"success":true,"result":{"status":"active"}}`, statusActive},
		{"inactive_body", http.StatusOK, `{"success":false,"result":{"status":"disabled"}}`, statusInactive},
		{"inactive_401", http.StatusUnauthorized, ``, statusInactive},
		{"unknown_5xx", http.StatusInternalServerError, ``, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Path != "/client/v4/user/tokens/verify" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := newTestClient()
			cloudflareAPIBase = srv.URL
			v := &cloudflareVerifier{c: c}
			got, err := v.Verify(context.Background(), "cf-tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

func TestMailgunVerifier(t *testing.T) {
	cases := []struct {
		code   int
		expect string
	}{
		{http.StatusOK, statusActive},
		{http.StatusUnauthorized, statusInactive},
		{http.StatusBadGateway, statusUnknown},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertNoMutation(t, r.Method)
			if r.URL.Path != "/v3/domains" {
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
			user, _, ok := r.BasicAuth()
			if !ok || user != "api" {
				t.Fatalf("expected basic-auth user 'api', got %q ok=%v", user, ok)
			}
			w.WriteHeader(tc.code)
		}))
		c := newTestClient()
		mailgunAPIBase = srv.URL
		v := &mailgunVerifier{c: c}
		got, err := v.Verify(context.Background(), "key-abc")
		srv.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.expect {
			t.Fatalf("code %d: expected %q, got %q", tc.code, tc.expect, got)
		}
	}
}

func TestDigitalOceanVerifier(t *testing.T) {
	cases := []struct {
		code   int
		expect string
	}{
		{http.StatusOK, statusActive},
		{http.StatusUnauthorized, statusInactive},
		{http.StatusInternalServerError, statusUnknown},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertNoMutation(t, r.Method)
			if r.URL.Path != "/v2/account" {
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
			w.WriteHeader(tc.code)
		}))
		c := newTestClient()
		digitalOceanAPIBase = srv.URL
		v := &digitalOceanVerifier{c: c}
		got, err := v.Verify(context.Background(), "dop_v1_tok")
		srv.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.expect {
			t.Fatalf("code %d: expected %q, got %q", tc.code, tc.expect, got)
		}
	}
}

func TestNewProviders_RegisteredInLookup(t *testing.T) {
	c := newTestClient()
	reg := defaultRegistry(c)
	for _, st := range []string{
		"GitLab Feed Token", "SendGrid API Key", "NPM Access Token",
		"Cloudflare API Token", "Mailgun API Key", "DigitalOcean PAT",
	} {
		if lookup(reg, st) == nil {
			t.Fatalf("expected a verifier for %q", st)
		}
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
	pgl, psg, pnpm, pcf, pmg, pdo, paws := gitlabAPIBase, sendgridAPIBase, npmAPIBase, cloudflareAPIBase, mailgunAPIBase, digitalOceanAPIBase, awsSTSBase
	// P3a additions
	poai, pant, pdd, ppd := openaiAPIBase, anthropicAPIBase, datadogAPIBase, pagerdutyAPIBase
	pdisc, ptg, pmb, psq := discordAPIBase, telegramAPIBase, mapboxAPIBase, squareAPIBase
	phk, pfg, pno, pair := herokuAPIBase, figmaAPIBase, notionAPIBase, airtableAPIBase

	githubAPIBase, slackAPIBase, stripeAPIBase, googleAPIBase, twilioAPIBase = base, base, base, base, base
	gitlabAPIBase, sendgridAPIBase, npmAPIBase, cloudflareAPIBase, mailgunAPIBase, digitalOceanAPIBase, awsSTSBase = base, base, base, base, base, base, base
	openaiAPIBase, anthropicAPIBase, datadogAPIBase, pagerdutyAPIBase = base, base, base, base
	discordAPIBase, telegramAPIBase, mapboxAPIBase, squareAPIBase = base, base, base, base
	herokuAPIBase, figmaAPIBase, notionAPIBase, airtableAPIBase = base, base, base, base

	return func() {
		githubAPIBase, slackAPIBase, stripeAPIBase, googleAPIBase, twilioAPIBase = pg, ps, pst, pgo, pt
		gitlabAPIBase, sendgridAPIBase, npmAPIBase, cloudflareAPIBase, mailgunAPIBase, digitalOceanAPIBase, awsSTSBase = pgl, psg, pnpm, pcf, pmg, pdo, paws
		openaiAPIBase, anthropicAPIBase, datadogAPIBase, pagerdutyAPIBase = poai, pant, pdd, ppd
		discordAPIBase, telegramAPIBase, mapboxAPIBase, squareAPIBase = pdisc, ptg, pmb, psq
		herokuAPIBase, figmaAPIBase, notionAPIBase, airtableAPIBase = phk, pfg, pno, pair
	}
}

// --- P3a: OpenAI -------------------------------------------------------------

func TestOpenAIVerifier(t *testing.T) {
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
				if r.URL.Path != "/v1/models" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
					t.Fatalf("unexpected auth header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			openaiAPIBase = srv.URL
			v := &openaiVerifier{c: c}
			got, err := v.Verify(context.Background(), "sk-test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Anthropic ----------------------------------------------------------

func TestAnthropicVerifier(t *testing.T) {
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
				if r.URL.Path != "/v1/models" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("x-api-key"); got != "sk-ant-key" {
					t.Fatalf("unexpected x-api-key header %q", got)
				}
				if got := r.Header.Get("anthropic-version"); got == "" {
					t.Fatalf("missing anthropic-version header")
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			anthropicAPIBase = srv.URL
			v := &anthropicVerifier{c: c}
			got, err := v.Verify(context.Background(), "sk-ant-key")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Datadog ------------------------------------------------------------

func TestDatadogVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		expect string
	}{
		{"active", http.StatusOK, statusActive},
		{"inactive", http.StatusForbidden, statusInactive},
		{"unknown", http.StatusInternalServerError, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Path != "/api/v1/validate" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("DD-API-KEY"); got != "dd-key-abc" {
					t.Fatalf("unexpected DD-API-KEY header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			datadogAPIBase = srv.URL
			v := &datadogVerifier{c: c}
			got, err := v.Verify(context.Background(), "dd-key-abc")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: PagerDuty ----------------------------------------------------------

func TestPagerDutyVerifier(t *testing.T) {
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
				if r.URL.Path != "/users" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Token token=pd-token" {
					t.Fatalf("unexpected auth header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			pagerdutyAPIBase = srv.URL
			v := &pagerdutyVerifier{c: c}
			got, err := v.Verify(context.Background(), "pd-token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Discord Bot --------------------------------------------------------

func TestDiscordBotVerifier(t *testing.T) {
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
				if r.URL.Path != "/api/v10/users/@me" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bot bot-tok" {
					t.Fatalf("unexpected auth header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			discordAPIBase = srv.URL
			v := &discordBotVerifier{c: c}
			got, err := v.Verify(context.Background(), "bot-tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Telegram Bot -------------------------------------------------------

func TestTelegramBotVerifier(t *testing.T) {
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
			const tok = "123456789:AABBccdd_eeFF"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				want := "/bot123456789:AABBccdd_eeFF/getMe"
				if r.URL.Path != want {
					t.Fatalf("unexpected path %q (want %q)", r.URL.Path, want)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			telegramAPIBase = srv.URL
			v := &telegramBotVerifier{c: c}
			got, err := v.Verify(context.Background(), tok)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Mapbox -------------------------------------------------------------

func TestMapboxVerifier(t *testing.T) {
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
				if r.URL.Path != "/tokens/v2" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.URL.Query().Get("access_token"); got != "pk.mapbox_token" {
					t.Fatalf("unexpected access_token query param %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			mapboxAPIBase = srv.URL
			v := &mapboxVerifier{c: c}
			got, err := v.Verify(context.Background(), "pk.mapbox_token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Square -------------------------------------------------------------

func TestSquareVerifier(t *testing.T) {
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
				if r.URL.Path != "/v2/locations" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer sq-token" {
					t.Fatalf("unexpected auth header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			squareAPIBase = srv.URL
			v := &squareVerifier{c: c}
			got, err := v.Verify(context.Background(), "sq-token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Heroku -------------------------------------------------------------

func TestHerokuVerifier(t *testing.T) {
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
				if r.URL.Path != "/account" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer hrku-token" {
					t.Fatalf("unexpected auth header %q", got)
				}
				if got := r.Header.Get("Accept"); !strings.Contains(got, "vnd.heroku+json") {
					t.Fatalf("missing Heroku Accept header, got %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			herokuAPIBase = srv.URL
			v := &herokuVerifier{c: c}
			got, err := v.Verify(context.Background(), "hrku-token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Figma --------------------------------------------------------------

func TestFigmaVerifier(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		expect string
	}{
		{"active", http.StatusOK, statusActive},
		{"inactive", http.StatusForbidden, statusInactive},
		{"unknown", http.StatusInternalServerError, statusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertNoMutation(t, r.Method)
				if r.URL.Path != "/v1/me" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("X-Figma-Token"); got != "figma-pat" {
					t.Fatalf("unexpected X-Figma-Token header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			figmaAPIBase = srv.URL
			v := &figmaVerifier{c: c}
			got, err := v.Verify(context.Background(), "figma-pat")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Notion -------------------------------------------------------------

func TestNotionVerifier(t *testing.T) {
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
				if r.URL.Path != "/v1/users/me" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer secret_ntn" {
					t.Fatalf("unexpected auth header %q", got)
				}
				if got := r.Header.Get("Notion-Version"); got == "" {
					t.Fatalf("missing Notion-Version header")
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			notionAPIBase = srv.URL
			v := &notionVerifier{c: c}
			got, err := v.Verify(context.Background(), "secret_ntn")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// --- P3a: Airtable -----------------------------------------------------------

func TestAirtableVerifier(t *testing.T) {
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
				if r.URL.Path != "/v0/meta/whoami" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer patABC.xyz" {
					t.Fatalf("unexpected auth header %q", got)
				}
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()
			c := newTestClient()
			airtableAPIBase = srv.URL
			v := &airtableVerifier{c: c}
			got, err := v.Verify(context.Background(), "patABC.xyz")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}

// TestP3aProviders_RegisteredInLookup verifies all P3a providers are in the
// registry and fire on their documented secret type substrings.
func TestP3aProviders_RegisteredInLookup(t *testing.T) {
	c := newTestClient()
	reg := defaultRegistry(c)
	for _, st := range []string{
		"OpenAI API Key",
		"Anthropic API Key",
		"Datadog API Key Assigned",
		"PagerDuty API Token",
		"Discord Bot Token",
		"Telegram Bot Token",
		"Mapbox Access Token",
		"Square Access Token",
		"Heroku API Key",
		"Figma Personal Access Token",
		"Notion Integration Token",
		"Airtable PAT",
	} {
		if lookup(reg, st) == nil {
			t.Fatalf("expected a verifier for %q", st)
		}
	}
}

// TestP3aProviders_DisabledGateNoNetworkCall verifies that with
// MORF_ENABLE_VERIFICATION unset, none of the P3a providers make a network
// call (the global default-off gate holds for all new providers).
func TestP3aProviders_DisabledGateNoNetworkCall(t *testing.T) {
	t.Setenv(envVerificationEnabled, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("network call made while verification disabled: %s %s", r.Method, r.URL)
	}))
	defer srv.Close()
	restore := swapEndpoints(srv.URL)
	defer restore()

	in := []models.SecretModel{
		{SecretType: "OpenAI API Key", SecretString: "sk-test"},
		{SecretType: "Anthropic API Key", SecretString: "sk-ant-key"},
		{SecretType: "Datadog API Key Assigned", SecretString: "dd-key"},
		{SecretType: "PagerDuty API Token", SecretString: "pd-tok"},
		{SecretType: "Discord Bot Token", SecretString: "bot-tok"},
		{SecretType: "Telegram Bot Token", SecretString: "123:AA"},
		{SecretType: "Mapbox Access Token", SecretString: "pk.map"},
		{SecretType: "Square Access Token", SecretString: "sq0atp-tok"},
		{SecretType: "Heroku API Key", SecretString: "hrku-tok"},
		{SecretType: "Figma Personal Access Token", SecretString: "figpat"},
		{SecretType: "Notion Integration Token", SecretString: "secret_ntn"},
		{SecretType: "Airtable PAT", SecretString: "patABC.xyz"},
	}
	out := VerifySecrets(context.Background(), in)
	for _, s := range out {
		if s.VerificationStatus != statusUnchecked {
			t.Fatalf("expected unchecked for %q, got %q", s.SecretType, s.VerificationStatus)
		}
	}
}

// TestAWSPairing_ASIATemporaryKeyIsUnknown locks in the fix that temporary
// (ASIA) credentials are NOT paired/signed: they additionally require a session
// token a static scan cannot recover, so signing with just id+secret would 403
// and be misread as "inactive". They must stay "unknown" and make no STS call,
// even when a plausible 40-char secret is co-located.
func TestAWSPairing_ASIATemporaryKeyIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no STS call expected for an ASIA temporary key: %s", r.URL)
	}))
	defer srv.Close()

	c := newTestClient()
	awsSTSBase = srv.URL
	defer func() { awsSTSBase = "https://sts.amazonaws.com" }()
	reg := defaultRegistry(c)

	in := []models.SecretModel{
		{SecretType: "AWS Session Token Prefix", SecretString: "ASIAIOSFODNN7EXAMPLE", FileLocation: "a.txt", LineNo: 10},
		{SecretType: "AWS Secret", SecretString: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY0", FileLocation: "a.txt", LineNo: 11},
	}
	out := verifyWithRegistry(context.Background(), in, reg)
	if out[0].VerificationStatus != statusUnknown {
		t.Fatalf("expected unknown for ASIA temporary key, got %q", out[0].VerificationStatus)
	}
}
