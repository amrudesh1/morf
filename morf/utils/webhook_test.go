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

package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// hexSigPattern matches a well-formed signature header value: the "sha256="
// prefix followed by exactly 64 lowercase hex characters (a SHA-256 digest).
var hexSigPattern = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)

// manualSignature independently recomputes the signature the way an external
// receiver would, so the test does not rely on the code under test to describe
// its own scheme.
func manualSignature(t *testing.T, secret, timestamp string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGenerateWebhookSignatureFormatAndDeterminism(t *testing.T) {
	secret := "s3cr3t"
	timestamp := "1700000000"
	body := []byte(`{"job_id":"abc","status":"completed"}`)

	sig := generateWebhookSignature(secret, timestamp, body)

	if !hexSigPattern.MatchString(sig) {
		t.Fatalf("signature %q does not match sha256=<64 hex> format", sig)
	}

	// Deterministic: same inputs -> same output.
	if again := generateWebhookSignature(secret, timestamp, body); again != sig {
		t.Fatalf("signature not deterministic: %q != %q", sig, again)
	}

	// Reproducible by an independent HMAC computation.
	if want := manualSignature(t, secret, timestamp, body); sig != want {
		t.Fatalf("signature %q does not match independent HMAC %q", sig, want)
	}
}

func TestGenerateWebhookSignatureBindsTimestampAndBody(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{"job_id":"abc"}`)

	base := generateWebhookSignature(secret, "1700000000", body)

	// Changing the timestamp must change the signature (replay protection).
	if other := generateWebhookSignature(secret, "1700000001", body); other == base {
		t.Fatal("signature did not change when timestamp changed")
	}
	// Changing the body must change the signature.
	if other := generateWebhookSignature(secret, "1700000000", []byte(`{"job_id":"xyz"}`)); other == base {
		t.Fatal("signature did not change when body changed")
	}
	// Changing the secret must change the signature.
	if other := generateWebhookSignature("other", "1700000000", body); other == base {
		t.Fatal("signature did not change when secret changed")
	}
}

func TestVerifyWebhookSignatureAcceptsValid(t *testing.T) {
	secret := "top-secret-key"
	timestamp := "1700000123"
	body := []byte(`{"job_id":"job-1","status":"completed","schema_version":"1"}`)

	sig := generateWebhookSignature(secret, timestamp, body)

	if !VerifyWebhookSignature(body, sig, timestamp, secret) {
		t.Fatal("VerifyWebhookSignature rejected a valid signature")
	}

	// A receiver reproducing the signature independently must also verify.
	if !VerifyWebhookSignature(body, manualSignature(t, secret, timestamp, body), timestamp, secret) {
		t.Fatal("VerifyWebhookSignature rejected an independently-computed valid signature")
	}
}

func TestVerifyWebhookSignatureRejectsTampering(t *testing.T) {
	secret := "top-secret-key"
	timestamp := "1700000123"
	body := []byte(`{"job_id":"job-1","status":"completed"}`)
	sig := generateWebhookSignature(secret, timestamp, body)

	cases := []struct {
		name      string
		body      []byte
		sig       string
		timestamp string
		secret    string
	}{
		{"tampered body", []byte(`{"job_id":"job-1","status":"FAILED"}`), sig, timestamp, secret},
		{"tampered signature digest", body, flipLastHexRune(sig), timestamp, secret},
		{"tampered timestamp (replay)", body, sig, "1700009999", secret},
		{"wrong secret", body, sig, timestamp, "not-the-secret"},
		{"empty secret", body, sig, timestamp, ""},
		{"empty signature header", body, "", timestamp, secret},
		{"missing prefix", body, strings.TrimPrefix(sig, "sha256="), timestamp, secret},
		{"garbage signature", body, "sha256=not-hex", timestamp, secret},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyWebhookSignature(tc.body, tc.sig, tc.timestamp, tc.secret) {
				t.Fatalf("VerifyWebhookSignature accepted invalid case %q", tc.name)
			}
		})
	}
}

// flipLastHexRune mutates the final hex character of a signature so the digest
// no longer matches while remaining the same length and valid hex.
func flipLastHexRune(sig string) string {
	if sig == "" {
		return sig
	}
	last := sig[len(sig)-1]
	var repl byte = '0'
	if last == '0' {
		repl = '1'
	}
	return sig[:len(sig)-1] + string(repl)
}

func TestResolveWebhookSecret(t *testing.T) {
	const env = "MORF_WEBHOOK_SECRET"

	t.Run("per-job secret wins over env", func(t *testing.T) {
		t.Setenv(env, "env-secret")
		if got := resolveWebhookSecret("job-secret"); got != "job-secret" {
			t.Fatalf("expected per-job secret to win, got %q", got)
		}
	})

	t.Run("falls back to env when per-job empty", func(t *testing.T) {
		t.Setenv(env, "env-secret")
		if got := resolveWebhookSecret(""); got != "env-secret" {
			t.Fatalf("expected env fallback, got %q", got)
		}
	})

	t.Run("empty when neither set", func(t *testing.T) {
		t.Setenv(env, "")
		if got := resolveWebhookSecret(""); got != "" {
			t.Fatalf("expected empty (unsigned delivery), got %q", got)
		}
	})
}

// TestSigningDecisionMatchesDelivery documents and locks in the header logic
// used by deliverWebhookWithContext: a delivery is signed exactly when
// resolveWebhookSecret returns a non-empty secret, and the emitted signature
// verifies. When the resolved secret is empty, no signature is produced (the
// delivery goes out with no signature headers, as before).
func TestSigningDecisionMatchesDelivery(t *testing.T) {
	const env = "MORF_WEBHOOK_SECRET"
	body := []byte(`{"job_id":"job-9","status":"completed","schema_version":"1"}`)
	timestamp := "1700000777"

	t.Run("signed when secret resolves", func(t *testing.T) {
		t.Setenv(env, "")
		secret := resolveWebhookSecret("per-job")
		if secret == "" {
			t.Fatal("expected a signing secret")
		}
		sig := generateWebhookSignature(secret, timestamp, body)
		if !VerifyWebhookSignature(body, sig, timestamp, secret) {
			t.Fatal("emitted signature did not verify")
		}
	})

	t.Run("signed via env fallback", func(t *testing.T) {
		t.Setenv(env, "env-secret")
		secret := resolveWebhookSecret("")
		if secret != "env-secret" {
			t.Fatalf("expected env-secret, got %q", secret)
		}
		sig := generateWebhookSignature(secret, timestamp, body)
		if !VerifyWebhookSignature(body, sig, timestamp, secret) {
			t.Fatal("emitted signature did not verify")
		}
	})

	t.Run("unsigned when no secret", func(t *testing.T) {
		t.Setenv(env, "")
		if secret := resolveWebhookSecret(""); secret != "" {
			t.Fatalf("expected no signing secret, got %q", secret)
		}
	})
}
