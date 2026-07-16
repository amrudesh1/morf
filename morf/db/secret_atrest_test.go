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

package db

import (
	"strings"
	"testing"

	"morf/crypto"
	"morf/models"
)

// atRestTestKeyHex is a fixed 32-byte AES-256 key (64 hex chars) for the
// encrypted-path assertions.
const atRestTestKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// TestBuildSecretFinding_EncryptsWithKey verifies that, with an encryption key
// configured, a written finding stores AES-256-GCM ciphertext (NOT plaintext)
// in secret_string plus a deterministic fingerprint identity, while the
// non-secret metadata is copied through unchanged.
func TestBuildSecretFinding_EncryptsWithKey(t *testing.T) {
	t.Setenv("MORF_SECRET_ENCRYPTION_KEY", atRestTestKeyHex)
	t.Setenv("MORF_FINGERPRINT_SALT", "db-unit-test-salt")

	const raw = "AKIAIOSFODNN7EXAMPLE"
	sm := models.SecretModel{
		Type:             "secret",
		LineNo:           42,
		FileLocation:     "assets/config.json",
		SecretType:       "AWS Access Key ID",
		SecretString:     raw,
		SecretConfidence: "high",
	}

	finding := buildSecretFinding(7, sm)

	// Metadata copied through.
	if finding.SecretID != 7 || finding.LineNo != 42 ||
		finding.FileLocation != "assets/config.json" ||
		finding.SecretType != "AWS Access Key ID" ||
		finding.SecretConfidence != "high" {
		t.Fatalf("metadata not preserved: %+v", finding)
	}

	// secret_string must be ciphertext, never plaintext.
	if finding.SecretString == raw {
		t.Fatalf("secret_string stored plaintext: %q", finding.SecretString)
	}
	if !strings.HasPrefix(finding.SecretString, "enc:v1:") {
		t.Fatalf("secret_string not encrypted: %q", finding.SecretString)
	}
	if strings.Contains(finding.SecretString, raw) {
		t.Fatalf("secret_string leaked plaintext: %q", finding.SecretString)
	}

	// Fingerprint present and equal to the deterministic identity of the value.
	if finding.Fingerprint == "" {
		t.Fatalf("fingerprint not populated")
	}
	if finding.Fingerprint != crypto.Fingerprint(raw) {
		t.Fatalf("fingerprint mismatch: got %q, want %q", finding.Fingerprint, crypto.Fingerprint(raw))
	}

	// The stored value must be recoverable by a key holder.
	if got, ok := crypto.Reveal(finding.SecretString); !ok || got != raw {
		t.Fatalf("Reveal(stored) = (%q,%v), want (%q,true)", got, ok, raw)
	}
}

// TestBuildSecretFinding_MasksWithoutKey verifies the default (keyless)
// configuration persists NO plaintext: secret_string is a masked preview
// (not ciphertext, not plaintext) and a fingerprint is still written.
func TestBuildSecretFinding_MasksWithoutKey(t *testing.T) {
	t.Setenv("MORF_SECRET_ENCRYPTION_KEY", "")
	t.Setenv("MORF_FINGERPRINT_SALT", "db-unit-test-salt")

	const raw = "AKIAIOSFODNN7EXAMPLE"
	sm := models.SecretModel{
		SecretType:   "AWS Access Key ID",
		SecretString: raw,
		FileLocation: "f",
		LineNo:       1,
	}

	finding := buildSecretFinding(1, sm)

	if finding.SecretString == raw {
		t.Fatalf("keyless write stored plaintext: %q", finding.SecretString)
	}
	if strings.HasPrefix(finding.SecretString, "enc:v1:") {
		t.Fatalf("keyless write produced ciphertext: %q", finding.SecretString)
	}
	if strings.Contains(finding.SecretString, raw) {
		t.Fatalf("masked preview leaked full plaintext: %q", finding.SecretString)
	}
	if !strings.Contains(finding.SecretString, "…") {
		t.Fatalf("expected masked preview, got %q", finding.SecretString)
	}
	if finding.Fingerprint != crypto.Fingerprint(raw) {
		t.Fatalf("fingerprint mismatch: got %q, want %q", finding.Fingerprint, crypto.Fingerprint(raw))
	}
}

// TestBuildSecretFinding_FingerprintStableForDedup verifies two findings with
// the same secret value share a fingerprint (stable identity for build-diff /
// de-dup) even though their encrypted secret_string differ per GCM nonce.
func TestBuildSecretFinding_FingerprintStableForDedup(t *testing.T) {
	t.Setenv("MORF_SECRET_ENCRYPTION_KEY", atRestTestKeyHex)
	t.Setenv("MORF_FINGERPRINT_SALT", "db-unit-test-salt")

	const raw = "AKIAIOSFODNN7EXAMPLE"
	a := buildSecretFinding(1, models.SecretModel{SecretString: raw, SecretType: "t", FileLocation: "f", LineNo: 1})
	b := buildSecretFinding(2, models.SecretModel{SecretString: raw, SecretType: "t", FileLocation: "f", LineNo: 9})

	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("same value produced different fingerprints: %q != %q", a.Fingerprint, b.Fingerprint)
	}
	if a.SecretString == b.SecretString {
		t.Fatalf("expected distinct ciphertext per finding (nonce reuse?): %q", a.SecretString)
	}

	// A different value must yield a different fingerprint.
	c := buildSecretFinding(3, models.SecretModel{SecretString: "AKIAJUSTANOTHERONE12", SecretType: "t", FileLocation: "f", LineNo: 1})
	if c.Fingerprint == a.Fingerprint {
		t.Fatalf("distinct values collided on fingerprint: %q", c.Fingerprint)
	}
}
