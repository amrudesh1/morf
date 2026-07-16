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

package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// testKeyHex is a fixed 32-byte AES-256 key (64 hex chars) used to exercise the
// encrypted paths deterministically.
const testKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// TestProtectAtRestRoundTrip verifies that with a key configured, ProtectAtRest
// produces recoverable "enc:v1:" ciphertext and Reveal returns the exact
// plaintext.
func TestProtectAtRestRoundTrip(t *testing.T) {
	t.Setenv(encryptionKeyEnv, testKeyHex)

	for _, value := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"",
		"short",
		"a value with spaces and symbols !@#$%^&*()_+日本語",
	} {
		stored := ProtectAtRest(value)
		if !strings.HasPrefix(stored, encPrefix) {
			t.Fatalf("ProtectAtRest(%q) = %q, want %q prefix", value, stored, encPrefix)
		}
		if strings.Contains(stored, value) && value != "" {
			t.Fatalf("ProtectAtRest(%q) leaked plaintext: %q", value, stored)
		}
		got, ok := Reveal(stored)
		if !ok {
			t.Fatalf("Reveal(%q) ok = false, want true", stored)
		}
		if got != value {
			t.Fatalf("round-trip mismatch: got %q, want %q", got, value)
		}
	}
}

// TestProtectAtRestNonDeterministic confirms GCM uses a fresh nonce per call so
// two encryptions of the same value differ (yet both decrypt correctly).
func TestProtectAtRestNonDeterministic(t *testing.T) {
	t.Setenv(encryptionKeyEnv, testKeyHex)

	value := "AKIAIOSFODNN7EXAMPLE"
	a := ProtectAtRest(value)
	b := ProtectAtRest(value)
	if a == b {
		t.Fatalf("expected distinct ciphertext per call (nonce reuse?), both = %q", a)
	}
	if got, ok := Reveal(a); !ok || got != value {
		t.Fatalf("Reveal(a) = (%q,%v), want (%q,true)", got, ok, value)
	}
	if got, ok := Reveal(b); !ok || got != value {
		t.Fatalf("Reveal(b) = (%q,%v), want (%q,true)", got, ok, value)
	}
}

// TestProtectAtRestAcceptsBase64Key verifies the key may be supplied base64- as
// well as hex-encoded.
func TestProtectAtRestAcceptsBase64Key(t *testing.T) {
	raw, err := hex.DecodeString(testKeyHex)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	t.Setenv(encryptionKeyEnv, base64.StdEncoding.EncodeToString(raw))

	value := "AIzaSyExampleKeyValue1234567890abcdefghij"
	stored := ProtectAtRest(value)
	if !strings.HasPrefix(stored, encPrefix) {
		t.Fatalf("base64 key not accepted; ProtectAtRest = %q", stored)
	}
	if got, ok := Reveal(stored); !ok || got != value {
		t.Fatalf("Reveal = (%q,%v), want (%q,true)", got, ok, value)
	}
}

// TestProtectAtRestNoKeyMasks verifies the default (keyless) configuration
// NEVER returns plaintext: it returns a masked preview that is not "enc:v1:"
// and is not revealable.
func TestProtectAtRestNoKeyMasks(t *testing.T) {
	t.Setenv(encryptionKeyEnv, "")

	value := "AKIAIOSFODNN7EXAMPLE"
	stored := ProtectAtRest(value)

	if stored == value {
		t.Fatalf("ProtectAtRest with no key returned plaintext: %q", stored)
	}
	if strings.HasPrefix(stored, encPrefix) {
		t.Fatalf("ProtectAtRest with no key returned ciphertext: %q", stored)
	}
	if !strings.Contains(stored, "…") {
		t.Fatalf("masked preview missing ellipsis: %q", stored)
	}
	// The full raw value must not be recoverable from the masked preview.
	if strings.Contains(stored, value) {
		t.Fatalf("masked preview leaked full plaintext: %q", stored)
	}
	if got, ok := Reveal(stored); ok || got != stored {
		t.Fatalf("Reveal of masked preview = (%q,%v), want (%q,false)", got, ok, stored)
	}
}

// TestProtectAtRestInvalidKeyMasks verifies a malformed key (wrong length) is
// rejected and degrades to masking rather than falling through to plaintext.
func TestProtectAtRestInvalidKeyMasks(t *testing.T) {
	t.Setenv(encryptionKeyEnv, "deadbeef") // 4 bytes, not 32

	value := "AKIAIOSFODNN7EXAMPLE"
	stored := ProtectAtRest(value)
	if stored == value {
		t.Fatalf("invalid key fell through to plaintext: %q", stored)
	}
	if strings.HasPrefix(stored, encPrefix) {
		t.Fatalf("invalid key produced ciphertext: %q", stored)
	}
	if !strings.Contains(stored, "…") {
		t.Fatalf("expected masked preview for invalid key, got %q", stored)
	}
}

// TestRevealPassthrough verifies Reveal returns (input,false) for non-encrypted
// input regardless of key presence.
func TestRevealPassthrough(t *testing.T) {
	// With a key present, a masked / plain string still isn't revealable.
	t.Setenv(encryptionKeyEnv, testKeyHex)
	for _, s := range []string{"", "plain value", "AKIA…LE", "not-enc:something"} {
		if got, ok := Reveal(s); ok || got != s {
			t.Fatalf("Reveal(%q) = (%q,%v), want (%q,false)", s, got, ok, s)
		}
	}
}

// TestRevealWithoutKey verifies encrypted values are NOT revealable when no key
// is configured (fails closed to the stored ciphertext).
func TestRevealWithoutKey(t *testing.T) {
	t.Setenv(encryptionKeyEnv, testKeyHex)
	stored := ProtectAtRest("AKIAIOSFODNN7EXAMPLE")

	t.Setenv(encryptionKeyEnv, "")
	if got, ok := Reveal(stored); ok || got != stored {
		t.Fatalf("Reveal without key = (%q,%v), want (%q,false)", got, ok, stored)
	}
}

// TestRevealCorruptCiphertext verifies tampered ciphertext fails GCM auth and
// is not revealed.
func TestRevealCorruptCiphertext(t *testing.T) {
	t.Setenv(encryptionKeyEnv, testKeyHex)
	stored := ProtectAtRest("AKIAIOSFODNN7EXAMPLE")

	// Flip a character in the base64 body.
	body := stored[len(encPrefix):]
	corruptChar := byte('A')
	if body[0] == 'A' {
		corruptChar = 'B'
	}
	corrupt := encPrefix + string(corruptChar) + body[1:]

	if got, ok := Reveal(corrupt); ok {
		t.Fatalf("Reveal of corrupt ciphertext succeeded: got %q", got)
	}
}

// TestFingerprintDeterministic verifies equal values yield equal digests and
// that the digest is a 64-char (32-byte) lowercase hex SHA-256 output.
func TestFingerprintDeterministic(t *testing.T) {
	t.Setenv(fingerprintSaltEnv, "unit-test-salt")

	value := "AKIAIOSFODNN7EXAMPLE"
	a := Fingerprint(value)
	b := Fingerprint(value)
	if a != b {
		t.Fatalf("Fingerprint not deterministic: %q != %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("Fingerprint length = %d, want 64 hex chars", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("Fingerprint is not valid hex: %v", err)
	}
	if a == value {
		t.Fatalf("Fingerprint returned the raw value")
	}
}

// TestFingerprintDistinctValues verifies different values produce different
// digests (identity separation for de-dup / build-diff).
func TestFingerprintDistinctValues(t *testing.T) {
	t.Setenv(fingerprintSaltEnv, "unit-test-salt")

	seen := map[string]string{}
	values := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AKIAJUSTANOTHERONE12",
		"AIzaSyExampleKeyValue1234567890abcdefghij",
		"",
		"a",
		"b",
	}
	for _, v := range values {
		fp := Fingerprint(v)
		if prev, ok := seen[fp]; ok {
			t.Fatalf("fingerprint collision: %q and %q both hash to %q", prev, v, fp)
		}
		seen[fp] = v
	}
}

// TestFingerprintSaltMatters verifies the salt participates: the same value
// under two different salts yields different digests, and the compiled-in
// fallback is used when the env var is unset.
func TestFingerprintSaltMatters(t *testing.T) {
	value := "AKIAIOSFODNN7EXAMPLE"

	t.Setenv(fingerprintSaltEnv, "salt-one")
	one := Fingerprint(value)
	t.Setenv(fingerprintSaltEnv, "salt-two")
	two := Fingerprint(value)
	if one == two {
		t.Fatalf("fingerprint identical under different salts: %q", one)
	}

	// Unset => compiled-in fallback (stable, non-empty).
	t.Setenv(fingerprintSaltEnv, "")
	fallback := Fingerprint(value)
	if fallback == "" || len(fallback) != 64 {
		t.Fatalf("fallback-salt fingerprint invalid: %q", fallback)
	}
}
