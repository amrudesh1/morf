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

// Package crypto provides AT-REST protection for detected secret values so the
// raw plaintext of a discovered credential never has to be persisted to the
// database.
//
// It exposes three primitives:
//
//   - Fingerprint(value): a deterministic keyed HMAC-SHA256 hex digest of the
//     value. Equal values always produce equal digests and distinct values
//     produce (with overwhelming probability) distinct digests, so the digest
//     is a stable per-value IDENTITY usable for de-duplication and build-diff
//     comparison WITHOUT revealing the value itself. The digest is salted with
//     MORF_FINGERPRINT_SALT (a compiled-in fallback is used when unset) so the
//     mapping from value to digest is not trivially reversible via a public
//     rainbow table.
//
//   - ProtectAtRest(value): the value transformed into a form that is safe to
//     store in the secret_string column. When MORF_SECRET_ENCRYPTION_KEY is set
//     (a 32-byte AES-256 key given as hex or base64) the value is AES-256-GCM
//     encrypted and returned as "enc:v1:" + base64(nonce||ciphertext), so the
//     value is recoverable by an operator holding the key. When NO key is set,
//     a MASKED preview (first four … last two characters) is returned instead.
//     Either way the raw plaintext is NEVER returned, so the default (keyless)
//     configuration persists no plaintext.
//
//   - Reveal(stored): the inverse of ProtectAtRest for encrypted values. Given
//     a stored string, it decrypts and returns (plaintext, true) only when the
//     value carries the "enc:v1:" prefix AND a valid key is configured;
//     otherwise it returns the stored value unchanged with false (masked
//     previews are not reversible).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

const (
	// fingerprintSaltEnv is the environment variable holding the HMAC salt used
	// by Fingerprint.
	fingerprintSaltEnv = "MORF_FINGERPRINT_SALT"

	// encryptionKeyEnv is the environment variable holding the 32-byte
	// AES-256-GCM key (hex- or base64-encoded) used by ProtectAtRest/Reveal.
	encryptionKeyEnv = "MORF_SECRET_ENCRYPTION_KEY"

	// defaultFingerprintSalt is the compiled-in fallback salt used when
	// MORF_FINGERPRINT_SALT is unset. It only needs to be stable and
	// non-empty; operators SHOULD override it with a deployment-specific value
	// so digests are not portable across independent MORF installations.
	defaultFingerprintSalt = "morf/at-rest-secret-fingerprint/v1"

	// encPrefix tags AES-256-GCM ciphertext produced by ProtectAtRest so Reveal
	// can distinguish an encrypted value from a masked preview.
	encPrefix = "enc:v1:"

	// aesKeySize is the required raw key length for AES-256.
	aesKeySize = 32
)

// Fingerprint returns a deterministic keyed HMAC-SHA256 hex digest of value.
//
// The digest is stable per value (equal inputs => equal outputs) and does not
// reveal the value, which makes it a safe identity for de-duplication and
// build-diff comparison in place of the raw plaintext. The salt comes from
// MORF_FINGERPRINT_SALT, falling back to a compiled-in constant when unset.
func Fingerprint(value string) string {
	mac := hmac.New(sha256.New, []byte(fingerprintSalt()))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// ProtectAtRest transforms value into a form safe to persist in place of the
// raw secret. It NEVER returns plaintext.
//
// When a valid MORF_SECRET_ENCRYPTION_KEY is configured, value is AES-256-GCM
// encrypted and returned as "enc:v1:" + base64(nonce||ciphertext), recoverable
// via Reveal by a holder of the key. When no (or an invalid) key is set, a
// masked preview (first four … last two characters) is returned so a human can
// eyeball-correlate a finding without the value leaking.
func ProtectAtRest(value string) string {
	key, ok := encryptionKey()
	if !ok {
		return maskSecret(value)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		// A misconfigured key must not fall through to plaintext; degrade to
		// the masked preview instead.
		return maskSecret(value)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return maskSecret(value)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return maskSecret(value)
	}
	// Seal appends the ciphertext to nonce, yielding nonce||ciphertext.
	sealed := gcm.Seal(nonce, nonce, []byte(value), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(sealed)
}

// Reveal is the inverse of ProtectAtRest for encrypted values. It returns
// (plaintext, true) only when stored carries the "enc:v1:" prefix AND a valid
// key is configured and decryption succeeds. In every other case (masked
// preview, missing/invalid key, corrupt ciphertext) it returns stored
// unchanged with false. Masked previews are intentionally not reversible.
func Reveal(stored string) (string, bool) {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored, false
	}
	key, ok := encryptionKey()
	if !ok {
		return stored, false
	}
	sealed, err := base64.StdEncoding.DecodeString(stored[len(encPrefix):])
	if err != nil {
		return stored, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return stored, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return stored, false
	}
	if len(sealed) < gcm.NonceSize() {
		return stored, false
	}
	nonce := sealed[:gcm.NonceSize()]
	ciphertext := sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return stored, false
	}
	return string(plaintext), true
}

// fingerprintSalt resolves the HMAC salt, preferring MORF_FINGERPRINT_SALT and
// falling back to the compiled-in constant when it is unset or empty.
func fingerprintSalt() string {
	if s := os.Getenv(fingerprintSaltEnv); s != "" {
		return s
	}
	return defaultFingerprintSalt
}

// encryptionKey resolves the AES-256 key from MORF_SECRET_ENCRYPTION_KEY,
// accepting either hex or base64 encoding. It returns (key, true) only when the
// decoded key is exactly 32 bytes; otherwise (nil, false) so callers fall back
// to masking.
func encryptionKey() ([]byte, bool) {
	raw := os.Getenv(encryptionKeyEnv)
	if raw == "" {
		return nil, false
	}
	raw = strings.TrimSpace(raw)

	// Try hex first (a 32-byte key is 64 hex chars); then base64 (std and raw).
	if key, err := hex.DecodeString(raw); err == nil && len(key) == aesKeySize {
		return key, true
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == aesKeySize {
		return key, true
	}
	if key, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(key) == aesKeySize {
		return key, true
	}
	return nil, false
}

// maskSecret redacts a secret value to a short preview, preserving at most the
// first four and last two characters. It mirrors report.maskSecret so masked
// previews are consistent across the SARIF export, the /results masker, and the
// at-rest column.
func maskSecret(value string) string {
	runes := []rune(value)
	n := len(runes)
	if n == 0 {
		return "…"
	}
	first := 4
	if first > n {
		first = n
	}
	last := 2
	// Never let head and tail overlap; if the value is short, drop the tail.
	if first+last > n {
		last = 0
	}
	head := string(runes[:first])
	tail := ""
	if last > 0 {
		tail = string(runes[n-last:])
	}
	return head + "…" + tail
}
