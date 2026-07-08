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

package detect

import (
	"strings"
	"testing"

	"morf/models"
)

// jwtX5CHeader is a base64url-encoded JWT header {"alg":"RS256","x5c":["MIID..."]}
// (public certificate chain), so the token is a public cert artifact, not a
// leaked bearer secret. A trivial payload/signature is appended to shape it.
const jwtX5CHeader = "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlELi4uIl19"

// jwtPlainHeader is a base64url-encoded plain JWT header {"alg":"HS256","typ":"JWT"}
// with no x5c/x5u/jku — a real signed token this precision stage must keep.
const jwtPlainHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

// findTier looks up the single finding of the given secret type in the returned
// slice, reporting whether it survived (was not dropped).
func findByType(out []models.SecretModel, secretType string) (models.SecretModel, bool) {
	for _, s := range out {
		if s.SecretType == secretType {
			return s, true
		}
	}
	return models.SecretModel{}, false
}

// TestApplyPrecision_HeaderOnlyPrivateKeyDropped: a "Private Key" finding whose
// value is only a PEM header (no >=40-char base64 body) is a clear FP -> dropped.
func TestApplyPrecision_HeaderOnlyPrivateKeyDropped(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "Private Key", SecretString: "-----BEGIN RSA PRIVATE KEY-----", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("header-only private key should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_RealPrivateKeyKept: a PEM block with a real base64 body
// (>=40 chars) is a genuine key and is kept.
func TestApplyPrecision_RealPrivateKeyKept(t *testing.T) {
	body := strings.Repeat("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj", 3) // >=40 base64 chars
	val := "-----BEGIN RSA PRIVATE KEY----- " + body + " -----END RSA PRIVATE KEY-----"
	in := []models.SecretModel{
		{SecretType: "Private Key", SecretString: val, SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	s, ok := findByType(out, "Private Key")
	if !ok {
		t.Fatalf("real private key should be kept; got %+v", out)
	}
	if s.Tier != "keep" {
		t.Fatalf("real private key tier: want keep, got %q", s.Tier)
	}
}

// TestApplyPrecision_X5CJWTDropped: a JWT whose header carries an x5c public cert
// chain is not a leaked secret and is dropped.
func TestApplyPrecision_X5CJWTDropped(t *testing.T) {
	jwt := jwtX5CHeader + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2ln"
	in := []models.SecretModel{
		{SecretType: "JSON Web Token (JWT)", SecretString: jwt, SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("x5c JWT should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_PlainJWTKept: a JWT with a plain header (no x5c/x5u/jku) is
// kept as a real secret.
func TestApplyPrecision_PlainJWTKept(t *testing.T) {
	jwt := jwtPlainHeader + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpEIn0.dBjftJeZ4CVP"
	in := []models.SecretModel{
		{SecretType: "JSON Web Token (JWT)", SecretString: jwt, SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	s, ok := findByType(out, "JSON Web Token (JWT)")
	if !ok {
		t.Fatalf("plain JWT should be kept; got %+v", out)
	}
	if s.Tier != "keep" {
		t.Fatalf("plain JWT tier: want keep, got %q", s.Tier)
	}
}

// TestApplyPrecision_NaturalLanguageDropped: a credential-type finding whose
// value is prose (whitespace + >=2 alpha word tokens of len>=4) is dropped.
func TestApplyPrecision_NaturalLanguageDropped(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "Generic API Key", SecretString: "please replace this value", SecretConfidence: "medium"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("natural-language value should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_KeychainKeyNameDropped: the literal entitlement key-name
// "keychain-access-groups" is not a value and is dropped.
func TestApplyPrecision_KeychainKeyNameDropped(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "iOS Keychain Access Group", SecretString: "keychain-access-groups", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("keychain-access-groups key-name should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_KeychainBenignDomainDropped: a keychain-group value that is
// actually a benign vendor domain (e.g. sentry.io) is dropped.
func TestApplyPrecision_KeychainBenignDomainDropped(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "iOS Keychain Access Group", SecretString: "o12345.ingest.sentry.io", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("benign-domain keychain value should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_KeychainGroupInfo: a well-formed keychain-access-group
// (<10-char TeamID>.<id>) is real config metadata -> info + low confidence.
func TestApplyPrecision_KeychainGroupInfo(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "iOS Keychain Access Group", SecretString: "ABCDE12345.com.acme.app", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	s, ok := findByType(out, "iOS Keychain Access Group")
	if !ok {
		t.Fatalf("valid keychain group should be kept as info; got %+v", out)
	}
	if s.Tier != "info" {
		t.Fatalf("keychain group tier: want info, got %q", s.Tier)
	}
	if s.SecretConfidence != "low" {
		t.Fatalf("keychain group confidence: want low, got %q", s.SecretConfidence)
	}
}

// TestApplyPrecision_AWSKeyKept: a real AWS AKIA access key is kept (Tier keep).
func TestApplyPrecision_AWSKeyKept(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "AWS Access Key ID", SecretString: "AKIAIOSFODNN7ABCDEF12", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	s, ok := findByType(out, "AWS Access Key ID")
	if !ok {
		t.Fatalf("AWS key should be kept; got %+v", out)
	}
	if s.Tier != "keep" {
		t.Fatalf("AWS key tier: want keep, got %q", s.Tier)
	}
	if s.Score <= 0 {
		t.Fatalf("AWS key score should be > 0, got %v", s.Score)
	}
}

// TestApplyPrecision_GoogleAIzaKept: a real Google AIza API key is kept.
func TestApplyPrecision_GoogleAIzaKept(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "Google API Key", SecretString: "AIzaSyD-abc123DEF456ghi789JKL012mno345PQ", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	s, ok := findByType(out, "Google API Key")
	if !ok {
		t.Fatalf("Google API key should be kept; got %+v", out)
	}
	if s.Tier != "keep" {
		t.Fatalf("Google API key tier: want keep, got %q", s.Tier)
	}
}

// TestApplyPrecision_GCPOAuthClientInfo: a GCP OAuth client ID is real but public
// by design -> downgraded to info + low confidence, not dropped.
func TestApplyPrecision_GCPOAuthClientInfo(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "Google Cloud Platform OAuth", SecretString: "123456789012-abcdefghijklmnop.apps.googleusercontent.com", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	s, ok := findByType(out, "Google Cloud Platform OAuth")
	if !ok {
		t.Fatalf("GCP OAuth client ID should be kept as info; got %+v", out)
	}
	if s.Tier != "info" {
		t.Fatalf("GCP OAuth tier: want info, got %q", s.Tier)
	}
	if s.SecretConfidence != "low" {
		t.Fatalf("GCP OAuth confidence: want low, got %q", s.SecretConfidence)
	}
}

// TestApplyPrecision_PlaceholderDropped: a placeholder banlist value is dropped.
func TestApplyPrecision_PlaceholderDropped(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "Generic API Key", SecretString: "your_key.abc123XYZ789def456", SecretConfidence: "medium"},
		{SecretType: "Generic API Key", SecretString: "example-api-token-value", SecretConfidence: "medium"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("placeholder values should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_BcryptDropped: a bcrypt hash value is dropped.
func TestApplyPrecision_BcryptDropped(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "Generic Secret", SecretString: "$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUV0123456789", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	if len(out) != 0 {
		t.Fatalf("bcrypt hash should be dropped; got %d findings: %+v", len(out), out)
	}
}

// TestApplyPrecision_PreservesOrderAndCount: a mixed batch retains the surviving
// findings in input order.
func TestApplyPrecision_PreservesOrderAndCount(t *testing.T) {
	in := []models.SecretModel{
		{SecretType: "AWS Access Key ID", SecretString: "AKIAIOSFODNN7ABCDEF12", SecretConfidence: "high"},
		{SecretType: "Generic API Key", SecretString: "your_key", SecretConfidence: "low"}, // dropped
		{SecretType: "Google API Key", SecretString: "AIzaSyD-abc123DEF456ghi789JKL012mno345PQ", SecretConfidence: "high"},
	}
	out := ApplyPrecision(in)
	if len(out) != 2 {
		t.Fatalf("want 2 survivors, got %d: %+v", len(out), out)
	}
	if out[0].SecretType != "AWS Access Key ID" || out[1].SecretType != "Google API Key" {
		t.Fatalf("survivor order not preserved: %+v", out)
	}
}
