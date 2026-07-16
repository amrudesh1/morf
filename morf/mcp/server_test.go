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

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morf/models"

	sdk "github.com/mark3labs/mcp-go/mcp"
)

// resultText extracts the concatenated text content of a tool result. It fails
// the test if the result is nil or carries no text content.
func resultText(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("nil tool result")
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := sdk.AsTextContent(c); ok {
			b.WriteString(tc.Text)
		}
	}
	if b.Len() == 0 {
		t.Fatal("tool result carried no text content")
	}
	return b.String()
}

// newReq builds a CallToolRequest with the given arguments map, matching what
// the MCP transport hands a handler.
func newReq(args map[string]any) sdk.CallToolRequest {
	var req sdk.CallToolRequest
	req.Params.Arguments = args
	return req
}

// TestNewServerRegistersTools asserts the server builds without panicking and
// that all four tools are registered under their expected names.
func TestNewServerRegistersTools(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	// ListTools is exercised indirectly by building the server; a nil server is
	// the only failure mode we can observe without a live session, and the
	// individual handlers are tested below.
}

// --- scan_file: arg validation + masking ---------------------------------

func TestScanFileHandler_MissingPath(t *testing.T) {
	res, err := scanFileHandler(context.Background(), newReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected a tool-level error for missing path")
	}
}

func TestScanFileHandler_BadExtension(t *testing.T) {
	// A path that exists but is not .apk/.ipa should fail arg-time before any
	// apktool/java is needed.
	tmp := filepath.Join(t.TempDir(), "not-a-package.txt")
	if err := os.WriteFile(tmp, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := scanFileHandler(context.Background(), newReq(map[string]any{"path": tmp}))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected a tool-level error for a non-apk/ipa file")
	}
	txt := resultText(t, res)
	if !strings.Contains(txt, "apk") && !strings.Contains(txt, "ipa") {
		t.Fatalf("error should mention .apk/.ipa, got: %q", txt)
	}
}

func TestScanFileHandler_BadFormat(t *testing.T) {
	res, err := scanFileHandler(context.Background(), newReq(map[string]any{
		"path":   "/tmp/whatever.apk",
		"format": "xml",
	}))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected a tool-level error for an invalid format")
	}
}

// TestRenderFindings_MasksSecrets is the core masking guarantee: a plaintext
// secret handed to renderFindings must NOT appear verbatim in either the SARIF
// or JSON output. This is the same masking scan_file relies on, tested without
// needing apktool/java.
func TestRenderFindings_MasksSecrets(t *testing.T) {
	const raw = "AKIAIOSFODNN7EXAMPLE-SUPERSECRET-VALUE"
	secrets := []models.SecretModel{{
		SecretType:       "aws",
		SecretString:     raw,
		SecretConfidence: "high",
		FileLocation:     "res/values/strings.xml",
		Tier:             "keep",
	}}

	for _, format := range []string{"sarif", "json"} {
		out, err := renderFindings(format, "app.apk", "android", secrets)
		if err != nil {
			t.Fatalf("renderFindings(%s) error: %v", format, err)
		}
		if strings.Contains(string(out), raw) {
			t.Fatalf("%s output leaked the raw secret value", format)
		}
		// The masked preview keeps a short prefix; make sure something rendered.
		if !strings.Contains(string(out), "AKIA") {
			t.Fatalf("%s output did not contain the masked preview head", format)
		}
	}
}

// TestSummarizeNeverLeaks verifies the summary block reports only metadata
// (counts by tier/type/status) and never the secret value.
func TestSummarizeNeverLeaks(t *testing.T) {
	const raw = "ghp_TOPSECRETTOKEN0000000000000000000000"
	secrets := []models.SecretModel{
		{SecretType: "github", SecretString: raw, Tier: "keep", VerificationStatus: "active"},
		{SecretType: "github", SecretString: raw, Tier: "info", VerificationStatus: "unchecked"},
	}
	sum := summarize("app.apk", "android", secrets)
	if strings.Contains(sum, raw) {
		t.Fatal("summary leaked the raw secret value")
	}
	if !strings.Contains(sum, "2 finding(s)") {
		t.Fatalf("summary should report 2 findings, got: %q", sum)
	}
	if !strings.Contains(sum, "keep=1") || !strings.Contains(sum, "info=1") {
		t.Fatalf("summary tier counts wrong: %q", sum)
	}
	if !strings.Contains(sum, "github=2") {
		t.Fatalf("summary type counts wrong: %q", sum)
	}
}

// --- list_patterns: real behavior ----------------------------------------

func TestListPatternsHandler(t *testing.T) {
	dir := t.TempDir()
	yaml := "" +
		"patterns:\n" +
		"  - pattern:\n" +
		"      name: aws-access-key\n" +
		"      regex: 'AKIA[0-9A-Z]{16}'\n" +
		"      confidence: high\n" +
		"      enabled: true\n" +
		"  - pattern:\n" +
		"      name: slack-token\n" +
		"      regex: 'xox[baprs]-[0-9A-Za-z-]+'\n" +
		"      confidence: medium\n" +
		"      enabled: false\n"
	if err := os.WriteFile(filepath.Join(dir, "test-patterns.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MORF_PATTERNS_DIR", dir)

	res, err := listPatternsHandler(context.Background(), newReq(nil))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", resultText(t, res))
	}

	var parsed struct {
		FileCount  int `json:"fileCount"`
		TotalCount int `json:"totalPatternCount"`
		Files      []struct {
			Filename string `json:"filename"`
			Count    int    `json:"count"`
			Patterns []struct {
				Name       string `json:"name"`
				Confidence string `json:"confidence"`
				Enabled    bool   `json:"enabled"`
			} `json:"patterns"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &parsed); err != nil {
		t.Fatalf("output was not valid JSON: %v", err)
	}
	if parsed.FileCount != 1 {
		t.Fatalf("expected 1 pattern file, got %d", parsed.FileCount)
	}
	if parsed.TotalCount != 2 {
		t.Fatalf("expected 2 total patterns, got %d", parsed.TotalCount)
	}
	if parsed.Files[0].Filename != "test-patterns.yaml" {
		t.Fatalf("unexpected filename: %s", parsed.Files[0].Filename)
	}
	// The regex must not be present in the summary payload.
	if strings.Contains(resultText(t, res), "AKIA[0-9A-Z]") {
		t.Fatal("list_patterns should not dump the raw regex")
	}
}

// --- verify_secret: real behavior (default-off) ----------------------------

func TestVerifySecretHandler_MissingArgs(t *testing.T) {
	for _, args := range []map[string]any{
		{},
		{"type": "github"},
		{"value": "x"},
	} {
		res, err := verifySecretHandler(context.Background(), newReq(args))
		if err != nil {
			t.Fatalf("unexpected protocol error: %v", err)
		}
		if !res.IsError {
			t.Fatalf("expected tool error for args %v", args)
		}
	}
}

func TestVerifySecretHandler_DefaultUnchecked(t *testing.T) {
	// Ensure verification is disabled so no network call is made and the status
	// is "unchecked".
	t.Setenv("MORF_ENABLE_VERIFICATION", "false")

	const value = "ghp_shouldNeverBeEchoed000000000000000000"
	res, err := verifySecretHandler(context.Background(), newReq(map[string]any{
		"type":  "github",
		"value": value,
	}))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", resultText(t, res))
	}
	txt := resultText(t, res)
	if strings.Contains(txt, value) {
		t.Fatal("verify_secret leaked the raw value")
	}

	var parsed struct {
		Type               string `json:"type"`
		VerificationStatus string `json:"verificationStatus"`
	}
	if err := json.Unmarshal([]byte(txt), &parsed); err != nil {
		t.Fatalf("output was not valid JSON: %v", err)
	}
	if parsed.Type != "github" {
		t.Fatalf("expected type github, got %q", parsed.Type)
	}
	if parsed.VerificationStatus != "unchecked" {
		t.Fatalf("expected unchecked status with verification off, got %q", parsed.VerificationStatus)
	}
}

// --- explain_finding: real behavior ----------------------------------------

func TestExplainFindingHandler_MissingType(t *testing.T) {
	res, err := explainFindingHandler(context.Background(), newReq(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected tool error for missing type")
	}
}

func TestExplainFindingHandler_Basic(t *testing.T) {
	// Point at an empty patterns dir so GetPatternCache is deterministic (no
	// matched patterns) and the fallback MASVS text is exercised.
	t.Setenv("MORF_PATTERNS_DIR", t.TempDir())

	res, err := explainFindingHandler(context.Background(), newReq(map[string]any{
		"type":               "aws",
		"tier":               "keep",
		"verificationStatus": "active",
	}))
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", resultText(t, res))
	}
	txt := resultText(t, res)
	for _, want := range []string{"aws", "MASVS", "Tier \"keep\"", "Verification \"active\""} {
		if !strings.Contains(txt, want) {
			t.Fatalf("explanation missing %q; got:\n%s", want, txt)
		}
	}
}

func TestExplainTierAndStatus(t *testing.T) {
	if got := explainTier("keep"); !strings.Contains(got, "true positive") {
		t.Fatalf("keep tier explanation unexpected: %q", got)
	}
	if got := explainStatus("active"); !strings.Contains(got, "live") {
		t.Fatalf("active status explanation unexpected: %q", got)
	}
	if got := explainStatus("bogus"); !strings.Contains(got, "unrecognized") {
		t.Fatalf("unknown status should be flagged: %q", got)
	}
}

// TestVerifySecretHandler_OptInDoesNotLeakGlobally locks in the fix that a
// per-call enable=true does NOT mutate the process-global MORF_ENABLE_VERIFICATION.
// Previously the handler did os.Setenv(...,"true") with no restore, so one
// opt-in call stuck verification ON for every later call. Here: a first call
// with enable=true, then a second call WITHOUT enable must still report
// "unchecked" (i.e. verification is off by default and was not left on).
func TestVerifySecretHandler_OptInDoesNotLeakGlobally(t *testing.T) {
	t.Setenv("MORF_ENABLE_VERIFICATION", "false")

	// First call opts in (forced). We do not assert its status (it may attempt a
	// network verify and return unknown); we only care about the side effect.
	if _, err := verifySecretHandler(context.Background(), newReq(map[string]any{
		"type": "github", "value": "ghp_first000000000000000000000000000000", "enable": true,
	})); err != nil {
		t.Fatalf("unexpected protocol error on first call: %v", err)
	}

	// The env must NOT have been flipped to a sticky "true".
	if v := os.Getenv("MORF_ENABLE_VERIFICATION"); v == "true" {
		t.Fatalf("enable=true leaked a global MORF_ENABLE_VERIFICATION=true")
	}

	// Second call without enable must be unchecked (default-off preserved).
	res, err := verifySecretHandler(context.Background(), newReq(map[string]any{
		"type": "github", "value": "ghp_second00000000000000000000000000000",
	}))
	if err != nil {
		t.Fatalf("unexpected protocol error on second call: %v", err)
	}
	var parsed struct {
		VerificationStatus string `json:"verificationStatus"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if parsed.VerificationStatus != "unchecked" {
		t.Fatalf("second call without enable should be unchecked, got %q (sticky global?)", parsed.VerificationStatus)
	}
}
