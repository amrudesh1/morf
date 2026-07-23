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

package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"morf/gate"
	"morf/models"
)

// finding builds a SecretModel row for the table tests. A real scan is not
// exercised here (it needs java/apktool); these tests drive the pure decision
// logic — exit codes and output formats — directly from a []SecretModel.
func finding(secretType, value, status, tier string) models.SecretModel {
	return models.SecretModel{
		Type:               "Secret",
		SecretType:         secretType,
		SecretString:       value,
		VerificationStatus: status,
		Tier:               tier,
		FileLocation:       "assets/config.json",
		LineNo:             7,
		MASVSID:            "MASVS-CRYPTO-1",
	}
}

func TestScanFailOnMapping(t *testing.T) {
	cases := map[string]struct {
		in      string
		want    gate.Policy
		wantErr bool
	}{
		"empty defaults to verified": {"", gate.FailOnNewVerified, false},
		"verified":                   {"verified", gate.FailOnNewVerified, false},
		"any":                        {"any", gate.FailOnNewAny, false},
		"keep":                       {"keep", gate.FailOnTierKeep, false},
		"none":                       {"none", gate.None, false},
		"case-insensitive":           {"ANY", gate.FailOnNewAny, false},
		"whitespace":                 {"  keep ", gate.FailOnTierKeep, false},
		"invalid":                    {"bogus", "", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := scanFailOn(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("scanFailOn(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEvaluateAndRenderExitCodes(t *testing.T) {
	active := finding("aws-key", "AKIAEXAMPLE1234567890", "active", "keep")
	unchecked := finding("generic", "someRandomToken1234", "unchecked", "keep")
	info := finding("maybe", "lowvalue000111", "unchecked", "info")

	cases := []struct {
		name     string
		failOn   string
		secrets  []models.SecretModel
		wantCode int
	}{
		{"no findings passes on verified", "verified", nil, exitOK},
		{"active finding fails on verified", "verified", []models.SecretModel{active}, exitPolicy},
		{"unchecked passes on verified", "verified", []models.SecretModel{unchecked}, exitOK},
		{"unchecked fails on any", "any", []models.SecretModel{unchecked}, exitPolicy},
		{"any with no findings passes", "any", nil, exitOK},
		{"keep-tier fails on keep", "keep", []models.SecretModel{unchecked}, exitPolicy},
		{"info-tier passes on keep", "keep", []models.SecretModel{info}, exitOK},
		{"none never fails despite active", "none", []models.SecretModel{active}, exitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := scanOptions{format: "sarif", failOn: tc.failOn, target: "app.apk", platform: "android"}
			_, summary, code, err := evaluateAndRender(opts, tc.secrets, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (summary: %s)", code, tc.wantCode, summary)
			}
		})
	}
}

func TestEvaluateAndRenderInvalidFailOn(t *testing.T) {
	opts := scanOptions{format: "sarif", failOn: "nope"}
	_, _, code, err := evaluateAndRender(opts, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid fail-on")
	}
	if code != exitOperational {
		t.Fatalf("exit code = %d, want %d (operational)", code, exitOperational)
	}
}

func TestEvaluateAndRenderSARIFFormat(t *testing.T) {
	secrets := []models.SecretModel{finding("aws-key", "AKIAEXAMPLE1234567890", "active", "keep")}
	opts := scanOptions{format: "sarif", failOn: "none", target: "app.apk", platform: "android"}
	out, _, _, err := evaluateAndRender(opts, secrets, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if _, ok := doc["$schema"]; !ok {
		t.Errorf("SARIF output missing $schema")
	}
	if v, _ := doc["version"].(string); v != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", v)
	}
	// The raw secret value must never appear in the report.
	if strings.Contains(string(out), "AKIAEXAMPLE1234567890") {
		t.Errorf("SARIF output leaked the plaintext secret")
	}
}

func TestEvaluateAndRenderJSONFormatMasksSecret(t *testing.T) {
	const raw = "AKIAEXAMPLE1234567890"
	secrets := []models.SecretModel{finding("aws-key", raw, "active", "keep")}
	opts := scanOptions{format: "json", failOn: "none", target: "app.apk", platform: "android"}
	out, _, _, err := evaluateAndRender(opts, secrets, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("JSON output is not valid JSON")
	}
	if strings.Contains(string(out), raw) {
		t.Errorf("JSON output leaked the plaintext secret: %s", out)
	}
	// A masked preview keeps the first four chars, so "AKIA…" should survive.
	if !strings.Contains(string(out), "AKIA") {
		t.Errorf("JSON output missing masked preview; got: %s", out)
	}
}

func TestEvaluateAndRenderSarifAliasOverridesFormat(t *testing.T) {
	secrets := []models.SecretModel{finding("aws-key", "AKIAEXAMPLE1234567890", "active", "keep")}
	// format says json but --sarif alias must win.
	opts := scanOptions{format: "json", sarif: true, failOn: "none", target: "app.apk", platform: "android"}
	out, _, _, err := evaluateAndRender(opts, secrets, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("expected SARIF (valid JSON): %v", err)
	}
	if _, ok := doc["$schema"]; !ok {
		t.Errorf("--sarif alias did not produce SARIF output")
	}
}

// TestEvaluateAndRenderSBOMFormat guards the CLI SBOM output path: with
// --format cyclonedx-sbom, evaluateAndRender emits a CycloneDX 1.6 document
// built from the provided components (not the secret findings), and always
// exits 0 (an inventory is not gated by --fail-on).
func TestEvaluateAndRenderSBOMFormat(t *testing.T) {
	sbom := []models.SBOMComponent{
		models.NewFrameworkComponent("Alamofire", "5.4.3", "org.cocoapods.Alamofire", "Payload/App.app/Frameworks/Alamofire.framework"),
		models.NewNativeLibComponent("libssl.so", []string{"arm64-v8a"}, "deadbeef"),
	}
	opts := scanOptions{format: "cyclonedx-sbom", target: "app.ipa", platform: "ios", failOn: "verified"}
	out, summary, code, err := evaluateAndRender(opts, nil, sbom, nil)
	if err != nil {
		t.Fatalf("evaluateAndRender: %v", err)
	}
	if code != exitOK {
		t.Errorf("SBOM exit code = %d, want %d (inventory is never gated)", code, exitOK)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if doc["specVersion"] != "1.6" || doc["bomFormat"] != "CycloneDX" {
		t.Errorf("not CycloneDX 1.6: bomFormat=%v specVersion=%v", doc["bomFormat"], doc["specVersion"])
	}
	comps, _ := doc["components"].([]any)
	if len(comps) != 2 {
		t.Errorf("components = %d, want 2 (Alamofire + libssl)", len(comps))
	}
	if !strings.Contains(summary, "2 component") {
		t.Errorf("summary missing component count: %q", summary)
	}
}

// TestEvaluateAndRenderJSONRevealShowsSecret is the counterpart to the masking
// test: with reveal set, --format json emits the plaintext value verbatim (the
// explicit opt-out for scanning your own authorized artifact). This guards the
// flag actually reaching renderFindings — a regression here silently re-masks.
func TestEvaluateAndRenderJSONRevealShowsSecret(t *testing.T) {
	const raw = "AKIAEXAMPLE1234567890"
	secrets := []models.SecretModel{finding("aws-key", raw, "active", "keep")}
	opts := scanOptions{format: "json", reveal: true, failOn: "none", target: "app.apk", platform: "android"}
	out, _, _, err := evaluateAndRender(opts, secrets, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("JSON output is not valid JSON")
	}
	if !strings.Contains(string(out), raw) {
		t.Errorf("--reveal-secrets did not emit the plaintext value; got: %s", out)
	}
}

// TestEvaluateAndRenderSARIFRevealStillMasks proves reveal is scoped to JSON:
// SARIF is built for upload to code scanning and must never carry plaintext,
// so a reveal request on the SARIF path is ignored (value stays masked).
func TestEvaluateAndRenderSARIFRevealStillMasks(t *testing.T) {
	const raw = "AKIAEXAMPLE1234567890"
	secrets := []models.SecretModel{finding("aws-key", raw, "active", "keep")}
	opts := scanOptions{format: "sarif", reveal: true, failOn: "none", target: "app.apk", platform: "android"}
	out, _, _, err := evaluateAndRender(opts, secrets, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), raw) {
		t.Errorf("SARIF leaked plaintext even though reveal must not apply to SARIF: %s", out)
	}
}

// TestEvaluateAndRenderPlatformFindingsInJSON verifies that platformFindings are
// included under "data.platformFindings" in the JSON output envelope, that they
// do not affect the exit code, and that the summary includes the count.
func TestEvaluateAndRenderPlatformFindingsInJSON(t *testing.T) {
	pfList := []models.PlatformFinding{
		{
			RuleID:   "exported-activity",
			Title:    "Exported activity",
			Severity: models.SeverityHigh,
			MASVSID:  "MASVS-PLATFORM-1",
			Category: "platform",
			Location: "AndroidManifest.xml",
			Evidence: "android:exported=true",
			Tier:     "keep",
		},
	}
	opts := scanOptions{format: "json", failOn: "none", target: "app.apk", platform: "android"}
	out, summary, code, err := evaluateAndRender(opts, nil, nil, pfList)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != exitOK {
		t.Errorf("platform findings must not change exit code (no secrets); got %d", code)
	}
	if !json.Valid(out) {
		t.Fatalf("JSON output is not valid JSON")
	}

	var env map[string]any
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data envelope")
	}
	pfs, ok := data["platformFindings"].([]any)
	if !ok {
		t.Fatalf("data.platformFindings not an array; got: %T %v", data["platformFindings"], data["platformFindings"])
	}
	if len(pfs) != 1 {
		t.Errorf("platformFindings count = %d, want 1", len(pfs))
	}
	if !strings.Contains(summary, "1 platform finding") {
		t.Errorf("summary missing platform finding count: %q", summary)
	}
}

// TestEvaluateAndRenderPlatformFindingsInSARIF verifies that platformFindings
// appear as SARIF results when the format is sarif, and that the exit code is
// still driven solely by secrets (platform findings do not gate).
func TestEvaluateAndRenderPlatformFindingsInSARIF(t *testing.T) {
	pfList := []models.PlatformFinding{
		{
			RuleID:   "exported-service",
			Title:    "Exported service",
			Severity: models.SeverityMedium,
			Category: "platform",
			Location: "AndroidManifest.xml",
			Evidence: "service exported=true",
		},
	}
	opts := scanOptions{format: "sarif", failOn: "any", target: "app.apk", platform: "android"}
	out, _, code, err := evaluateAndRender(opts, nil, nil, pfList)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No secrets, fail-on=any: must pass (platform findings are not gated).
	if code != exitOK {
		t.Errorf("exit code = %d, want 0 (platform findings do not gate)", code)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 1 {
		t.Errorf("SARIF results count = %d, want 1 (platform finding)", len(results))
	}
}
