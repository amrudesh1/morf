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
			_, summary, code, err := evaluateAndRender(opts, tc.secrets)
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
	_, _, code, err := evaluateAndRender(opts, nil)
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
	out, _, _, err := evaluateAndRender(opts, secrets)
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
	out, _, _, err := evaluateAndRender(opts, secrets)
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
	out, _, _, err := evaluateAndRender(opts, secrets)
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
