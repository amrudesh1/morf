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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morf/crypto"
	"morf/gate"
	"morf/models"
)

func TestLoadBaselineOrEmpty(t *testing.T) {
	// Empty path -> fresh empty baseline.
	b, err := loadBaselineOrEmpty("")
	if err != nil {
		t.Fatalf("empty path: unexpected error %v", err)
	}
	if len(b.Fingerprints) != 0 {
		t.Fatalf("empty path should yield empty baseline")
	}

	// Missing file -> fresh empty baseline (first run), no error.
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	b, err = loadBaselineOrEmpty(missing)
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if len(b.Fingerprints) != 0 {
		t.Fatalf("missing file should yield empty baseline")
	}

	// Malformed file -> error surfaced.
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaselineOrEmpty(bad); err == nil {
		t.Fatal("malformed baseline should error")
	}
}

func TestEvaluateGateExitCodes(t *testing.T) {
	active := finding("aws-key", "AKIAEXAMPLE1234567890", "active", "keep")
	unchecked := finding("generic", "someRandomToken1234", "unchecked", "keep")

	// Baseline that already knows the active finding's fingerprint.
	knownBase := gate.NewBaseline()
	knownBase.Fingerprints[crypto.Fingerprint(active.SecretString)] = struct{}{}

	cases := []struct {
		name     string
		failOn   string
		secrets  []models.SecretModel
		base     *gate.Baseline
		wantCode int
	}{
		{"new active fails on verified", "verified", []models.SecretModel{active}, gate.NewBaseline(), exitPolicy},
		{"baselined active passes", "verified", []models.SecretModel{active}, knownBase, exitOK},
		{"nil baseline treated as empty -> new active fails", "verified", []models.SecretModel{active}, nil, exitPolicy},
		{"new unchecked passes on verified", "verified", []models.SecretModel{unchecked}, gate.NewBaseline(), exitOK},
		{"new unchecked fails on any", "any", []models.SecretModel{unchecked}, gate.NewBaseline(), exitPolicy},
		{"none never fails", "none", []models.SecretModel{active}, gate.NewBaseline(), exitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := gateOptions{failOn: tc.failOn}
			_, _, summary, code, err := evaluateGate(opts, tc.secrets, tc.base)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (summary: %s)", code, tc.wantCode, summary)
			}
		})
	}
}

func TestEvaluateGateInvalidFailOn(t *testing.T) {
	opts := gateOptions{failOn: "bogus"}
	_, _, _, code, err := evaluateGate(opts, nil, gate.NewBaseline())
	if err == nil {
		t.Fatal("expected error for invalid fail-on")
	}
	if code != exitOperational {
		t.Fatalf("exit code = %d, want %d", code, exitOperational)
	}
}

func TestEvaluateGateJSONOutputMasksSecret(t *testing.T) {
	const raw = "AKIAEXAMPLE1234567890"
	active := finding("aws-key", raw, "active", "keep")
	opts := gateOptions{failOn: "verified", jsonOut: true}

	res, out, _, code, err := evaluateGate(opts, []models.SecretModel{active}, gate.NewBaseline())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != exitPolicy {
		t.Fatalf("exit code = %d, want %d", code, exitPolicy)
	}
	if !res.Failed {
		t.Fatal("expected gate to fail")
	}
	if out == nil {
		t.Fatal("expected JSON output bytes")
	}
	if !json.Valid(out) {
		t.Fatalf("gate JSON output invalid: %s", out)
	}
	if strings.Contains(string(out), raw) {
		t.Errorf("gate JSON leaked plaintext secret: %s", out)
	}
	// Structure sanity: failed + newFindings present.
	var env struct {
		Failed      bool  `json:"failed"`
		NewFindings []any `json:"newFindings"`
		NewVerified []any `json:"newVerified"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("gate JSON shape: %v", err)
	}
	if !env.Failed || len(env.NewFindings) != 1 || len(env.NewVerified) != 1 {
		t.Errorf("unexpected gate JSON payload: %s", out)
	}
}

// TestGateBaselineRoundTripAcceptsPreviouslyNew verifies the accept-baseline
// workflow decision: a scan that fails against an empty baseline passes once its
// findings are snapshotted via BaselineFromScan and reloaded.
func TestGateBaselineRoundTripAcceptsPreviouslyNew(t *testing.T) {
	active := finding("aws-key", "AKIAEXAMPLE1234567890", "active", "keep")
	secrets := []models.SecretModel{active}

	// First run against empty baseline -> fails.
	_, _, _, code, err := evaluateGate(gateOptions{failOn: "verified"}, secrets, gate.NewBaseline())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != exitPolicy {
		t.Fatalf("first run: exit code = %d, want %d", code, exitPolicy)
	}

	// Snapshot + persist + reload (exercises Save/LoadBaseline path).
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := gate.BaselineFromScan(secrets).Save(path); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	reloaded, err := loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload baseline: %v", err)
	}

	// Second run against the reloaded baseline -> passes.
	_, _, _, code, err = evaluateGate(gateOptions{failOn: "verified"}, secrets, reloaded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != exitOK {
		t.Fatalf("second run: exit code = %d, want %d (baseline should accept)", code, exitOK)
	}

	// The persisted baseline must contain only opaque fingerprints, no plaintext.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), active.SecretString) {
		t.Errorf("baseline file leaked plaintext secret: %s", data)
	}
}

// TestSplitComma verifies that the comma/repeat flag parser deduplicates and
// trims as expected.
func TestSplitComma(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{""}, nil},
		{[]string{"  "}, nil},
		{[]string{"a"}, []string{"a"}},
		{[]string{"a,b,c"}, []string{"a", "b", "c"}},
		{[]string{"a", "b"}, []string{"a", "b"}},
		// dedup across items
		{[]string{"a,b", "b,c"}, []string{"a", "b", "c"}},
		// trim whitespace
		{[]string{" a , b "}, []string{"a", "b"}},
	}
	for _, tc := range cases {
		got := splitComma(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitComma(%v) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitComma(%v)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// TestRunGateAllowRequiresBaseline checks that runGateAllow errors when no
// --baseline path is given.
func TestRunGateAllowRequiresBaseline(t *testing.T) {
	err := runGateAllow(allowOptions{
		baseline: "",
		types:    []string{"aws-access-key"},
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when --baseline is empty")
	}
}

// TestRunGateAllowRequiresEntries checks that runGateAllow errors when neither
// fingerprints nor types are specified.
func TestRunGateAllowRequiresEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	err := runGateAllow(allowOptions{baseline: path}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when no --allow-fingerprint or --allow-type is given")
	}
}

// TestRunGateAllowTypeSupressesFinding verifies the primary end-to-end workflow:
// add a secret type to the allowlist, then re-evaluate: the finding is
// suppressed and exit code becomes 0.
func TestRunGateAllowTypeSupressesFinding(t *testing.T) {
	const secretType = "test-fixture-allowtype"
	const secretValue = "AKIAEXAMPLE_ALLOW_TYPE"

	f := finding(secretType, secretValue, "active", "keep")
	secrets := []models.SecretModel{f}

	// Step 1: without allowlist, the active finding fails.
	_, _, _, code, err := evaluateGate(gateOptions{failOn: "verified"}, secrets, gate.NewBaseline())
	if err != nil {
		t.Fatalf("step1 error: %v", err)
	}
	if code != exitPolicy {
		t.Fatalf("step1: expected exitPolicy(%d), got %d", exitPolicy, code)
	}

	// Step 2: create (empty) baseline, add the type via runGateAllow.
	path := filepath.Join(t.TempDir(), "baseline.json")
	var stderr bytes.Buffer
	if err := runGateAllow(allowOptions{
		baseline: path,
		types:    []string{secretType},
	}, &stderr); err != nil {
		t.Fatalf("runGateAllow: %v", err)
	}

	// Step 3: reload and re-evaluate — finding must now be suppressed.
	base, err := loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	_, _, _, code, err = evaluateGate(gateOptions{failOn: "verified"}, secrets, base)
	if err != nil {
		t.Fatalf("step3 error: %v", err)
	}
	if code != exitOK {
		t.Fatalf("step3: expected exitOK(%d) after allowlist, got %d", exitOK, code)
	}

	// Step 4: the persisted JSON must carry the type, no plaintext secret.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("baseline not valid JSON: %s", data)
	}
	if !strings.Contains(string(data), secretType) {
		t.Errorf("baseline does not contain allowed type %q: %s", secretType, data)
	}
	if strings.Contains(string(data), secretValue) {
		t.Errorf("baseline leaked plaintext secret value: %s", data)
	}
}

// TestRunGateAllowFingerprintSupressesFinding verifies the fingerprint-based
// allowlist: adding crypto.Fingerprint(secretValue) suppresses that finding.
func TestRunGateAllowFingerprintSupressesFinding(t *testing.T) {
	const secretValue = "AKIAEXAMPLE_ALLOW_FP"

	f := finding("aws-access-key", secretValue, "active", "keep")
	secrets := []models.SecretModel{f}

	fp := crypto.Fingerprint(secretValue)

	// Step 1: fails without allowlist.
	_, _, _, code, err := evaluateGate(gateOptions{failOn: "verified"}, secrets, gate.NewBaseline())
	if err != nil {
		t.Fatalf("step1 error: %v", err)
	}
	if code != exitPolicy {
		t.Fatalf("step1: expected exitPolicy(%d), got %d", exitPolicy, code)
	}

	// Step 2: allowlist the fingerprint.
	path := filepath.Join(t.TempDir(), "baseline.json")
	var stderr bytes.Buffer
	if err := runGateAllow(allowOptions{
		baseline:     path,
		fingerprints: []string{fp},
	}, &stderr); err != nil {
		t.Fatalf("runGateAllow: %v", err)
	}

	// Step 3: suppressed after allowlist.
	base, err := loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	_, _, _, code, err = evaluateGate(gateOptions{failOn: "verified"}, secrets, base)
	if err != nil {
		t.Fatalf("step3 error: %v", err)
	}
	if code != exitOK {
		t.Fatalf("step3: expected exitOK(%d) after allowlist, got %d", exitOK, code)
	}

	// Step 4: persisted JSON must carry the fingerprint digest, not the value.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("baseline not valid JSON: %s", data)
	}
	if !strings.Contains(string(data), fp) {
		t.Errorf("baseline does not contain allowed fingerprint %q: %s", fp, data)
	}
	if strings.Contains(string(data), secretValue) {
		t.Errorf("baseline leaked plaintext secret: %s", data)
	}
}

// TestRunGateAllowIdempotent verifies that running runGateAllow twice with the
// same entries does not duplicate them in the JSON.
func TestRunGateAllowIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	opts := allowOptions{
		baseline: path,
		types:    []string{"some-type"},
	}
	var stderr bytes.Buffer
	if err := runGateAllow(opts, &stderr); err != nil {
		t.Fatalf("first allow: %v", err)
	}
	if err := runGateAllow(opts, &stderr); err != nil {
		t.Fatalf("second allow: %v", err)
	}

	base, err := loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(base.AllowedTypes) != 1 {
		t.Errorf("expected 1 allowed type after idempotent adds, got %d: %v", len(base.AllowedTypes), base.AllowedTypes)
	}
}

// TestRunGateAllowOnBaselineFromScan verifies that a baseline produced by
// BaselineFromScan can subsequently receive allowlist entries, and that a
// finding NOT in the snapshot but matching the allowlist is still suppressed.
func TestRunGateAllowOnBaselineFromScan(t *testing.T) {
	// Two existing secrets — these will be snapshotted.
	s1 := finding("aws-access-key", "AKIASNAPSHOT1111", "active", "keep")
	s2 := finding("gcp-api-key", "gcptoken0000", "unchecked", "keep")

	// A third secret: NOT in the snapshot, but we'll allow its type.
	newSecret := finding("test-always-allowed", "some-ci-fixture-value", "active", "keep")

	// Snapshot the first two.
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := gate.BaselineFromScan([]models.SecretModel{s1, s2}).Save(path); err != nil {
		t.Fatalf("BaselineFromScan.Save: %v", err)
	}

	// Before allow: newSecret is a new verified finding -> fails.
	base, err := loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload pre-allow: %v", err)
	}
	allSecrets := []models.SecretModel{s1, s2, newSecret}
	_, _, _, code, err := evaluateGate(gateOptions{failOn: "verified"}, allSecrets, base)
	if err != nil {
		t.Fatalf("pre-allow eval: %v", err)
	}
	if code != exitPolicy {
		t.Fatalf("pre-allow: expected exitPolicy(%d), got %d", exitPolicy, code)
	}

	// Add the type allowlist entry.
	var stderr bytes.Buffer
	if err := runGateAllow(allowOptions{
		baseline: path,
		types:    []string{newSecret.SecretType},
	}, &stderr); err != nil {
		t.Fatalf("runGateAllow: %v", err)
	}

	// After allow: all three are suppressed.
	base, err = loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload post-allow: %v", err)
	}
	_, _, _, code, err = evaluateGate(gateOptions{failOn: "verified"}, allSecrets, base)
	if err != nil {
		t.Fatalf("post-allow eval: %v", err)
	}
	if code != exitOK {
		t.Fatalf("post-allow: expected exitOK(%d), got %d", exitOK, code)
	}

	// The on-disk baseline must not contain any plaintext secret value.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range allSecrets {
		if strings.Contains(string(data), s.SecretString) {
			t.Errorf("baseline leaked plaintext secret %q: %s", s.SecretString, data)
		}
	}
}

// TestRunGateAllowCommaValues verifies comma-separated values in a single flag
// are expanded correctly.
func TestRunGateAllowCommaValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	var stderr bytes.Buffer
	if err := runGateAllow(allowOptions{
		baseline: path,
		types:    []string{"type-a,type-b,type-c"},
	}, &stderr); err != nil {
		t.Fatalf("runGateAllow: %v", err)
	}

	base, err := loadBaselineOrEmpty(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, want := range []string{"type-a", "type-b", "type-c"} {
		if _, ok := base.AllowedTypes[want]; !ok {
			t.Errorf("expected AllowedTypes to contain %q; got %v", want, base.AllowedTypes)
		}
	}
}
