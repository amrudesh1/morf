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
