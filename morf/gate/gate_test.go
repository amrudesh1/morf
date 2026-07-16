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

package gate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"morf/crypto"
	"morf/models"
)

// sec is a small constructor for readable table rows.
func sec(secretType, value, status, tier string) models.SecretModel {
	return models.SecretModel{
		SecretType:         secretType,
		SecretString:       value,
		VerificationStatus: status,
		Tier:               tier,
		FileLocation:       "src/config.go",
		LineNo:             42,
	}
}

// fp is a shorthand for the fingerprint identity used by the gate.
func fp(value string) string { return crypto.Fingerprint(value) }

func TestEvaluate(t *testing.T) {
	// A baseline that has already accepted the "known-active" secret.
	baselineWithKnown := func() *Baseline {
		b := NewBaseline()
		b.Fingerprints[fp("known-active-value")] = struct{}{}
		return b
	}

	tests := []struct {
		name           string
		current        []models.SecretModel
		base           *Baseline
		policy         Policy
		wantFailed     bool
		wantNewCount   int
		wantVerifCount int
	}{
		{
			name:           "new verified fails (default policy)",
			current:        []models.SecretModel{sec("aws", "brand-new", statusActive, tierKeep)},
			base:           NewBaseline(),
			policy:         FailOnNewVerified,
			wantFailed:     true,
			wantNewCount:   1,
			wantVerifCount: 1,
		},
		{
			name:           "empty policy defaults to FailOnNewVerified",
			current:        []models.SecretModel{sec("aws", "brand-new", statusActive, tierKeep)},
			base:           NewBaseline(),
			policy:         "",
			wantFailed:     true,
			wantNewCount:   1,
			wantVerifCount: 1,
		},
		{
			name:           "known baselined verified does NOT fail",
			current:        []models.SecretModel{sec("aws", "known-active-value", statusActive, tierKeep)},
			base:           baselineWithKnown(),
			policy:         FailOnNewVerified,
			wantFailed:     false,
			wantNewCount:   0,
			wantVerifCount: 0,
		},
		{
			name: "new but unverified does not fail under FailOnNewVerified",
			current: []models.SecretModel{
				sec("aws", "unverified-new", "unchecked", tierKeep),
				sec("gcp", "inactive-new", "inactive", tierKeep),
			},
			base:           NewBaseline(),
			policy:         FailOnNewVerified,
			wantFailed:     false,
			wantNewCount:   2,
			wantVerifCount: 0,
		},
		{
			name: "FailOnNewAny fails on any new even if unverified",
			current: []models.SecretModel{
				sec("aws", "unverified-new", "unchecked", tierKeep),
			},
			base:           NewBaseline(),
			policy:         FailOnNewAny,
			wantFailed:     true,
			wantNewCount:   1,
			wantVerifCount: 0,
		},
		{
			name: "FailOnNewAny vs FailOnNewVerified diverge on same input",
			// One new-inactive secret: NewAny fails, NewVerified does not.
			current:        []models.SecretModel{sec("aws", "inactive-new", "inactive", tierKeep)},
			base:           NewBaseline(),
			policy:         FailOnNewVerified,
			wantFailed:     false,
			wantNewCount:   1,
			wantVerifCount: 0,
		},
		{
			name:           "allowlisted fingerprint suppressed",
			current:        []models.SecretModel{sec("aws", "allowlisted-fp", statusActive, tierKeep)},
			base:           &Baseline{Fingerprints: map[string]struct{}{}, AllowedFingerprints: map[string]struct{}{fp("allowlisted-fp"): {}}, AllowedTypes: map[string]struct{}{}},
			policy:         FailOnNewVerified,
			wantFailed:     false,
			wantNewCount:   0,
			wantVerifCount: 0,
		},
		{
			name:           "allowlisted secret type suppressed",
			current:        []models.SecretModel{sec("test-fixture", "any-value", statusActive, tierKeep)},
			base:           &Baseline{Fingerprints: map[string]struct{}{}, AllowedFingerprints: map[string]struct{}{}, AllowedTypes: map[string]struct{}{"test-fixture": {}}},
			policy:         FailOnNewVerified,
			wantFailed:     false,
			wantNewCount:   0,
			wantVerifCount: 0,
		},
		{
			name: "FailOnTierKeep fails on new keep-tier, ignores info-tier",
			current: []models.SecretModel{
				sec("aws", "keep-new", "unchecked", tierKeep),
				sec("gcp", "info-new", "unchecked", "info"),
			},
			base:           NewBaseline(),
			policy:         FailOnTierKeep,
			wantFailed:     true,
			wantNewCount:   2,
			wantVerifCount: 0,
		},
		{
			name: "FailOnTierKeep does not fail when only info-tier is new",
			current: []models.SecretModel{
				sec("gcp", "info-new", "unchecked", "info"),
			},
			base:           NewBaseline(),
			policy:         FailOnTierKeep,
			wantFailed:     false,
			wantNewCount:   1,
			wantVerifCount: 0,
		},
		{
			name:           "None never fails despite new verified",
			current:        []models.SecretModel{sec("aws", "brand-new", statusActive, tierKeep)},
			base:           NewBaseline(),
			policy:         None,
			wantFailed:     false,
			wantNewCount:   1,
			wantVerifCount: 1,
		},
		{
			name:           "empty baseline treats everything as new",
			current:        []models.SecretModel{sec("aws", "a", statusActive, tierKeep), sec("gcp", "b", "unchecked", "info")},
			base:           NewBaseline(),
			policy:         FailOnNewVerified,
			wantFailed:     true,
			wantNewCount:   2,
			wantVerifCount: 1,
		},
		{
			name:           "nil baseline treated as empty",
			current:        []models.SecretModel{sec("aws", "a", statusActive, tierKeep)},
			base:           nil,
			policy:         FailOnNewVerified,
			wantFailed:     true,
			wantNewCount:   1,
			wantVerifCount: 1,
		},
		{
			name:           "no current findings never fails",
			current:        nil,
			base:           NewBaseline(),
			policy:         FailOnNewAny,
			wantFailed:     false,
			wantNewCount:   0,
			wantVerifCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.current, tt.base, tt.policy)
			if got.Failed != tt.wantFailed {
				t.Errorf("Failed = %v, want %v (reason=%q)", got.Failed, tt.wantFailed, got.Reason)
			}
			if len(got.NewFindings) != tt.wantNewCount {
				t.Errorf("len(NewFindings) = %d, want %d", len(got.NewFindings), tt.wantNewCount)
			}
			if len(got.NewVerified) != tt.wantVerifCount {
				t.Errorf("len(NewVerified) = %d, want %d", len(got.NewVerified), tt.wantVerifCount)
			}
			if got.Reason == "" {
				t.Errorf("Reason is empty; want a non-empty explanation")
			}
		})
	}
}

func TestBaselineFromScan(t *testing.T) {
	current := []models.SecretModel{
		sec("aws", "v1", statusActive, tierKeep),
		sec("gcp", "v2", "unchecked", "info"),
	}
	b := BaselineFromScan(current)

	if len(b.Fingerprints) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(b.Fingerprints))
	}
	if _, ok := b.Fingerprints[fp("v1")]; !ok {
		t.Errorf("fingerprint for v1 missing from snapshot")
	}
	if _, ok := b.Fingerprints[fp("v2")]; !ok {
		t.Errorf("fingerprint for v2 missing from snapshot")
	}

	// A scan re-run against its own snapshot must produce no new findings.
	res := Evaluate(current, b, FailOnNewAny)
	if res.Failed || len(res.NewFindings) != 0 {
		t.Errorf("snapshot baseline should suppress all findings; got Failed=%v new=%d", res.Failed, len(res.NewFindings))
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	orig := NewBaseline()
	orig.Fingerprints[fp("v1")] = struct{}{}
	orig.Fingerprints[fp("v2")] = struct{}{}
	orig.AllowedFingerprints[fp("allow-me")] = struct{}{}
	orig.AllowedTypes["test-fixture"] = struct{}{}

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := orig.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	if !reflect.DeepEqual(orig.Fingerprints, got.Fingerprints) {
		t.Errorf("Fingerprints mismatch:\n orig=%v\n got =%v", orig.Fingerprints, got.Fingerprints)
	}
	if !reflect.DeepEqual(orig.AllowedFingerprints, got.AllowedFingerprints) {
		t.Errorf("AllowedFingerprints mismatch:\n orig=%v\n got =%v", orig.AllowedFingerprints, got.AllowedFingerprints)
	}
	if !reflect.DeepEqual(orig.AllowedTypes, got.AllowedTypes) {
		t.Errorf("AllowedTypes mismatch:\n orig=%v\n got =%v", orig.AllowedTypes, got.AllowedTypes)
	}
}

func TestLoadBaselineErrors(t *testing.T) {
	if _, err := LoadBaseline(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Errorf("expected error loading missing file")
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(bad); err == nil {
		t.Errorf("expected error parsing invalid JSON")
	}
}
