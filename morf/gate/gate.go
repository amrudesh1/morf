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

// Package gate implements the MORF build-diff gate: given the findings of a
// candidate scan and a baseline of previously-accepted findings, it decides
// whether the build should fail.
//
// Identity is crypto.Fingerprint(secretValue), the same keyed HMAC-SHA256
// identity the DB fingerprint column and the baseline use. This means:
//   - line/path churn never manufactures a false gate failure, and
//   - no plaintext secret ever enters the gate's inputs, outputs, or the
//     on-disk baseline/allowlist (all identities are opaque fingerprints).
package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"morf/crypto"
	"morf/models"
)

// statusActive is the sole VerificationStatus that means "confirmed live" (see
// verify/registry.go). Kept as a local literal so the gate does not depend on
// the unexported constant in the verify package.
const statusActive = "active"

// tierKeep is the precision tier for a confident, retained finding (set by
// detect.ApplyPrecision). Downgraded findings carry Tier == "info".
const tierKeep = "keep"

// Policy selects the condition under which Evaluate marks a build as failed.
type Policy string

const (
	// FailOnNewVerified fails only when a NEW finding is verified active. This
	// is the default and the recommended CI policy: it gates on credentials
	// confirmed live that were not previously accepted.
	FailOnNewVerified Policy = "new_verified"
	// FailOnNewAny fails when any NEW finding appears, regardless of
	// verification status.
	FailOnNewAny Policy = "new_any"
	// FailOnTierKeep fails when a NEW finding is classified Tier == "keep"
	// (a confident detection), regardless of verification status.
	FailOnTierKeep Policy = "new_tier_keep"
	// None never fails; useful for reporting-only runs that still want the
	// computed NewFindings/NewVerified lists.
	None Policy = "none"
)

// DefaultPolicy is the policy applied when an empty Policy is passed to
// Evaluate.
const DefaultPolicy = FailOnNewVerified

// Baseline is a snapshot of accepted findings plus an operator allowlist. A
// finding is "known" (non-gating) when its fingerprint is in Fingerprints, its
// fingerprint is allowlisted, or its secret type is allowlisted.
//
// Everything stored here is an opaque crypto.Fingerprint hex digest or a secret
// type label; no plaintext secret is ever persisted, so a Baseline file is safe
// to commit and share.
type Baseline struct {
	// Fingerprints is the set of accepted secret fingerprints.
	Fingerprints map[string]struct{} `json:"-"`
	// AllowedFingerprints is the operator allowlist of fingerprints that must
	// never gate, even if they are not part of an accepted snapshot.
	AllowedFingerprints map[string]struct{} `json:"-"`
	// AllowedTypes is the operator allowlist of secret types (e.g.
	// "aws-access-key") that must never gate.
	AllowedTypes map[string]struct{} `json:"-"`
}

// NewBaseline returns an empty, ready-to-use Baseline with all sets
// initialized.
func NewBaseline() *Baseline {
	return &Baseline{
		Fingerprints:        map[string]struct{}{},
		AllowedFingerprints: map[string]struct{}{},
		AllowedTypes:        map[string]struct{}{},
	}
}

// baselineJSON is the on-disk representation. Sets are encoded as sorted slices
// for stable, diff-friendly files.
type baselineJSON struct {
	Fingerprints        []string `json:"fingerprints"`
	AllowedFingerprints []string `json:"allowedFingerprints,omitempty"`
	AllowedTypes        []string `json:"allowedTypes,omitempty"`
}

func setToSortedSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sliceToSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// MarshalJSON implements json.Marshaler, encoding the sets as sorted slices.
func (b *Baseline) MarshalJSON() ([]byte, error) {
	return json.Marshal(baselineJSON{
		Fingerprints:        setToSortedSlice(b.Fingerprints),
		AllowedFingerprints: setToSortedSlice(b.AllowedFingerprints),
		AllowedTypes:        setToSortedSlice(b.AllowedTypes),
	})
}

// UnmarshalJSON implements json.Unmarshaler, decoding the sorted slices back
// into sets. Nil maps are initialized so the zero-value-from-disk Baseline is
// immediately usable.
func (b *Baseline) UnmarshalJSON(data []byte) error {
	var bj baselineJSON
	if err := json.Unmarshal(data, &bj); err != nil {
		return err
	}
	b.Fingerprints = sliceToSet(bj.Fingerprints)
	b.AllowedFingerprints = sliceToSet(bj.AllowedFingerprints)
	b.AllowedTypes = sliceToSet(bj.AllowedTypes)
	return nil
}

// isKnown reports whether a finding is baselined or allowlisted (and therefore
// never gates).
func (b *Baseline) isKnown(fp, secretType string) bool {
	if b == nil {
		return false
	}
	if _, ok := b.Fingerprints[fp]; ok {
		return true
	}
	if _, ok := b.AllowedFingerprints[fp]; ok {
		return true
	}
	if _, ok := b.AllowedTypes[secretType]; ok {
		return true
	}
	return false
}

// LoadBaseline reads and parses a Baseline JSON file from path.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gate: read baseline %q: %w", path, err)
	}
	b := NewBaseline()
	if err := json.Unmarshal(data, b); err != nil {
		return nil, fmt.Errorf("gate: parse baseline %q: %w", path, err)
	}
	return b, nil
}

// Save writes the Baseline as indented JSON to path.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("gate: marshal baseline: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("gate: write baseline %q: %w", path, err)
	}
	return nil
}

// Allow adds fp to AllowedFingerprints. The call is idempotent: adding a
// fingerprint that is already present is a no-op. fp must be an opaque
// crypto.Fingerprint hex digest — no plaintext secret is ever stored.
func (b *Baseline) Allow(fp string) {
	if b.AllowedFingerprints == nil {
		b.AllowedFingerprints = map[string]struct{}{}
	}
	b.AllowedFingerprints[fp] = struct{}{}
}

// AllowType adds secretType to AllowedTypes. The call is idempotent: adding a
// type that is already present is a no-op.
func (b *Baseline) AllowType(secretType string) {
	if b.AllowedTypes == nil {
		b.AllowedTypes = map[string]struct{}{}
	}
	b.AllowedTypes[secretType] = struct{}{}
}

// BaselineFromScan snapshots current findings into an accepted Baseline. Every
// finding's fingerprint becomes an accepted fingerprint; the allowlists start
// empty. Callers who also want to seed allowlists can populate the returned
// Baseline's AllowedFingerprints / AllowedTypes before saving.
func BaselineFromScan(current []models.SecretModel) *Baseline {
	b := NewBaseline()
	for _, s := range current {
		b.Fingerprints[crypto.Fingerprint(s.SecretString)] = struct{}{}
	}
	return b
}

// GateResult is the outcome of Evaluate.
type GateResult struct {
	// NewFindings are findings whose fingerprint is neither baselined nor
	// allowlisted.
	NewFindings []models.SecretModel `json:"newFindings"`
	// NewVerified is the subset of NewFindings that are verified active.
	NewVerified []models.SecretModel `json:"newVerified"`
	// Failed is true when the selected Policy's fail condition is met.
	Failed bool `json:"failed"`
	// Reason is a short human-readable explanation of the outcome.
	Reason string `json:"reason"`
}

// Evaluate diffs current findings against base under policy.
//
// Identity is crypto.Fingerprint(secret value). A finding is "New" when its
// fingerprint is not in the baseline and not allowlisted (by fingerprint or by
// secret type). A finding is "Verified" when VerificationStatus == "active".
//
// The returned NewFindings/NewVerified are always populated regardless of
// policy, so a None run still yields the diff for reporting.
func Evaluate(current []models.SecretModel, base *Baseline, policy Policy) GateResult {
	if policy == "" {
		policy = DefaultPolicy
	}

	var res GateResult
	var newTierKeep int

	for _, s := range current {
		fp := crypto.Fingerprint(s.SecretString)
		if base.isKnown(fp, s.SecretType) {
			continue
		}
		res.NewFindings = append(res.NewFindings, s)
		if s.VerificationStatus == statusActive {
			res.NewVerified = append(res.NewVerified, s)
		}
		if s.Tier == tierKeep {
			newTierKeep++
		}
	}

	switch policy {
	case FailOnNewAny:
		res.Failed = len(res.NewFindings) > 0
		if res.Failed {
			res.Reason = fmt.Sprintf("%d new finding(s) detected (policy=%s)", len(res.NewFindings), policy)
		} else {
			res.Reason = "no new findings"
		}
	case FailOnTierKeep:
		res.Failed = newTierKeep > 0
		if res.Failed {
			res.Reason = fmt.Sprintf("%d new keep-tier finding(s) detected (policy=%s)", newTierKeep, policy)
		} else {
			res.Reason = "no new keep-tier findings"
		}
	case None:
		res.Failed = false
		res.Reason = fmt.Sprintf("gate disabled (policy=%s); %d new finding(s), %d new verified", policy, len(res.NewFindings), len(res.NewVerified))
	case FailOnNewVerified:
		fallthrough
	default:
		res.Failed = len(res.NewVerified) > 0
		if res.Failed {
			res.Reason = fmt.Sprintf("%d new verified-active finding(s) detected (policy=%s)", len(res.NewVerified), policy)
		} else {
			res.Reason = "no new verified-active findings"
		}
	}

	return res
}
