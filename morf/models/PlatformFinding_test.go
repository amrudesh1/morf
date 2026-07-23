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

package models

import (
	"encoding/json"
	"testing"
)

// TestPlatformFindingSeverityConstants verifies the four severity constants
// have the correct string values, which appear verbatim in JSON output and in
// the SARIF level mapping.
func TestPlatformFindingSeverityConstants(t *testing.T) {
	cases := map[PlatformFindingSeverity]string{
		SeverityInfo:   "info",
		SeverityLow:    "low",
		SeverityMedium: "medium",
		SeverityHigh:   "high",
	}
	for sev, want := range cases {
		if string(sev) != want {
			t.Errorf("PlatformFindingSeverity constant %q has value %q, want %q", want, string(sev), want)
		}
	}
}

// TestTierForSeverity verifies the Tier mapping from severity to the precision
// tier vocabulary. Only "info" and "keep" are valid output values.
func TestTierForSeverity(t *testing.T) {
	cases := map[PlatformFindingSeverity]string{
		SeverityHigh:   "keep",
		SeverityMedium: "info",
		SeverityLow:    "info",
		SeverityInfo:   "info",
	}
	for sev, want := range cases {
		got := TierForSeverity(sev)
		if got != want {
			t.Errorf("TierForSeverity(%q) = %q, want %q", sev, got, want)
		}
	}
	// Unknown severity values must also map to "info" (safe default).
	if got := TierForSeverity("bogus"); got != "info" {
		t.Errorf("TierForSeverity(bogus) = %q, want info", got)
	}
}

// TestPlatformFindingJSONRoundTrip verifies that all fields survive a
// json.Marshal + json.Unmarshal round-trip without loss, and that the JSON
// keys match the documented names (which the SARIF encoder and downstream
// consumers key on).
func TestPlatformFindingJSONRoundTrip(t *testing.T) {
	orig := PlatformFinding{
		RuleID:   "exported-component-no-permission",
		Title:    "Exported component without permission guard",
		Severity: SeverityHigh,
		MASVSID:  "MASVS-PLATFORM-1",
		Category: "platform",
		Location: "AndroidManifest.xml",
		Evidence: "android:exported=true with no permission attribute",
		Tier:     "keep",
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got PlatformFinding
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.RuleID != orig.RuleID {
		t.Errorf("RuleID: got %q, want %q", got.RuleID, orig.RuleID)
	}
	if got.Title != orig.Title {
		t.Errorf("Title: got %q, want %q", got.Title, orig.Title)
	}
	if got.Severity != orig.Severity {
		t.Errorf("Severity: got %q, want %q", got.Severity, orig.Severity)
	}
	if got.MASVSID != orig.MASVSID {
		t.Errorf("MASVSID: got %q, want %q", got.MASVSID, orig.MASVSID)
	}
	if got.Category != orig.Category {
		t.Errorf("Category: got %q, want %q", got.Category, orig.Category)
	}
	if got.Location != orig.Location {
		t.Errorf("Location: got %q, want %q", got.Location, orig.Location)
	}
	if got.Evidence != orig.Evidence {
		t.Errorf("Evidence: got %q, want %q", got.Evidence, orig.Evidence)
	}
	if got.Tier != orig.Tier {
		t.Errorf("Tier: got %q, want %q", got.Tier, orig.Tier)
	}
}

// TestPlatformFindingJSONKeys verifies that the JSON key names exactly match
// what is documented (the SARIF encoder, MaskResultJSON, and the frontend
// all key on these names).
func TestPlatformFindingJSONKeys(t *testing.T) {
	f := PlatformFinding{
		RuleID:   "r",
		Title:    "t",
		Severity: SeverityMedium,
		MASVSID:  "MASVS-PLATFORM-1",
		Category: "platform",
		Location: "l",
		Evidence: "e",
		Tier:     "info",
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"ruleId", "title", "severity", "masvsId", "category", "location", "evidence", "tier"} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}

// TestPlatformFindingMASVSIDOmitEmpty verifies that a PlatformFinding with no
// MASVSID does not emit a "masvsId" key in JSON (it is tagged omitempty).
func TestPlatformFindingMASVSIDOmitEmpty(t *testing.T) {
	f := PlatformFinding{
		RuleID:   "some-rule",
		Title:    "Some Rule",
		Severity: SeverityLow,
		Category: "config",
		Location: "some-file.json",
		Evidence: "some observation",
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := m["masvsId"]; ok {
		t.Errorf("masvsId should be absent when empty (omitempty), but found in JSON")
	}
}
