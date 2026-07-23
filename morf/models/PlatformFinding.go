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

// Package models defines the shared data types exchanged across MORF packages.
package models

// PlatformFindingSeverity is the severity level for a platform security finding.
// Valid values are the four named constants below; any other string is treated
// as informational by consumers.
type PlatformFindingSeverity string

const (
	// SeverityInfo is an informational observation that does not represent an
	// immediate risk. Maps to SARIF level "note" and precision Tier "info".
	SeverityInfo PlatformFindingSeverity = "info"

	// SeverityLow is a low-risk finding that warrants attention but is unlikely
	// to be directly exploitable in isolation. Maps to SARIF level "warning".
	SeverityLow PlatformFindingSeverity = "low"

	// SeverityMedium is a medium-risk finding that could be exploited under
	// certain conditions. Maps to SARIF level "warning".
	SeverityMedium PlatformFindingSeverity = "medium"

	// SeverityHigh is a high-risk finding that is likely directly exploitable.
	// Maps to SARIF level "error" and precision Tier "keep".
	SeverityHigh PlatformFindingSeverity = "high"
)

// TierForSeverity maps a PlatformFindingSeverity to the precision-engine Tier
// vocabulary ("drop" / "info" / "keep") used by secrets. Platform findings are
// never dropped by the engine, so only "info" and "keep" are returned.
func TierForSeverity(s PlatformFindingSeverity) string {
	switch s {
	case SeverityHigh:
		return "keep"
	default:
		// info, low, medium — all surface as informational in the tier ladder.
		return "info"
	}
}

// PlatformFinding represents a single NON-secret security finding produced by a
// platform-level detector (e.g. an exported Android component reachable without
// a permission, a misconfigured deep-link, or a Firebase misconfiguration). It
// is intentionally separate from models.SecretModel so that the two concern
// areas remain independently evolvable and their SARIF emission rules stay
// decoupled.
//
// Field naming mirrors the SecretModel convention where the same concept exists
// (MASVSID, Tier) so cross-cutting consumers can handle both types uniformly.
type PlatformFinding struct {
	// RuleID is the stable, machine-readable identifier for this class of
	// finding (e.g. "exported-component-no-permission",
	// "deep-link-missing-autoVerify"). It is used as the SARIF ruleId and as
	// the primary key for rule deduplication.
	RuleID string `json:"ruleId"`

	// Title is a short, human-readable name for the finding rule (e.g.
	// "Exported component without permission guard"). It maps to the SARIF
	// reportingDescriptor.name field.
	Title string `json:"title"`

	// Severity is the risk classification: info | low | medium | high.
	// Use the SeverityXxx constants for assignment.
	Severity PlatformFindingSeverity `json:"severity"`

	// MASVSID is the OWASP MASVS control identifier attributed to this class
	// of finding (e.g. "MASVS-PLATFORM-1"). It is emitted as a tag on the
	// SARIF rule and as a properties.masvsId entry on each SARIF result, and is
	// intentionally parallel to SecretModel.MASVSID.
	MASVSID string `json:"masvsId,omitempty"`

	// Category groups the finding class for display and filtering. Use
	// "platform" for component-exposure / intent / deep-link findings, and
	// "config" for configuration-level findings (Firebase, Google Services, etc.).
	Category string `json:"category"`

	// Location is the file or component path that best identifies where the
	// issue was detected (e.g. "AndroidManifest.xml",
	// "com.example.app.MainActivity", "GoogleService-Info.plist"). It is mapped
	// to the SARIF physicalLocation.artifactLocation.uri field.
	Location string `json:"location"`

	// Evidence is a short, human-readable description of the observed condition
	// that triggered this finding (e.g. "android:exported=true with no
	// permission attribute"). It must NEVER contain a secret value; the SARIF
	// encoder runs it through the mask helper defensively, but the generator is
	// responsible for keeping secrets out of this field.
	Evidence string `json:"evidence"`

	// Tier maps the finding into the shared precision-engine vocabulary:
	// "info" (informational, surfaced but not blocking) or "keep" (high
	// confidence, blocking in strict gate policies). Populated automatically
	// from Severity by TierForSeverity when not explicitly set; callers may
	// override it for special cases.
	Tier string `json:"tier,omitempty"`
}
