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

// Package report renders MORF scan findings into external interchange formats.
// EncodeSARIF produces a SARIF 2.1.0 document (Static Analysis Results
// Interchange Format) so findings can be ingested directly by GitHub Code
// Scanning, Microsoft Defender, and most security dashboards without a bespoke
// parser.
package report

import (
	"encoding/json"

	"morf/models"
)

const (
	// sarifVersion is the SARIF schema version this encoder targets.
	sarifVersion = "2.1.0"
	// sarifSchema is the canonical JSON schema URL for SARIF 2.1.0.
	sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"
	// driverName is the analysis tool name reported in tool.driver.name.
	driverName = "MORF"
	// driverInfoURI is the tool's information URI.
	driverInfoURI = "https://github.com/amrudesh1/morf"
)

// SARIF document types. Only the subset of the SARIF 2.1.0 object model that
// MORF emits is modelled here; omitempty keeps the output compact and
// schema-valid. See https://json.schemastore.org/sarif-2.1.0.json.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool              `json:"tool"`
	Results    []sarifResult          `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifReportingDescriptor struct {
	ID               string               `json:"id"`
	Name             string               `json:"name,omitempty"`
	ShortDescription *sarifMessage        `json:"shortDescription,omitempty"`
	Properties       *sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// levelForTier maps a precision Tier to a SARIF result level. "keep" findings
// are confident true positives (error); "info" findings are retained but
// downgraded (note); anything else falls back to "warning".
func levelForTier(tier string) string {
	switch tier {
	case "keep":
		return "error"
	case "info":
		return "note"
	default:
		return "warning"
	}
}

// maskSecret redacts a secret value for safe inclusion in the SARIF message,
// preserving at most the first four and last two characters so a human can
// eyeball-correlate without the raw value leaking into the report.
func maskSecret(value string) string {
	runes := []rune(value)
	n := len(runes)
	if n == 0 {
		return "…"
	}
	first := 4
	if first > n {
		first = n
	}
	last := 2
	// Never let head and tail overlap; if the value is short, drop the tail.
	if first+last > n {
		last = 0
	}
	head := string(runes[:first])
	tail := ""
	if last > 0 {
		tail = string(runes[n-last:])
	}
	return head + "…" + tail
}

// MaskResultJSON walks a stored scan-result envelope
// ({"data":{"secrets":[{"secretString":...},...]}}) and replaces every
// secretString with a masked preview (same masking used in the SARIF export),
// preserving all other fields and structure. It is used to keep raw secret
// values out of the /results JSON API by default.
//
// It fails CLOSED: if the payload cannot be parsed as JSON it returns an error
// and NO bytes, so a masking failure can never fall through to leaking the raw
// payload. Callers should drop the result field (or 500) on error rather than
// returning the unmasked input.
func MaskResultJSON(raw []byte) ([]byte, error) {
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if data, ok := env["data"].(map[string]any); ok {
		if secrets, ok := data["secrets"].([]any); ok {
			for _, s := range secrets {
				if m, ok := s.(map[string]any); ok {
					if v, ok := m["secretString"].(string); ok {
						m["secretString"] = maskSecret(v)
					}
				}
			}
		}
	}
	return json.Marshal(env)
}

// MaskComparisonJSON walks a ComparisonResult JSON envelope
// ({"added":[...],"removed":[...],"unchanged":[...],...}) and replaces every
// secretString in the three secret-list arrays with a masked preview, preserving
// all other fields and structure.
//
// It uses the same masking as MaskResultJSON and fails CLOSED: a parse failure
// returns an error and NO bytes so the caller can drop the field rather than
// leak raw secrets.
func MaskComparisonJSON(raw []byte) ([]byte, error) {
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	for _, key := range []string{"added", "removed", "unchanged"} {
		if list, ok := env[key].([]any); ok {
			for _, item := range list {
				if m, ok := item.(map[string]any); ok {
					if v, ok := m["secretString"].(string); ok {
						m["secretString"] = maskSecret(v)
					}
				}
			}
		}
	}
	return json.Marshal(env)
}

// levelForPlatformSeverity maps a PlatformFinding Severity string to a SARIF
// result level. High findings map to "error"; everything else maps to "warning"
// (medium/low) or "note" (info).
func levelForPlatformSeverity(severity models.PlatformFindingSeverity) string {
	switch severity {
	case models.SeverityHigh:
		return "error"
	case models.SeverityInfo:
		return "note"
	default:
		// medium and low
		return "warning"
	}
}

// EncodeSARIF renders the given findings as a SARIF 2.1.0 JSON document for the
// scanned artifact. target identifies the scanned bundle (file name / package
// id), platform is "android" or "ios", and secrets are the enriched findings to
// report.
//
// The document contains a single run whose tool.driver.name is "MORF".
// tool.driver.rules holds one reportingDescriptor per distinct secret type (in
// first-seen order), carrying the MASVS control id in properties.tags when a
// finding of that type is attributed to one. Each finding becomes one SARIF
// result: ruleId = secret type; level derived from the precision Tier; a
// redacted (masked) message; a physicalLocation from FileLocation + LineNo; and
// properties carrying Score, Tier, VerificationStatus, and MASVSID. The run's
// properties are populated from target and platform so the report is
// self-describing.
//
// This function is a backward-compatible wrapper around EncodeSARIFWithFindings
// that passes nil for platform findings so all existing callers remain unchanged.
func EncodeSARIF(target string, platform string, secrets []models.SecretModel) ([]byte, error) {
	return EncodeSARIFWithFindings(target, platform, secrets, nil)
}

// EncodeSARIFWithFindings renders both secret findings and platform findings as a
// SARIF 2.1.0 JSON document for the scanned artifact. It is the canonical encoder;
// EncodeSARIF delegates here with nil platformFindings.
//
// Platform findings are appended to the SARIF results array after the secret
// findings. Each platform finding contributes one rule (keyed by RuleID) to
// tool.driver.rules the first time it is seen; the MASVSID (if present) is
// added as a tag. Each SARIF result for a platform finding carries:
//   - ruleId = PlatformFinding.RuleID
//   - level derived from Severity (high -> error, info -> note, else warning)
//   - message.text = PlatformFinding.Evidence (defensively masked)
//   - physicalLocation.uri = PlatformFinding.Location
//   - properties: category, tier, masvsId (when set)
//
// Platform findings contain no secret values, but Evidence is still run through
// maskSecret defensively (a masked ellipsis is safe; an accidental token is not).
//
// Platform findings do NOT affect the gate/exit-code semantics in cmd/scan.go —
// they are always reported but never cause a policy failure unless a future gate
// policy explicitly checks them. This is by design: detectors fill
// []PlatformFinding and hand it to the aggregation point; the gate evaluates
// []SecretModel independently.
func EncodeSARIFWithFindings(target string, platform string, secrets []models.SecretModel, platformFindings []models.PlatformFinding) ([]byte, error) {
	rules := make([]sarifReportingDescriptor, 0)
	ruleIndex := make(map[string]int)
	results := make([]sarifResult, 0, len(secrets)+len(platformFindings))

	// --- Secret findings (identical to the original EncodeSARIF logic) ---
	for _, s := range secrets {
		ruleID := s.SecretType

		// Register a rule the first time we see this secret type. If a later
		// finding of the same type carries a MASVS id and the earlier one did
		// not, backfill the tag so the rule advertises the mapping.
		idx, ok := ruleIndex[ruleID]
		if !ok {
			rule := sarifReportingDescriptor{
				ID:   ruleID,
				Name: ruleID,
				ShortDescription: &sarifMessage{
					Text: "Hardcoded secret of type " + ruleID + " detected by MORF.",
				},
			}
			if s.MASVSID != "" {
				rule.Properties = &sarifRuleProperties{Tags: []string{s.MASVSID}}
			}
			rules = append(rules, rule)
			ruleIndex[ruleID] = len(rules) - 1
		} else if s.MASVSID != "" {
			r := &rules[idx]
			if r.Properties == nil {
				r.Properties = &sarifRuleProperties{}
			}
			if !containsString(r.Properties.Tags, s.MASVSID) {
				r.Properties.Tags = append(r.Properties.Tags, s.MASVSID)
			}
		}

		result := sarifResult{
			RuleID: ruleID,
			Level:  levelForTier(s.Tier),
			Message: sarifMessage{
				Text: ruleID + " (masked: " + maskSecret(s.SecretString) + ")",
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: s.FileLocation},
						Region:           &sarifRegion{StartLine: s.LineNo},
					},
				},
			},
		}

		props := make(map[string]interface{})
		if s.Score != 0 {
			props["score"] = s.Score
		}
		if s.Tier != "" {
			props["tier"] = s.Tier
		}
		if s.VerificationStatus != "" {
			props["verificationStatus"] = s.VerificationStatus
		}
		if s.MASVSID != "" {
			props["masvsId"] = s.MASVSID
		}
		if len(props) > 0 {
			result.Properties = props
		}

		results = append(results, result)
	}

	// --- Platform findings ---
	for _, pf := range platformFindings {
		ruleID := pf.RuleID

		// Register the rule the first time we see this RuleID. Back-fill MASVS
		// tag on a subsequent encounter if the earlier finding lacked one.
		idx, ok := ruleIndex[ruleID]
		if !ok {
			rule := sarifReportingDescriptor{
				ID:   ruleID,
				Name: pf.Title,
				ShortDescription: &sarifMessage{
					Text: pf.Title + " detected by MORF.",
				},
			}
			if pf.MASVSID != "" {
				rule.Properties = &sarifRuleProperties{Tags: []string{pf.MASVSID}}
			}
			rules = append(rules, rule)
			ruleIndex[ruleID] = len(rules) - 1
		} else if pf.MASVSID != "" {
			r := &rules[idx]
			if r.Properties == nil {
				r.Properties = &sarifRuleProperties{}
			}
			if !containsString(r.Properties.Tags, pf.MASVSID) {
				r.Properties.Tags = append(r.Properties.Tags, pf.MASVSID)
			}
		}

		// Determine effective tier (use stored Tier if set, else derive from severity).
		tier := pf.Tier
		if tier == "" {
			tier = models.TierForSeverity(pf.Severity)
		}

		// PlatformFinding.Evidence is a NON-secret resource identifier by contract
		// (a component class name, scheme://host, RTDB host, or bucket — never a
		// credential; the detectors that build these findings never place a secret
		// here). It is the actionable content of the SARIF message, so it is
		// emitted verbatim. (maskSecret would truncate it to "http…le" and destroy
		// the host/component the triager needs.) Secret VALUES live only in
		// models.SecretModel and remain masked on their own SARIF path.
		result := sarifResult{
			RuleID: ruleID,
			Level:  levelForPlatformSeverity(pf.Severity),
			Message: sarifMessage{
				Text: pf.Title + ": " + pf.Evidence,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: pf.Location},
					},
				},
			},
		}

		props := make(map[string]interface{})
		if pf.Category != "" {
			props["category"] = pf.Category
		}
		if tier != "" {
			props["tier"] = tier
		}
		if pf.MASVSID != "" {
			props["masvsId"] = pf.MASVSID
		}
		if len(props) > 0 {
			result.Properties = props
		}

		results = append(results, result)
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           driverName,
						InformationURI: driverInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
				Properties: map[string]interface{}{
					"target":   target,
					"platform": platform,
				},
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}

// containsString reports whether s is present in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
