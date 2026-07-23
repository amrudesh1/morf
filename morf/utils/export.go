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

package utils

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"morf/models"
	"morf/osv"
	"morf/version"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// ExportFormat represents the export format
type ExportFormat string

const (
	ExportFormatJSON      ExportFormat = "json"
	ExportFormatCSV       ExportFormat = "csv"
	ExportFormatPDF       ExportFormat = "pdf"
	ExportFormatSARIF     ExportFormat = "sarif"     // GitHub Code Scanning, Defender, etc.
	ExportFormatCycloneDX ExportFormat = "cyclonedx" // SBOM (CycloneDX 1.6 JSON)
	// ExportFormatCycloneDXSBOM is an alias for ExportFormatCycloneDX; both
	// route to exportCycloneDX and emit identical CycloneDX 1.6 output. It
	// exists so callers/tooling that request the more explicit "cyclonedx-sbom"
	// format string are served the SBOM rather than rejected.
	ExportFormatCycloneDXSBOM ExportFormat = "cyclonedx-sbom"
)

// scanResultPayload mirrors the JSON envelope written by the worker into
// ScanJob.Result. Decoding into typed fields eliminates the per-export
// generic map[string]interface{} allocation and traversal (EXPORT-1mem).
type scanResultPayload struct {
	Message       string         `json:"message"`
	SchemaVersion string         `json:"schema_version,omitempty"`
	Data          scanResultData `json:"data"`
}

// scanResultData holds the per-scan fields stored under the "data" key.
// Secrets are decoded directly into []models.SecretModel to avoid nested
// map rebuilding on every export path.
type scanResultData struct {
	FileName    string               `json:"fileName"`
	PackageName string               `json:"packageName"`
	Version     string               `json:"version"`
	MinSdk      string               `json:"minSdk"`
	TargetSdk   string               `json:"targetSdk"`
	Permissions []string             `json:"permissions"`
	SecretCount int                  `json:"secretCount"`
	Secrets     []models.SecretModel `json:"secrets"`
	// UsesLibrary is populated only for APKs that declare <uses-library> elements;
	// exportCycloneDX consumes it as a demoted platform-library fallback.
	UsesLibrary []string `json:"usesLibrary,omitempty"`
	// SBOMComponents is THE CONTRACT KEY (json "sbomComponents") that the
	// platform extractors populate in the scan result payload. Each element is
	// an evidence-bearing CycloneDX 1.6 component (see models.SBOMComponent);
	// exportCycloneDX maps these directly into the SBOM's components array,
	// preserving identity methods/confidence, occurrences, hashes and purl.
	SBOMComponents []models.SBOMComponent `json:"sbomComponents,omitempty"`
}

// ExportResult exports scan results in the specified format.
//
// JSON uses a raw map round-trip so that all envelope fields (including
// schema_version and any future additions) survive verbatim.
// Every other format decodes once into the typed scanResultPayload struct
// to eliminate per-export generic-map allocation churn (EXPORT-1mem).
func ExportResult(job *models.ScanJob, format ExportFormat) ([]byte, string, error) {
	if format == ExportFormatJSON {
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(job.Result), &raw); err != nil {
			return nil, "", fmt.Errorf("failed to parse result: %v", err)
		}
		return exportJSON(raw)
	}

	var result scanResultPayload
	if err := json.Unmarshal([]byte(job.Result), &result); err != nil {
		return nil, "", fmt.Errorf("failed to parse result: %v", err)
	}

	switch format {
	case ExportFormatCSV:
		return exportCSV(job, &result)
	case ExportFormatPDF:
		return exportPDF(job, &result)
	case ExportFormatSARIF:
		return exportSARIF(job, &result)
	case ExportFormatCycloneDX, ExportFormatCycloneDXSBOM:
		return exportCycloneDX(job, &result, nil)
	default:
		return nil, "", fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportSARIF exports results in SARIF 2.1.0 (Static Analysis Results
// Interchange Format). This unlocks ingestion by GitHub Code Scanning,
// Microsoft Defender, and most security dashboards without bespoke parsers.
//
// Each MORF secret finding maps to one SARIF "result" with:
//   - ruleId    -> SecretType
//   - level     -> "error" for high-confidence, "warning" otherwise
//   - location  -> FileLocation + LineNo
//   - message   -> brief textual summary
func exportSARIF(job *models.ScanJob, result *scanResultPayload) ([]byte, string, error) {
	rules := []map[string]interface{}{}
	results := []map[string]interface{}{}
	seenRules := map[string]struct{}{}

	for _, s := range result.Data.Secrets {
		ruleID := s.SecretType
		if ruleID == "" {
			ruleID = "morf.secret.unknown"
		}
		if _, seen := seenRules[ruleID]; !seen {
			rules = append(rules, map[string]interface{}{
				"id":               ruleID,
				"name":             ruleID,
				"shortDescription": map[string]string{"text": ruleID},
				"helpUri":          "https://github.com/your-org/morf",
			})
			seenRules[ruleID] = struct{}{}
		}

		level := "warning"
		if s.SecretConfidence == "high" {
			level = "error"
		}

		results = append(results, map[string]interface{}{
			"ruleId": ruleID,
			"level":  level,
			"message": map[string]string{
				"text": fmt.Sprintf("Detected %s in %s", ruleID, s.FileLocation),
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": s.FileLocation,
						},
						"region": map[string]int{
							"startLine": s.LineNo,
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"confidence": s.SecretConfidence,
				"jobId":      job.ID,
			},
		})
	}

	sarif := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "MORF",
						"informationUri": "https://github.com/your-org/morf",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}

	out, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal SARIF: %v", err)
	}
	return out, "application/sarif+json", nil
}

// exportCycloneDX exports a CycloneDX 1.6 JSON SBOM.
//
// The authoritative component source is result.Data.SBOMComponents — the
// evidence-bearing components the platform extractors produce (see
// models.SBOMComponent). Each is mapped to a CycloneDX component object with
// its full evidence graph: evidence.identity[].field/confidence/concludedValue,
// each identity's methods[].technique/confidence/value, evidence.occurrences[],
// content hashes, and purl.
//
// MORF characterizes its own output honestly: metadata.properties advertises
// the SBOM as an "evidence-based-lower-bound", and compositions declares the
// aggregate "incomplete" for the app assembly — MORF observes what is present
// in the artifact, it does not resolve a transitive dependency graph.
//
// The legacy <uses-library> handling survives only as a FALLBACK for older APK
// payloads that predate SBOMComponents. Those entries are demoted: they are
// classified type "platform" (not "library") to signal they are declared
// platform libraries, not identified third-party components. They are never
// emitted when real SBOMComponents are present.
//
// This function reads only inventory metadata (package id, library/framework
// names, versions, hashes, paths). It deliberately does NOT read
// result.Data.Secrets, so no secret value can leak into the SBOM.
//
// vulns is an optional pre-resolved vulnerability slice (from the osv package).
// When non-nil and non-empty, the vulnerabilities array is appended to the BOM.
// Pass nil to omit vulnerability enrichment (the default, opt-out path).
func exportCycloneDX(job *models.ScanJob, result *scanResultPayload, vulns []osv.OSVVulnerability) ([]byte, string, error) {
	pkg := result.Data.PackageName
	appVersion := result.Data.Version

	if pkg == "" {
		pkg = job.OriginalFilename
	}

	var components []map[string]interface{}

	if len(result.Data.SBOMComponents) > 0 {
		components = make([]map[string]interface{}, 0, len(result.Data.SBOMComponents))
		for _, c := range result.Data.SBOMComponents {
			components = append(components, cycloneDXComponent(c))
		}
	} else {
		// Fallback: demote declared platform libraries. Only reached for
		// legacy payloads with no SBOMComponents.
		components = make([]map[string]interface{}, 0, len(result.Data.UsesLibrary))
		for _, lib := range result.Data.UsesLibrary {
			if lib != "" {
				components = append(components, map[string]interface{}{
					"type":    "platform",
					"name":    lib,
					"bom-ref": "platform:" + lib,
				})
			}
		}
	}

	metadataComponent := map[string]interface{}{
		"type":    "application",
		"bom-ref": "app",
		"name":    pkg,
	}
	if appVersion != "" {
		metadataComponent["version"] = appVersion
	}

	bom := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"version":      1,
		"serialNumber": "urn:uuid:" + job.ID,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": map[string]interface{}{
				"components": []map[string]interface{}{
					{
						"type":      "application",
						"name":      "morf",
						"publisher": "MORF - Mobile Reconnaissance Framework",
						"version":   version.Version,
					},
				},
			},
			"component": metadataComponent,
			"properties": []map[string]string{
				{"name": "morf:sbom:completeness", "value": "evidence-based-lower-bound"},
			},
		},
		"components": components,
		"compositions": []map[string]interface{}{
			{
				"aggregate":  "incomplete",
				"assemblies": []string{"app"},
			},
		},
	}

	// Emit CycloneDX 1.6 vulnerabilities array only when enrichment produced results.
	// An empty or nil slice omits the key entirely, preserving identical output to
	// the non-enriched path (no schema noise for opt-out callers).
	if len(vulns) > 0 {
		bom["vulnerabilities"] = cycloneDXVulnerabilities(vulns)
	}

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal CycloneDX: %v", err)
	}
	return out, "application/vnd.cyclonedx+json", nil
}

// cycloneDXVulnerabilities converts a slice of OSV vulnerabilities into the
// CycloneDX 1.6 vulnerabilities array format. Each entry carries:
//   - id:      the canonical identifier (CVE/GHSA/OSV)
//   - source:  {name, url}
//   - ratings: [{severity, score, method, vector}] when CVSS data is available
//   - affects: [{ref: bom-ref of the affected component}]
//   - description: the truncated OSV summary
//
// Secret values are never present in an OSVVulnerability — only public
// vulnerability metadata — so no masking is required here.
func cycloneDXVulnerabilities(vulns []osv.OSVVulnerability) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(vulns))
	for _, v := range vulns {
		entry := map[string]interface{}{
			"id": v.ID,
			"source": map[string]string{
				"name": v.SourceName,
				"url":  v.SourceURL,
			},
			"affects": []map[string]interface{}{
				{"ref": v.AffectedBomRef},
			},
		}
		if v.Summary != "" {
			entry["description"] = v.Summary
		}
		// Ratings — only emit when we have meaningful severity data.
		if v.Severity != "" && v.Severity != "unknown" {
			rating := map[string]interface{}{
				"severity": v.Severity,
				"method":   "CVSSv31",
			}
			if v.CVSS != "" {
				rating["score"] = v.CVSS
			}
			if v.CVSSVector != "" {
				rating["vector"] = v.CVSSVector
			}
			entry["ratings"] = []map[string]interface{}{rating}
		}
		out = append(out, entry)
	}
	return out
}

// ExportResultWithOSV exports a CycloneDX SBOM with optional OSV enrichment.
// When osvClient is non-nil and osv.IsEnabled() is true (or forceOSV is true),
// it calls osvClient.EnrichComponents and folds the vulnerabilities into the BOM.
// For all other formats this behaves identically to ExportResult.
//
// SAFETY: the network call is only made when opt-in is active. When opt-in is
// off the function is a thin wrapper over ExportResult with zero overhead.
func ExportResultWithOSV(ctx context.Context, job *models.ScanJob, format ExportFormat, osvClient *osv.Client, forceOSV bool) ([]byte, string, error) {
	if format != ExportFormatCycloneDX && format != ExportFormatCycloneDXSBOM {
		return ExportResult(job, format)
	}

	var result scanResultPayload
	if err := json.Unmarshal([]byte(job.Result), &result); err != nil {
		return nil, "", fmt.Errorf("failed to parse result: %v", err)
	}

	var vulns []osv.OSVVulnerability
	if osvClient != nil && (forceOSV || osv.IsEnabled()) {
		vulns = osvClient.EnrichComponents(ctx, result.Data.SBOMComponents)
	}

	return exportCycloneDX(job, &result, vulns)
}

// cycloneDXComponent maps a single evidence-bearing models.SBOMComponent into a
// CycloneDX 1.6 component object, preserving the full identity/occurrence
// evidence graph, hashes and purl. Empty optional sections are omitted so the
// output stays schema-clean.
func cycloneDXComponent(c models.SBOMComponent) map[string]interface{} {
	comp := map[string]interface{}{
		"type":    c.Type,
		"bom-ref": c.BomRef,
		"name":    c.Name,
	}
	if c.Version != "" {
		comp["version"] = c.Version
	}
	if c.Group != "" {
		comp["group"] = c.Group
	}
	if c.Scope != "" {
		comp["scope"] = c.Scope
	}
	if c.Purl != "" {
		comp["purl"] = c.Purl
	}

	if len(c.Hashes) > 0 {
		hashes := make([]map[string]string, 0, len(c.Hashes))
		for _, h := range c.Hashes {
			hashes = append(hashes, map[string]string{
				"alg":     h.Alg,
				"content": h.Content,
			})
		}
		comp["hashes"] = hashes
	}

	evidence := map[string]interface{}{}

	if len(c.Evidence.Identity) > 0 {
		identities := make([]map[string]interface{}, 0, len(c.Evidence.Identity))
		for _, id := range c.Evidence.Identity {
			methods := make([]map[string]interface{}, 0, len(id.Methods))
			for _, m := range id.Methods {
				methods = append(methods, map[string]interface{}{
					"technique":  m.Technique,
					"confidence": m.Confidence,
					"value":      m.Value,
				})
			}
			identity := map[string]interface{}{
				"field":      id.Field,
				"confidence": id.Confidence,
				"methods":    methods,
			}
			if id.ConcludedValue != "" {
				identity["concludedValue"] = id.ConcludedValue
			}
			identities = append(identities, identity)
		}
		evidence["identity"] = identities
	}

	if len(c.Evidence.Occurrences) > 0 {
		occurrences := make([]map[string]interface{}, 0, len(c.Evidence.Occurrences))
		for _, o := range c.Evidence.Occurrences {
			occurrences = append(occurrences, map[string]interface{}{
				"location": o.Location,
			})
		}
		evidence["occurrences"] = occurrences
	}

	if len(evidence) > 0 {
		comp["evidence"] = evidence
	}

	return comp
}

// exportJSON exports results as JSON (lossless raw round-trip via map).
func exportJSON(resultData map[string]interface{}) ([]byte, string, error) {
	data, err := json.MarshalIndent(resultData, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal JSON: %v", err)
	}
	return data, "application/json", nil
}

// exportCSV exports results as CSV with job-metadata header rows followed by
// per-finding rows. Field values are read directly from typed structs.
func exportCSV(job *models.ScanJob, result *scanResultPayload) ([]byte, string, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Job metadata header.
	if err := writer.Write([]string{"Job ID", "Status", "Original Filename", "Created At", "Completed At"}); err != nil {
		return nil, "", fmt.Errorf("failed to write CSV header: %v", err)
	}

	completedAt := ""
	if job.CompletedAt != nil {
		completedAt = job.CompletedAt.Format(time.RFC3339)
	}
	if err := writer.Write([]string{
		job.ID,
		string(job.Status),
		job.OriginalFilename,
		job.CreatedAt.Format(time.RFC3339),
		completedAt,
	}); err != nil {
		return nil, "", fmt.Errorf("failed to write CSV row: %v", err)
	}

	// Secret findings — only emitted when present.
	if len(result.Data.Secrets) > 0 {
		if err := writer.Write([]string{"Type", "Line No", "File Location", "Secret Type", "Secret String", "Confidence"}); err != nil {
			return nil, "", fmt.Errorf("failed to write secrets header: %v", err)
		}
		for _, s := range result.Data.Secrets {
			if err := writer.Write([]string{
				s.Type,
				fmt.Sprintf("%d", s.LineNo),
				s.FileLocation,
				s.SecretType,
				s.SecretString,
				s.SecretConfidence,
			}); err != nil {
				log.Warnf("Failed to write secret row: %v", err)
				continue
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, "", fmt.Errorf("CSV flush error: %v", err)
	}
	return []byte(buf.String()), "text/csv", nil
}

// exportPDF generates a minimal but valid %PDF-1.4 single-page document
// containing the scan report. The PDF is hand-built using only stdlib
// (no external dependency), satisfying the Content-Type: application/pdf
// contract without lying about the payload type (EXPORT-1).
//
// Text is rendered with 10pt Helvetica on a US-Letter page (612×792pt).
// Lines that extend below the bottom margin are clipped by the viewer;
// the file structure remains spec-valid.
func exportPDF(job *models.ScanJob, result *scanResultPayload) ([]byte, string, error) {
	lines := []string{
		"MORF Scan Report",
		"================",
		"",
		"Job ID: " + job.ID,
		"Status: " + string(job.Status),
		"Original Filename: " + job.OriginalFilename,
		"Created At: " + job.CreatedAt.Format(time.RFC3339),
	}
	if job.CompletedAt != nil {
		lines = append(lines, "Completed At: "+job.CompletedAt.Format(time.RFC3339))
	}
	lines = append(lines,
		"",
		fmt.Sprintf("Package: %s  Version: %s", result.Data.PackageName, result.Data.Version),
		fmt.Sprintf("Secrets found: %d", result.Data.SecretCount),
	)
	if len(result.Data.Secrets) > 0 {
		lines = append(lines, "", "Findings:")
		for i, s := range result.Data.Secrets {
			lines = append(lines, fmt.Sprintf("  [%d] %s (%s) in %s line %d",
				i+1, s.SecretType, s.SecretConfidence, s.FileLocation, s.LineNo))
		}
	}

	return buildMinimalPDF(lines), "application/pdf", nil
}

// pdfEscapeString returns s encoded for use inside a PDF literal string
// (parentheses delimiter). Non-ASCII and control characters are dropped;
// (, ), and \ are backslash-escaped per PDF Reference §3.2.3.
func pdfEscapeString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r <= 0x7E: // printable ASCII only
			b.WriteRune(r)
		}
	}
	return b.String()
}

// buildMinimalPDF constructs a valid %PDF-1.4 document containing a single
// page with the given text lines. Object layout:
//
//	1: Catalog  2: Pages  3: Page  4: Content stream  5: Font (Helvetica)
//
// Byte offsets for each object are tracked precisely for the cross-reference
// table so any conforming PDF reader can locate objects directly.
func buildMinimalPDF(lines []string) []byte {
	const (
		fontSizePt = 10
		leadingPt  = 14  // line-to-line spacing in points
		startX     = 72  // left margin (~1 inch)
		startY     = 720 // top of text area (US Letter = 792pt; ~1 inch top margin)
	)

	// Build the page content stream using BT/ET text block operators.
	// T* moves to the start of the next line (equivalent to 0 -TL Td).
	var cs strings.Builder
	cs.WriteString("BT\n")
	fmt.Fprintf(&cs, "/F1 %d Tf\n", fontSizePt)
	fmt.Fprintf(&cs, "%d TL\n", leadingPt)
	fmt.Fprintf(&cs, "%d %d Td\n", startX, startY)
	for _, line := range lines {
		fmt.Fprintf(&cs, "(%s) Tj T*\n", pdfEscapeString(line))
	}
	cs.WriteString("ET\n")
	csBytes := []byte(cs.String())

	// Assemble PDF body, recording the byte offset of each object start
	// for the cross-reference table.
	var buf bytes.Buffer
	offsets := make([]int, 5) // indices 0..4 correspond to objects 1..5

	buf.WriteString("%PDF-1.4\n")

	offsets[0] = buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	offsets[1] = buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	offsets[2] = buf.Len()
	buf.WriteString("3 0 obj\n" +
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]" +
		" /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n" +
		"endobj\n")

	offsets[3] = buf.Len()
	fmt.Fprintf(&buf, "4 0 obj\n<< /Length %d >>\nstream\n", len(csBytes))
	buf.Write(csBytes)
	buf.WriteString("endstream\nendobj\n")

	offsets[4] = buf.Len()
	buf.WriteString("5 0 obj\n" +
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica" +
		" /Encoding /WinAnsiEncoding >>\n" +
		"endobj\n")

	// Cross-reference table: 6 entries (free entry 0 plus objects 1..5).
	// Each entry is exactly 20 bytes: 10-digit offset, space, 5-digit
	// generation, space, status flag, space, LF.
	xrefOffset := buf.Len()
	buf.WriteString("xref\n0 6\n")
	buf.WriteString("0000000000 65535 f \n") // entry 0: always free
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}

	// Trailer.
	fmt.Fprintf(&buf, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n", xrefOffset)
	buf.WriteString("%%EOF\n")

	return buf.Bytes()
}
