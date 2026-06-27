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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"morf/models"
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
	ExportFormatCycloneDX ExportFormat = "cyclonedx" // SBOM (CycloneDX 1.5 JSON)
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
	// exportCycloneDX consumes it as library components.
	UsesLibrary []string `json:"usesLibrary,omitempty"`
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
	case ExportFormatCycloneDX:
		return exportCycloneDX(job, &result)
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

// exportCycloneDX exports a minimal CycloneDX 1.5 JSON SBOM derived from the
// APK's metadata (package, version, libraries). This isn't a full mobile-SBOM
// (no transitive dependency graph), but it's enough for downstream supply-
// chain tooling to ingest MORF output.
func exportCycloneDX(job *models.ScanJob, result *scanResultPayload) ([]byte, string, error) {
	pkg := result.Data.PackageName
	version := result.Data.Version

	if pkg == "" {
		pkg = job.OriginalFilename
	}

	components := make([]map[string]interface{}, 0, len(result.Data.UsesLibrary))
	for _, lib := range result.Data.UsesLibrary {
		if lib != "" {
			components = append(components, map[string]interface{}{
				"type":    "library",
				"name":    lib,
				"bom-ref": "lib:" + lib,
			})
		}
	}

	bom := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"version":      1,
		"serialNumber": "urn:uuid:" + job.ID,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]string{
				{"vendor": "MORF", "name": "morf", "version": "1.0"},
			},
			"component": map[string]interface{}{
				"type":    "application",
				"name":    pkg,
				"version": version,
				"bom-ref": "app:" + pkg,
			},
		},
		"components": components,
	}

	out, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal CycloneDX: %v", err)
	}
	return out, "application/vnd.cyclonedx+json", nil
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
