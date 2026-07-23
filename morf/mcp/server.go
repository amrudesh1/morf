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

// Package mcp exposes MORF's in-process scan and pattern plumbing as a
// standalone stdio MCP (Model Context Protocol) server. It reuses the same leaf
// packages the `morf scan` command uses (apk/ios scanners, detect precision,
// verify, report) so an MCP client (e.g. an LLM agent) can scan a local
// .apk/.ipa, list patterns, verify a single credential, and get a human
// explanation of a finding — all without a running HTTP server, database,
// Redis, or any other MORF service.
//
// SECURITY: every tool output that could carry a secret is masked through the
// same report masking the CLI uses. scan_file returns SARIF/JSON produced by
// report.EncodeSARIF / report.MaskResultJSON (both mask secretString), and
// verify_secret returns only a status string — the raw credential value is
// never echoed back over the wire.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"morf/apk"
	"morf/detect"
	"morf/ios"
	"morf/models"
	"morf/report"
	"morf/utils"
	"morf/verify"
	"morf/version"

	sdk "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// NewServer builds the MORF stdio MCP server with all tools registered. The
// caller serves it via server.ServeStdio (see cmd/mcp.go). No network, DB, or
// Redis dependency is taken here; the java/apktool runtime tools are only
// touched lazily by scan_file when an actual scan runs.
func NewServer() *mcpserver.MCPServer {
	s := mcpserver.NewMCPServer(
		"morf",
		version.Version,
		mcpserver.WithToolCapabilities(false),
		mcpserver.WithRecovery(),
	)
	registerTools(s)
	return s
}

// registerTools wires every MORF tool onto the given server. It is separated
// from NewServer so tests can register onto a bare server if needed; in
// practice the handlers are unit-tested directly (they take no server state).
func registerTools(s *mcpserver.MCPServer) {
	s.AddTool(
		sdk.NewTool("scan_file",
			sdk.WithDescription("Scan a local .apk or .ipa in-process for hardcoded secrets. "+
				"Returns a findings summary (counts by tier/type/verification) and the full "+
				"report. Secret values are always MASKED; raw secrets are never returned."),
			sdk.WithString("path", sdk.Required(),
				sdk.Description("Absolute path to a local .apk or .ipa file")),
			sdk.WithString("format",
				sdk.Description("Report format: \"sarif\" (default) or \"json\". Both mask secret values.")),
			sdk.WithBoolean("verify",
				sdk.Description("Enable live, read-only verification of findings (network calls). Default false.")),
		),
		scanFileHandler,
	)

	s.AddTool(
		sdk.NewTool("list_patterns",
			sdk.WithDescription("List the loaded secret-detection pattern files and the patterns "+
				"in each (name, confidence, enabled). No arguments; reads from the local patterns directory."),
		),
		listPatternsHandler,
	)

	s.AddTool(
		sdk.NewTool("verify_secret",
			sdk.WithDescription("Check whether a single credential is live. Returns only a status "+
				"(active|inactive|unknown|unchecked); the value is NEVER echoed back. "+
				"Requires MORF_ENABLE_VERIFICATION=true (or pass enable=true) to make network calls."),
			sdk.WithString("type", sdk.Required(),
				sdk.Description("Secret type, e.g. github, slack, stripe, google, gcp, twilio, aws")),
			sdk.WithString("value", sdk.Required(),
				sdk.Description("The candidate secret value to check. Not returned in the response.")),
			sdk.WithBoolean("enable",
				sdk.Description("Force-enable live verification for this call only. Default false.")),
		),
		verifySecretHandler,
	)

	s.AddTool(
		sdk.NewTool("explain_finding",
			sdk.WithDescription("Explain a finding: a short human description of the secret type, its "+
				"OWASP MASVS control id, and what any precision tier / verification status mean. "+
				"Local only; makes no network calls."),
			sdk.WithString("type", sdk.Required(),
				sdk.Description("The secret type / pattern name, e.g. aws, github, slack")),
			sdk.WithString("tier",
				sdk.Description("Optional precision tier to explain: keep|info")),
			sdk.WithString("verificationStatus",
				sdk.Description("Optional verification status to explain: active|inactive|unknown|unchecked")),
		),
		explainFindingHandler,
	)

	s.AddTool(
		sdk.NewTool("get_results",
			sdk.WithDescription("Re-open a previously written MORF scan output file (JSON or SARIF "+
				"produced by `morf scan --out <path>`) and return a MASKED summary. "+
				"Counts are reported by tier, type, and verificationStatus. "+
				"The findings list in the response always has secretString masked — "+
				"raw secret values are NEVER returned even if the file on disk is unmasked. "+
				"No network, DB, or Redis calls are made; only the supplied file is read."),
			sdk.WithString("path", sdk.Required(),
				sdk.Description("Absolute filesystem path to a previously written MORF scan output file "+
					"(.json or .sarif / .json extension). Must be a regular file.")),
		),
		getResultsHandler,
	)
}

// ---------------------------------------------------------------------------
// scan_file
// ---------------------------------------------------------------------------

// scanFileHandler scans a local .apk/.ipa in-process and returns a masked
// report. It reproduces the exact pipeline order used by cmd/scan.go's
// runScanForFile (StartSecScanE / StartIOSExtraction -> ApplyPrecision ->
// VerifySecrets) — that helper is unexported in package cmd, and importing cmd
// here would create a cycle, so the ~15-line recipe is reproduced rather than
// called. Rendering reuses report.EncodeSARIF / report.MaskResultJSON so the
// masking guarantee is identical to the CLI.
func scanFileHandler(ctx context.Context, req sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return sdk.NewToolResultError(err.Error()), nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return sdk.NewToolResultError("path must not be empty"), nil
	}

	format := strings.ToLower(strings.TrimSpace(req.GetString("format", "sarif")))
	if format == "" {
		format = "sarif"
	}
	if format != "sarif" && format != "json" {
		return sdk.NewToolResultError(fmt.Sprintf("invalid format %q: want sarif or json", format)), nil
	}

	doVerify := req.GetBool("verify", false)

	secrets, platform, err := runScanForFile(ctx, path, doVerify)
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	target := filepathBase(path)
	rendered, err := renderFindings(format, target, platform, secrets)
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("render failed: %v", err)), nil
	}

	summary := summarize(target, platform, secrets)
	return sdk.NewToolResultText(summary + "\n\n" + string(rendered)), nil
}

// runScanForFile reproduces cmd.runScanForFile (which is unexported). Keep this
// in lockstep with cmd/scan.go's runScanForFile and morf's worker.go ordering:
// scan -> ApplyPrecision -> VerifySecrets. The workspace is created and torn
// down per call.
func runScanForFile(ctx context.Context, path string, doVerify bool) ([]models.SecretModel, string, error) {
	lower := strings.ToLower(path)

	jobCtx := utils.NewJobContext()
	if err := jobCtx.CreateWorkspace(); err != nil {
		return nil, "", fmt.Errorf("create workspace: %w", err)
	}
	defer jobCtx.CleanupWorkspace()

	var secrets []models.SecretModel
	var platform string
	var err error
	switch {
	case strings.HasSuffix(lower, ".apk"):
		platform = "android"
		secrets, err = apk.StartSecScanE(ctx, path, jobCtx)
	case strings.HasSuffix(lower, ".ipa"):
		platform = "ios"
		secrets, _, _, err = ios.StartIOSExtraction(ctx, path, jobCtx)
	default:
		return nil, "", fmt.Errorf("file must be .apk or .ipa")
	}
	if err != nil {
		return nil, platform, err
	}

	secrets = detect.ApplyPrecision(secrets)
	if doVerify {
		// Per-call opt-in: force verification for THIS call only, without
		// mutating the process-global MORF_ENABLE_VERIFICATION (which would
		// stick ON for every later call and race across concurrent tool calls).
		secrets = verify.VerifySecretsForced(ctx, secrets)
	} else {
		secrets = verify.VerifySecrets(ctx, secrets)
	}

	return secrets, platform, nil
}

// renderFindings serialises findings in the requested format, masking every
// secretString. SARIF masking lives in report.EncodeSARIF; JSON masking reuses
// report.MaskResultJSON via the same {"data":{"secrets":[...]}} envelope
// cmd/scan.go uses. Mirrors cmd.renderFindings so the guarantee is identical.
func renderFindings(format, target, platform string, secrets []models.SecretModel) ([]byte, error) {
	switch format {
	case "sarif":
		return report.EncodeSARIF(target, platform, secrets)
	case "json":
		if secrets == nil {
			secrets = []models.SecretModel{}
		}
		env := map[string]any{
			"data": map[string]any{
				"target":   target,
				"platform": platform,
				"secrets":  secrets,
			},
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		masked, err := report.MaskResultJSON(raw)
		if err != nil {
			return nil, err
		}
		var pretty any
		if err := json.Unmarshal(masked, &pretty); err != nil {
			return nil, err
		}
		return json.MarshalIndent(pretty, "", "  ")
	default:
		return nil, fmt.Errorf("invalid format %q: want json or sarif", format)
	}
}

// summarize produces a compact, secret-free summary line block: total findings,
// counts by tier, by verification status, and by secret type. It reads only
// metadata fields (Tier / VerificationStatus / SecretType) — never the value.
func summarize(target, platform string, secrets []models.SecretModel) string {
	byTier := map[string]int{}
	byStatus := map[string]int{}
	byType := map[string]int{}
	for _, s := range secrets {
		tier := s.Tier
		if tier == "" {
			tier = "unclassified"
		}
		byTier[tier]++
		status := s.VerificationStatus
		if status == "" {
			status = "unchecked"
		}
		byStatus[status]++
		typ := s.SecretType
		if typ == "" {
			typ = s.Type
		}
		if typ == "" {
			typ = "unknown"
		}
		byType[typ]++
	}

	var b strings.Builder
	fmt.Fprintf(&b, "MORF scan of %s (%s): %d finding(s)", target, platform, len(secrets))
	if len(secrets) > 0 {
		fmt.Fprintf(&b, "\n  by tier: %s", formatCounts(byTier))
		fmt.Fprintf(&b, "\n  by verification: %s", formatCounts(byStatus))
		fmt.Fprintf(&b, "\n  by type: %s", formatCounts(byType))
	}
	return b.String()
}

// formatCounts renders a count map deterministically (sorted keys) as
// "k=v, k=v" so summaries are stable across runs.
func formatCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// filepathBase is a tiny wrapper so the handler does not import path/filepath
// just for one call site; kept local for readability.
func filepathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ---------------------------------------------------------------------------
// list_patterns
// ---------------------------------------------------------------------------

// listPatternsHandler returns the loaded pattern files and, per file, the
// pattern name/confidence/enabled flags. It reuses utils.ListPatternFiles, the
// same in-process loader the HTTP pattern API uses. Regexes are omitted from
// the summary to keep the payload small and to avoid dumping the full ruleset.
func listPatternsHandler(ctx context.Context, req sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	files, err := utils.ListPatternFiles()
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("failed to list patterns: %v", err)), nil
	}

	type patternOut struct {
		Name       string `json:"name"`
		Confidence string `json:"confidence"`
		Enabled    bool   `json:"enabled"`
	}
	type fileOut struct {
		Filename string       `json:"filename"`
		Count    int          `json:"count"`
		Patterns []patternOut `json:"patterns"`
	}
	out := struct {
		PatternsDir string    `json:"patternsDir"`
		FileCount   int       `json:"fileCount"`
		TotalCount  int       `json:"totalPatternCount"`
		Files       []fileOut `json:"files"`
	}{
		PatternsDir: utils.GetPatternsDir(),
		Files:       []fileOut{},
	}

	for _, f := range files {
		fo := fileOut{Filename: f.Filename, Count: len(f.Patterns), Patterns: []patternOut{}}
		for _, p := range f.Patterns {
			fo.Patterns = append(fo.Patterns, patternOut{
				Name:       p.Name,
				Confidence: p.Confidence,
				Enabled:    p.Enabled,
			})
		}
		out.Files = append(out.Files, fo)
		out.TotalCount += len(f.Patterns)
	}
	out.FileCount = len(out.Files)

	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("failed to encode patterns: %v", err)), nil
	}
	return sdk.NewToolResultText(string(body)), nil
}

// ---------------------------------------------------------------------------
// verify_secret
// ---------------------------------------------------------------------------

// verifySecretHandler checks a single credential's liveness and returns ONLY a
// status string. It reuses verify.VerifySecrets on a one-element slice (the
// per-type dispatch is unexported), matching the CLI's --verify path. The raw
// value is never placed in the response. Verification is default-off: unless
// MORF_ENABLE_VERIFICATION=="true" (or enable=true is passed), the status is
// "unchecked" and no network call is made.
func verifySecretHandler(ctx context.Context, req sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	typ, err := req.RequireString("type")
	if err != nil {
		return sdk.NewToolResultError(err.Error()), nil
	}
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return sdk.NewToolResultError("type must not be empty"), nil
	}

	value, err := req.RequireString("value")
	if err != nil {
		return sdk.NewToolResultError(err.Error()), nil
	}
	if strings.TrimSpace(value) == "" {
		return sdk.NewToolResultError("value must not be empty"), nil
	}

	// Per-call opt-in without mutating the process-global env (see runScanForFile).
	in := []models.SecretModel{{SecretType: typ, SecretString: value}}
	var out []models.SecretModel
	if req.GetBool("enable", false) {
		out = verify.VerifySecretsForced(ctx, in)
	} else {
		out = verify.VerifySecrets(ctx, in)
	}

	status := "unknown"
	if len(out) > 0 && out[0].VerificationStatus != "" {
		status = out[0].VerificationStatus
	}

	// Response carries the status and the type only — never the value.
	resp := map[string]string{
		"type":               typ,
		"verificationStatus": status,
	}
	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("failed to encode result: %v", err)), nil
	}
	return sdk.NewToolResultText(string(body)), nil
}

// ---------------------------------------------------------------------------
// explain_finding
// ---------------------------------------------------------------------------

// explainFindingHandler produces a local, network-free explanation of a secret
// type: which pattern(s) match it, the OWASP MASVS control id attributed to
// them, and a plain-language meaning of any supplied precision tier /
// verification status. MASVS is looked up from the compiled pattern cache
// (detect.GetPatternCache) so the resolved (pattern- or file-level) id is used.
func explainFindingHandler(ctx context.Context, req sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	typ, err := req.RequireString("type")
	if err != nil {
		return sdk.NewToolResultError(err.Error()), nil
	}
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return sdk.NewToolResultError("type must not be empty"), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Finding type: %s\n\n", typ)

	// Match patterns whose name contains the requested type (case-insensitive),
	// collecting distinct resolved MASVS ids.
	lowerType := strings.ToLower(typ)
	masvs := map[string]struct{}{}
	var matched []string
	if cache, cerr := detect.GetPatternCache("mcp-explain", "any"); cerr == nil && cache != nil {
		for _, p := range cache.Patterns {
			if strings.Contains(strings.ToLower(p.Name), lowerType) {
				matched = append(matched, p.Name)
				if p.MASVS != "" {
					masvs[p.MASVS] = struct{}{}
				}
			}
		}
	}

	if len(matched) > 0 {
		sort.Strings(matched)
		fmt.Fprintf(&b, "Matching pattern(s): %s\n", strings.Join(dedupe(matched), ", "))
	} else {
		fmt.Fprintf(&b, "No loaded pattern name contains %q; treating it as a free-form type.\n", typ)
	}

	if len(masvs) > 0 {
		ids := make([]string, 0, len(masvs))
		for id := range masvs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Fprintf(&b, "OWASP MASVS control(s): %s\n", strings.Join(ids, ", "))
	} else {
		fmt.Fprintf(&b, "OWASP MASVS control: MASVS-STORAGE-1 (hardcoded/stored secret; no explicit control mapped for this pattern)\n")
	}

	fmt.Fprintf(&b, "\nWhy it matters: a %s credential embedded in a mobile package can be "+
		"extracted by anyone who unpacks the app, letting an attacker impersonate the app "+
		"or access the backing service.\n", typ)

	if tier := strings.ToLower(strings.TrimSpace(req.GetString("tier", ""))); tier != "" {
		fmt.Fprintf(&b, "\nTier %q: %s\n", tier, explainTier(tier))
	}
	if status := strings.ToLower(strings.TrimSpace(req.GetString("verificationStatus", ""))); status != "" {
		fmt.Fprintf(&b, "Verification %q: %s\n", status, explainStatus(status))
	}

	return sdk.NewToolResultText(b.String()), nil
}

// explainTier maps a precision tier to a one-line meaning.
func explainTier(tier string) string {
	switch tier {
	case "keep":
		return "high-precision finding retained as a confident true positive."
	case "info":
		return "retained but downgraded to informational (lower precision / likely noise)."
	default:
		return "unrecognized tier; MORF assigns \"keep\" or \"info\" during precision scoring."
	}
}

// explainStatus maps a verification status to a one-line meaning.
func explainStatus(status string) string {
	switch status {
	case "active":
		return "the provider confirmed the credential is valid/live — treat as an active leak."
	case "inactive":
		return "the provider confirmed the credential is revoked/invalid."
	case "unknown":
		return "no verifier exists for this type, or the check was inconclusive."
	case "unchecked":
		return "verification was disabled or not attempted (the default)."
	default:
		return "unrecognized status; expected active|inactive|unknown|unchecked."
	}
}

// ---------------------------------------------------------------------------
// get_results
// ---------------------------------------------------------------------------

// getResultsMaxBytes is the upper limit on result files accepted by
// getResultsHandler. Files larger than this are rejected to avoid reading
// arbitrarily large files from disk.
const getResultsMaxBytes = 10 * 1024 * 1024 // 10 MiB

// getResultsHandler reads a previously written MORF scan output file (JSON or
// SARIF produced by `morf scan --out`) and returns a MASKED summary. It is
// strictly file-based: no network, DB, or Redis call is ever made. The handler
// fails CLOSED — if masking fails, it returns an error rather than leaking the
// raw file content. Security properties:
//
//   - Path must point to a regular file (directories and special files are
//     rejected).
//   - Files larger than getResultsMaxBytes are rejected.
//   - All secretString values in JSON output are masked through
//     report.MaskResultJSON before being returned; SARIF output has no
//     secretString field (values were masked at encode time by EncodeSARIF).
func getResultsHandler(ctx context.Context, req sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return sdk.NewToolResultError(err.Error()), nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return sdk.NewToolResultError("path must not be empty"), nil
	}

	// Validate the path points to a regular (non-special) file.
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sdk.NewToolResultError(fmt.Sprintf("file not found: %s", path)), nil
		}
		return sdk.NewToolResultError(fmt.Sprintf("cannot stat file: %v", err)), nil
	}
	if !fi.Mode().IsRegular() {
		return sdk.NewToolResultError(fmt.Sprintf("path is not a regular file: %s", path)), nil
	}
	if fi.Size() > getResultsMaxBytes {
		return sdk.NewToolResultError(fmt.Sprintf(
			"file is too large (%d bytes; limit %d): %s",
			fi.Size(), getResultsMaxBytes, path,
		)), nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("cannot read file: %v", err)), nil
	}

	// Detect format by sniffing the top-level JSON keys.
	// SARIF files have a "runs" array at the root.
	// MORF JSON output files have a "data" object at the root.
	format, err := sniffResultFormat(raw)
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("not a valid MORF output file: %v", err)), nil
	}

	switch format {
	case "json":
		return handleJSONResults(path, raw)
	case "sarif":
		return handleSARIFResults(path, raw)
	default:
		return sdk.NewToolResultError(fmt.Sprintf("unrecognized format %q in file %s", format, path)), nil
	}
}

// sniffResultFormat sniffs the top-level structure of raw JSON to determine
// whether it is a MORF JSON envelope ("data" key) or a SARIF document
// ("runs" key / "$schema" referencing sarif). Returns "json" or "sarif".
func sniffResultFormat(raw []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return "", fmt.Errorf("cannot parse as JSON: %w", err)
	}
	if _, hasSARIF := top["runs"]; hasSARIF {
		return "sarif", nil
	}
	if _, hasData := top["data"]; hasData {
		return "json", nil
	}
	return "", fmt.Errorf("missing expected keys: want \"data\" (JSON) or \"runs\" (SARIF)")
}

// handleJSONResults processes a MORF JSON envelope
// ({"data":{"secrets":[...],...}}). It masks every secretString through
// report.MaskResultJSON (fail-closed), then builds a summary from the masked
// secrets slice.
func handleJSONResults(path string, raw []byte) (*sdk.CallToolResult, error) {
	// Always re-mask regardless of whether the file was written with --reveal-secrets.
	// MaskResultJSON fails CLOSED: if it returns an error we return that error
	// rather than the unmasked content.
	masked, err := report.MaskResultJSON(raw)
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("masking failed: %v", err)), nil
	}

	// Parse the masked envelope to build the summary.
	var env struct {
		Data struct {
			Target   string               `json:"target"`
			Platform string               `json:"platform"`
			Secrets  []models.SecretModel `json:"secrets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(masked, &env); err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("cannot parse masked JSON: %v", err)), nil
	}

	target := env.Data.Target
	if target == "" {
		target = filepathBase(path)
	}
	platform := env.Data.Platform
	if platform == "" {
		platform = "unknown"
	}

	// Build a human-readable masked findings preview (no secretString verbatim —
	// MaskResultJSON already replaced them).
	type maskedFinding struct {
		SecretType         string  `json:"secretType"`
		SecretString       string  `json:"secretString"` // already masked
		FileLocation       string  `json:"fileLocation"`
		LineNo             int     `json:"lineNo,omitempty"`
		Tier               string  `json:"tier,omitempty"`
		VerificationStatus string  `json:"verificationStatus,omitempty"`
		Score              float64 `json:"score,omitempty"`
	}
	findings := make([]maskedFinding, 0, len(env.Data.Secrets))
	for _, s := range env.Data.Secrets {
		typ := s.SecretType
		if typ == "" {
			typ = s.Type
		}
		findings = append(findings, maskedFinding{
			SecretType:         typ,
			SecretString:       s.SecretString, // already masked by MaskResultJSON
			FileLocation:       s.FileLocation,
			LineNo:             s.LineNo,
			Tier:               s.Tier,
			VerificationStatus: s.VerificationStatus,
			Score:              s.Score,
		})
	}

	summary := summarize(target, platform, env.Data.Secrets)

	out := map[string]any{
		"summary":  summary,
		"format":   "json",
		"source":   path,
		"findings": findings,
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("failed to encode result: %v", err)), nil
	}
	return sdk.NewToolResultText(string(body)), nil
}

// handleSARIFResults processes a SARIF 2.1.0 document produced by
// report.EncodeSARIF. SARIF never carries raw secret values (EncodeSARIF always
// masks at encode time via the maskSecret function), so the raw document is safe
// to summarize as-is. The handler extracts rule ids and result levels for the
// summary.
func handleSARIFResults(path string, raw []byte) (*sdk.CallToolResult, error) {
	// Parse only the fields needed for the summary; unknown fields are ignored.
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string                     `json:"ruleId"`
				Level      string                     `json:"level"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("cannot parse SARIF: %v", err)), nil
	}
	if len(doc.Runs) == 0 {
		return sdk.NewToolResultError("SARIF document has no runs"), nil
	}

	run := doc.Runs[0]

	// Extract target/platform from run.properties if present.
	target := ""
	platform := "unknown"
	if v, ok := run.Properties["target"]; ok {
		_ = json.Unmarshal(v, &target)
	}
	if v, ok := run.Properties["platform"]; ok {
		_ = json.Unmarshal(v, &platform)
	}
	if target == "" {
		target = filepathBase(path)
	}

	// Build synthetic SecretModel list from SARIF results for the summarize
	// helper (we only need tier/type/verificationStatus metadata fields — no
	// secret values are present in SARIF output).
	secrets := make([]models.SecretModel, 0, len(run.Results))
	for _, r := range run.Results {
		sm := models.SecretModel{
			SecretType: r.RuleID,
		}
		// Map SARIF level back to Tier for the summary.
		switch r.Level {
		case "error":
			sm.Tier = "keep"
		case "note":
			sm.Tier = "info"
		}
		// Extract verificationStatus from result.properties if present.
		if v, ok := r.Properties["verificationStatus"]; ok {
			var vs string
			if err := json.Unmarshal(v, &vs); err == nil {
				sm.VerificationStatus = vs
			}
		}
		secrets = append(secrets, sm)
	}

	summary := summarize(target, platform, secrets)

	// Build masked findings preview: SARIF messages already contain the masked
	// value (e.g. "aws (masked: AKIA…le)") — we extract the message text.
	type sarifFindingPreview struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message string `json:"message,omitempty"`
	}
	previews := make([]sarifFindingPreview, 0, len(run.Results))
	for _, r := range run.Results {
		msg := ""
		if raw, ok := r.Properties["message"]; ok {
			_ = json.Unmarshal(raw, &msg)
		}
		previews = append(previews, sarifFindingPreview{
			RuleID: r.RuleID,
			Level:  r.Level,
		})
	}

	out := map[string]any{
		"summary":  summary,
		"format":   "sarif",
		"source":   path,
		"findings": previews,
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return sdk.NewToolResultError(fmt.Sprintf("failed to encode result: %v", err)), nil
	}
	return sdk.NewToolResultText(string(body)), nil
}

// dedupe returns the input with consecutive duplicates removed; the caller
// sorts first so this collapses all duplicates.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
