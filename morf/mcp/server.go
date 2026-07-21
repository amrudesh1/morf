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
