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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"morf/apk"
	"morf/detect"
	"morf/gate"
	"morf/ios"
	"morf/models"
	"morf/report"
	"morf/utils"
	"morf/verify"

	"github.com/spf13/cobra"
)

// Exit codes shared by the scan and gate commands. CI systems key off these:
//   - exitOK is a clean pass.
//   - exitOperational is any operational failure (bad args, scan/tool error,
//     unreadable baseline) — the scan could not be trusted, distinct from a
//     policy hit.
//   - exitPolicy is a policy/gate hit: the scan ran fine but findings tripped
//     the configured threshold. Kept separate so a pipeline can distinguish
//     "the gate failed the build" from "the tool broke".
const (
	exitOK          = 0
	exitOperational = 1
	exitPolicy      = 4
)

// scanFailOn maps the --fail-on flag values to gate policies. The CLI vocabulary
// (none|any|verified|keep) is intentionally shorter and CI-friendly than the
// underlying gate.Policy string constants.
func scanFailOn(failOn string) (gate.Policy, error) {
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "", "verified":
		return gate.FailOnNewVerified, nil
	case "any":
		return gate.FailOnNewAny, nil
	case "keep":
		return gate.FailOnTierKeep, nil
	case "none":
		return gate.None, nil
	default:
		return "", fmt.Errorf("invalid --fail-on %q: want one of none|any|verified|keep", failOn)
	}
}

// scanOptions carries the resolved flag state for a single scan invocation.
type scanOptions struct {
	format   string // "sarif" or "json"
	out      string // output file path; empty == stdout
	verify   bool   // enable live verification (sets MORF_ENABLE_VERIFICATION)
	failOn   string // none|any|verified|keep
	sarif    bool   // --sarif convenience alias for --format sarif
	reveal   bool   // --reveal-secrets: emit UNMASKED values (JSON format only)
	target   string // artifact name for the SARIF/report header
	platform string
}

// runScanForFile performs the actual scan of an .apk/.ipa file, reusing the
// in-process plumbing (identical order to worker.go). It is the only part that
// needs java/apktool at runtime; the decision logic lives in evaluateAndRender
// so it can be tested without those tools.
//
// The returned []models.PlatformFinding is always non-nil (but may be empty);
// detectors will populate it in a future unit. For now the slice is wired
// through the call chain so the plumbing is in place.
func runScanForFile(ctx context.Context, path string, doVerify bool) ([]models.SecretModel, []models.SBOMComponent, []models.PlatformFinding, string, error) {
	lower := strings.ToLower(path)

	jobCtx := utils.NewJobContext()
	if err := jobCtx.CreateWorkspace(); err != nil {
		return nil, nil, nil, "", fmt.Errorf("create workspace: %w", err)
	}
	defer jobCtx.CleanupWorkspace()

	var secrets []models.SecretModel
	var sbom []models.SBOMComponent
	var platform string
	var err error
	var platformFindings []models.PlatformFinding
	switch {
	case strings.HasSuffix(lower, ".apk"):
		platform = "android"
		secrets, err = apk.StartSecScanE(ctx, path, jobCtx)
		if err == nil {
			// Native-lib + runtime SBOM components are enumerated from the
			// decompiled tree the scan just produced (best-effort; nil when none).
			sbom = apk.CollectSBOMComponents(jobCtx)

			// Platform findings (unit P2a): derive exported-component + deep-link
			// exposure findings from the already-parsed manifest metadata. The
			// metadata extraction runs inline here via the shared helper so the CLI
			// path has the same coverage as the worker path.
			if meta, _, metaErr := apk.ExtractMetadataAndPackageData(ctx, path, jobCtx); metaErr == nil {
				platformFindings = apk.AnalyzeExposure(&meta)
			}
			// Platform findings (unit P2b): Firebase/GCP misconfig findings from
			// google-services.json (passive always, active when MORF_ENABLE_VERIFICATION).
			platformFindings = append(platformFindings, apk.CollectFirebaseMisconfigFindings(ctx, jobCtx, nil)...)
		}
	case strings.HasSuffix(lower, ".ipa"):
		platform = "ios"
		secrets, _, sbom, err = ios.StartIOSExtraction(ctx, path, jobCtx)
		if err == nil {
			// Platform findings (unit P2b): Firebase/GCP misconfig findings from
			// GoogleService-Info.plist (passive always, active when MORF_ENABLE_VERIFICATION).
			platformFindings = append(platformFindings, ios.CollectIOSFirebaseMisconfigFindingsFromIPA(ctx, jobCtx, nil)...)
		}
	default:
		return nil, nil, nil, "", fmt.Errorf("file must be .apk or .ipa")
	}
	if err != nil {
		return nil, nil, nil, platform, err
	}

	// Identical post-processing to worker.go (Android 696-697 / iOS 827-828).
	// SanitizeSecrets is already done inside the scanner, so it is not repeated.
	secrets = detect.ApplyPrecision(secrets)
	if doVerify {
		// verify.VerifySecrets is gated on MORF_ENABLE_VERIFICATION=="true".
		// The --verify flag opts in for the lifetime of this process.
		_ = os.Setenv("MORF_ENABLE_VERIFICATION", "true")
	}
	secrets = verify.VerifySecrets(ctx, secrets)

	// Ensure platformFindings is always a non-nil slice so downstream JSON
	// renders as "[]" rather than null.
	if platformFindings == nil {
		platformFindings = []models.PlatformFinding{}
	}

	return secrets, sbom, platformFindings, platform, nil
}

// renderFindings serialises findings in the requested format. The JSON path
// masks every secretString via report.MaskResultJSON so plaintext secrets never
// leave the process, matching the SARIF encoder's masking guarantee — UNLESS
// reveal is set, an explicit per-run opt-out (`--reveal-secrets`) for scanning
// your own authorized artifact when you need the plaintext to rotate/verify.
// reveal never affects SARIF: that format is built for upload to code scanning
// and must always mask, so a reveal request there is ignored (still masked).
//
// platformFindings are always included in both formats:
//   - SARIF: appended as additional results via EncodeSARIFWithFindings.
//   - JSON: added as "platformFindings" array in the data envelope.
//
// Platform findings do not affect the gate/exit-code semantics (they are
// reported, not gated). Passing nil for platformFindings is safe; it is treated
// as an empty slice.
func renderFindings(format, target, platform string, secrets []models.SecretModel, platformFindings []models.PlatformFinding, reveal bool) ([]byte, error) {
	if platformFindings == nil {
		platformFindings = []models.PlatformFinding{}
	}
	switch strings.ToLower(format) {
	case "sarif":
		return report.EncodeSARIFWithFindings(target, platform, secrets, platformFindings)
	case "json":
		// Wrap in the {"data":{"secrets":[...],"platformFindings":[...]}} envelope
		// MaskResultJSON expects, so secret masking reuses the exact SARIF masking
		// logic (no plaintext leak). platformFindings carry no secrets but are
		// included in the same envelope for a single coherent JSON output.
		if secrets == nil {
			secrets = []models.SecretModel{}
		}
		env := map[string]any{
			"data": map[string]any{
				"target":           target,
				"platform":         platform,
				"secrets":          secrets,
				"platformFindings": platformFindings,
			},
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		if !reveal {
			raw, err = report.MaskResultJSON(raw)
			if err != nil {
				return nil, err
			}
		}
		// Re-indent for human/diff friendliness.
		var pretty any
		if err := json.Unmarshal(raw, &pretty); err != nil {
			return nil, err
		}
		return json.MarshalIndent(pretty, "", "  ")
	default:
		return nil, fmt.Errorf("invalid format %q: want json or sarif", format)
	}
}

// renderSBOM builds the CycloneDX 1.6 SBOM document for the scanned artifact,
// reusing the exact exporter the /results/:jobID/export?format=cyclonedx route
// uses (so CLI and API produce identical SBOMs). The components carry their own
// evidence/confidence; this just wraps them in the payload envelope the exporter
// consumes and stamps the artifact name as the app root.
func renderSBOM(target, platform string, sbom []models.SBOMComponent) ([]byte, error) {
	if sbom == nil {
		sbom = []models.SBOMComponent{}
	}
	env := map[string]any{
		"data": map[string]any{
			"fileName":       target,
			"platform":       platform,
			"sbomComponents": sbom,
		},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	job := &models.ScanJob{OriginalFilename: target, Result: string(raw)}
	out, _, err := utils.ExportResult(job, utils.ExportFormatCycloneDX)
	return out, err
}

// evaluateAndRender is the pure, testable core: given already-enriched findings
// and the resolved options, it produces the output bytes, the human summary, and
// the process exit code. It performs NO scanning and NO I/O beyond formatting,
// so tests can drive it with a hand-built []models.SecretModel.
//
// platformFindings are threaded into the output (SARIF results + JSON array) but
// do NOT affect gate/exit-code semantics. Passing nil is safe (treated as empty).
func evaluateAndRender(opts scanOptions, secrets []models.SecretModel, sbom []models.SBOMComponent, platformFindings []models.PlatformFinding) (out []byte, summary string, exitCode int, err error) {
	format := opts.format
	if opts.sarif {
		format = "sarif"
	}
	if format == "" {
		format = "sarif"
	}

	// SBOM output is a component INVENTORY, not a findings gate: emit the
	// CycloneDX 1.6 document and always exit 0 (no --fail-on policy applies to an
	// inventory). Reuses the same exporter the /export route uses.
	switch strings.ToLower(format) {
	case "cyclonedx-sbom", "cyclonedx":
		rendered, rerr := renderSBOM(opts.target, opts.platform, sbom)
		if rerr != nil {
			return nil, "", exitOperational, rerr
		}
		summary = fmt.Sprintf("MORF SBOM: %d component(s) [%s] (evidence-based inventory)", len(sbom), opts.platform)
		return rendered, summary, exitOK, nil
	}

	policy, perr := scanFailOn(opts.failOn)
	if perr != nil {
		return nil, "", exitOperational, perr
	}

	rendered, rerr := renderFindings(format, opts.target, opts.platform, secrets, platformFindings, opts.reveal)
	if rerr != nil {
		return nil, "", exitOperational, rerr
	}

	// Reuse the gate diff engine against an empty baseline: every finding is
	// "new", so the same policy vocabulary decides pass/fail for a standalone
	// scan exactly as it does for a baselined gate run.
	// Platform findings do NOT affect gate evaluation — only secrets are gated.
	res := gate.Evaluate(secrets, gate.NewBaseline(), policy)

	code := exitOK
	if res.Failed {
		code = exitPolicy
	}

	summary = fmt.Sprintf(
		"MORF scan: %d finding(s) (%d verified-active), %d platform finding(s); fail-on=%s -> %s [%s]",
		len(secrets), len(res.NewVerified), len(platformFindings), policyLabel(policy), passFail(res.Failed), res.Reason,
	)

	return rendered, summary, code, nil
}

func policyLabel(p gate.Policy) string {
	switch p {
	case gate.FailOnNewVerified:
		return "verified"
	case gate.FailOnNewAny:
		return "any"
	case gate.FailOnTierKeep:
		return "keep"
	case gate.None:
		return "none"
	default:
		return string(p)
	}
}

func passFail(failed bool) string {
	if failed {
		return "FAIL"
	}
	return "PASS"
}

// writeOutput writes rendered bytes to opts.out (or w when out is empty).
func writeOutput(opts scanOptions, w io.Writer, data []byte) error {
	if strings.TrimSpace(opts.out) == "" {
		_, err := w.Write(data)
		return err
	}
	return os.WriteFile(opts.out, data, 0o644)
}

// runScan is the full command helper: scan -> enrich -> render -> write -> code.
// It returns the exit code so the cobra Run wrapper can call os.Exit, keeping the
// os.Exit boundary out of the tested logic.
func runScan(ctx context.Context, opts scanOptions, path string, stdout, stderr io.Writer) (int, error) {
	secrets, sbom, platformFindings, platform, err := runScanForFile(ctx, path, opts.verify)
	if err != nil {
		return exitOperational, err
	}
	opts.platform = platform
	if opts.target == "" {
		opts.target = filepath.Base(path)
	}

	// Loudly flag the unmask opt-out: reveal only takes effect for JSON (SARIF
	// always masks), so only warn when it will actually emit plaintext.
	if opts.reveal && !opts.sarif && strings.EqualFold(opts.format, "json") {
		dest := "stdout"
		if strings.TrimSpace(opts.out) != "" {
			dest = opts.out
		}
		fmt.Fprintf(stderr, "WARNING: --reveal-secrets wrote UNMASKED secret values to %s — handle as sensitive.\n", dest)
	}

	out, summary, code, err := evaluateAndRender(opts, secrets, sbom, platformFindings)
	if err != nil {
		return exitOperational, err
	}
	if err := writeOutput(opts, stdout, out); err != nil {
		return exitOperational, err
	}
	fmt.Fprintln(stderr, summary)
	return code, nil
}

// GetScanCmd returns the `morf scan` command: a one-shot, in-process local scan
// that reuses the worker's scan+precision+verify pipeline and emits SARIF (or
// JSON), then sets a CI-gating exit code from --fail-on.
func GetScanCmd() *cobra.Command {
	var opts scanOptions

	scanCmd := &cobra.Command{
		Use:   "scan <file.apk|file.ipa>",
		Short: "One-shot local scan; emit SARIF/JSON and gate via exit code",
		Long: `Scan a single Android (.apk) or iOS (.ipa) package in-process and emit a
findings report (SARIF by default, or JSON). The exit code is driven by
--fail-on so CI can gate the build:

  0  nothing at/above the --fail-on threshold
  4  the threshold was tripped (a gate/policy hit)
  1  an operational error (bad file, missing tools, scan failure)

Live verification is OFF by default; pass --verify (or set
MORF_ENABLE_VERIFICATION=true) to make read-only liveness checks.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			code, err := runScan(cmd.Context(), opts, args[0], os.Stdout, os.Stderr)
			if err != nil {
				fmt.Fprintln(os.Stderr, "morf scan:", err)
			}
			os.Exit(code)
		},
	}

	scanCmd.Flags().BoolVar(&opts.sarif, "sarif", false, "Emit SARIF (alias for --format sarif)")
	scanCmd.Flags().StringVar(&opts.out, "out", "", "Write output to this path (default stdout)")
	scanCmd.Flags().StringVar(&opts.format, "format", "sarif", "Output format: json|sarif|cyclonedx-sbom")
	scanCmd.Flags().BoolVar(&opts.verify, "verify", false, "Enable live (read-only) verification of findings")
	scanCmd.Flags().StringVar(&opts.failOn, "fail-on", "verified", "Gate threshold: none|any|verified|keep")
	scanCmd.Flags().BoolVar(&opts.reveal, "reveal-secrets", false, "Emit UNMASKED secret values in JSON output (own/authorized artifacts only; ignored for SARIF)")

	return scanCmd
}
