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
	"strings"

	"morf/gate"
	"morf/models"

	"github.com/spf13/cobra"
)

// allowOptions carries the resolved flag state for a single gate-allow
// invocation.
type allowOptions struct {
	baseline     string   // path to the baseline JSON (required)
	fingerprints []string // --allow-fingerprint values (repeatable, comma-ok)
	types        []string // --allow-type values (repeatable, comma-ok)
}

// splitComma splits a slice of potentially comma-separated tokens into a flat
// deduplicated slice of non-empty trimmed strings. This supports both the
// --flag v1 --flag v2 and --flag v1,v2 invocation styles.
func splitComma(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		for _, tok := range strings.Split(s, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if _, dup := seen[tok]; !dup {
				seen[tok] = struct{}{}
				out = append(out, tok)
			}
		}
	}
	return out
}

// runGateAllow loads the baseline at opts.baseline (creating an empty one when
// the file does not yet exist), adds the specified fingerprints / types to the
// allowlists, and persists the result. It returns the number of entries added
// and the path, which the caller can echo to stderr.
func runGateAllow(opts allowOptions, stderr io.Writer) error {
	if strings.TrimSpace(opts.baseline) == "" {
		return fmt.Errorf("--baseline <path> is required for gate allow")
	}

	fps := splitComma(opts.fingerprints)
	typs := splitComma(opts.types)
	if len(fps) == 0 && len(typs) == 0 {
		return fmt.Errorf("gate allow: at least one --allow-fingerprint or --allow-type is required")
	}

	base, err := loadBaselineOrEmpty(opts.baseline)
	if err != nil {
		return err
	}

	added := 0
	for _, fp := range fps {
		before := len(base.AllowedFingerprints)
		base.Allow(fp)
		if len(base.AllowedFingerprints) > before {
			added++
		}
	}
	for _, t := range typs {
		before := len(base.AllowedTypes)
		base.AllowType(t)
		if len(base.AllowedTypes) > before {
			added++
		}
	}

	if err := base.Save(opts.baseline); err != nil {
		return err
	}

	fmt.Fprintf(stderr,
		"MORF gate: allowlist updated (%s) — %d new entr(y/ies) added (%d fingerprint(s), %d type(s))\n",
		opts.baseline, added, len(fps), len(typs),
	)
	return nil
}

// GetGateAllowCmd returns the `morf gate allow` subcommand: load a baseline,
// add fingerprints and/or secret types to its allowlist, and persist.
func GetGateAllowCmd() *cobra.Command {
	var opts allowOptions

	allowCmd := &cobra.Command{
		Use:   "allow --baseline <path> [--allow-fingerprint FP ...] [--allow-type TYPE ...]",
		Short: "Add fingerprints or secret types to a baseline allowlist",
		Long: `Load the baseline at --baseline, add the given fingerprints / secret types to
its allowlist (AllowedFingerprints / AllowedTypes), and persist. A missing
baseline file is treated as empty (first run). All updates are idempotent.

Fingerprints are opaque HMAC-SHA256 hex digests — no plaintext is stored.
Secret types are detector labels such as "aws-access-key" or "generic-api-key".

Both flags accept comma-separated values and may be repeated:

  morf gate allow --baseline base.json --allow-type aws-access-key,gcp-api-key
  morf gate allow --baseline base.json --allow-fingerprint <hex1> --allow-fingerprint <hex2>`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runGateAllow(opts, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, "morf gate allow:", err)
				os.Exit(exitOperational)
			}
		},
	}

	allowCmd.Flags().StringVar(&opts.baseline, "baseline", "", "Path to the accepted-findings baseline JSON (required)")
	allowCmd.Flags().StringArrayVar(&opts.fingerprints, "allow-fingerprint", nil, "Fingerprint hex digest(s) to allowlist (repeatable; comma-separated ok)")
	allowCmd.Flags().StringArrayVar(&opts.types, "allow-type", nil, "Secret type label(s) to allowlist (repeatable; comma-separated ok)")

	return allowCmd
}

// gateOptions carries the resolved flag state for a single gate invocation.
type gateOptions struct {
	baseline       string // path to the baseline JSON
	updateBaseline bool   // rewrite the baseline from this scan and pass
	verify         bool   // enable live verification during the scan
	failOn         string // none|any|verified|keep
	jsonOut        bool   // emit the GateResult as JSON to stdout
}

// loadBaselineOrEmpty loads the baseline at path, treating a missing file as an
// empty baseline (first run) rather than an error. Any other read/parse failure
// is surfaced so CI does not silently gate against nothing.
func loadBaselineOrEmpty(path string) (*gate.Baseline, error) {
	if strings.TrimSpace(path) == "" {
		return gate.NewBaseline(), nil
	}
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return gate.NewBaseline(), nil
	}
	return gate.LoadBaseline(path)
}

// evaluateGate is the pure, testable core: given already-enriched findings, a
// loaded baseline, and the resolved options, it computes the GateResult, the
// rendered output, the human summary, and the exit code. It performs NO scanning
// and does NOT write the baseline (that side effect is applied by runGate) so
// tests can drive it with a hand-built []models.SecretModel.
func evaluateGate(opts gateOptions, secrets []models.SecretModel, base *gate.Baseline) (res gate.GateResult, out []byte, summary string, exitCode int, err error) {
	policy, perr := scanFailOn(opts.failOn)
	if perr != nil {
		return gate.GateResult{}, nil, "", exitOperational, perr
	}

	res = gate.Evaluate(secrets, base, policy)

	code := exitOK
	if res.Failed {
		code = exitPolicy
	}

	if opts.jsonOut {
		// GateResult carries findings verbatim, so mask before emitting to keep
		// plaintext secrets out of the JSON. renderFindings(json) masks the
		// secret strings for each list.
		masked, merr := maskGateResult(res)
		if merr != nil {
			return res, nil, "", exitOperational, merr
		}
		out = masked
	}

	summary = fmt.Sprintf(
		"MORF gate: %d new finding(s), %d new verified-active; fail-on=%s -> %s [%s]",
		len(res.NewFindings), len(res.NewVerified), policyLabel(policy), passFail(res.Failed), res.Reason,
	)

	return res, out, summary, code, nil
}

// maskGateResult renders a GateResult as JSON with every secretString masked in
// both NewFindings and NewVerified, reusing renderFindings' JSON masking.
func maskGateResult(res gate.GateResult) ([]byte, error) {
	maskList := func(in []models.SecretModel) ([]any, error) {
		if len(in) == 0 {
			return []any{}, nil
		}
		raw, err := renderFindings("json", "", "", in, false) // gate output always masks
		if err != nil {
			return nil, err
		}
		var env struct {
			Data struct {
				Secrets []any `json:"secrets"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, err
		}
		return env.Data.Secrets, nil
	}

	nf, err := maskList(res.NewFindings)
	if err != nil {
		return nil, err
	}
	nv, err := maskList(res.NewVerified)
	if err != nil {
		return nil, err
	}

	envelope := map[string]any{
		"failed":      res.Failed,
		"reason":      res.Reason,
		"newFindings": nf,
		"newVerified": nv,
	}
	return json.MarshalIndent(envelope, "", "  ")
}

// runGate is the full command helper: scan -> load baseline -> evaluate ->
// (optionally rewrite baseline) -> exit code. It returns the exit code so the
// cobra Run wrapper owns the os.Exit boundary.
func runGate(ctx context.Context, opts gateOptions, path string, stdout, stderr io.Writer) (int, error) {
	secrets, _, _, err := runScanForFile(ctx, path, opts.verify)
	if err != nil {
		return exitOperational, err
	}

	base, err := loadBaselineOrEmpty(opts.baseline)
	if err != nil {
		return exitOperational, err
	}

	res, out, summary, code, err := evaluateGate(opts, secrets, base)
	if err != nil {
		return exitOperational, err
	}

	if opts.jsonOut && out != nil {
		if _, werr := stdout.Write(append(out, '\n')); werr != nil {
			return exitOperational, werr
		}
	}
	fmt.Fprintln(stderr, summary)

	// --update-baseline snapshots the CURRENT scan as the new accepted baseline
	// and forces a pass: the operator is explicitly accepting whatever was found.
	if opts.updateBaseline {
		if strings.TrimSpace(opts.baseline) == "" {
			return exitOperational, fmt.Errorf("--update-baseline requires --baseline <path>")
		}
		if err := gate.BaselineFromScan(secrets).Save(opts.baseline); err != nil {
			return exitOperational, err
		}
		fmt.Fprintf(stderr, "MORF gate: baseline updated (%s), %d finding(s) accepted\n", opts.baseline, len(secrets))
		return exitOK, nil
	}

	_ = res
	return code, nil
}

// GetGateCmd returns the `morf gate` command: scan a package, diff it against a
// committed baseline of accepted fingerprints, and fail the build (exit 4) when
// the --fail-on policy is tripped by NEW findings.
func GetGateCmd() *cobra.Command {
	var opts gateOptions

	gateCmd := &cobra.Command{
		Use:   "gate <file.apk|file.ipa> --baseline <path>",
		Short: "Scan and gate a package against an accepted-findings baseline",
		Long: `Scan a single Android (.apk) or iOS (.ipa) package in-process, then diff the
findings against a baseline of previously-accepted secret fingerprints. NEW
findings (not baselined, not allowlisted) drive the exit code per --fail-on:

  0  no new finding tripped the threshold (or --update-baseline was used)
  4  a new finding tripped the threshold (gate failure)
  1  an operational error (bad file, missing tools, unreadable baseline)

A missing baseline file is treated as an empty baseline (first run). Pass
--update-baseline to snapshot the current scan as the new accepted baseline;
this always exits 0. Baselines contain only opaque fingerprints (no plaintext
secrets) and are safe to commit.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			code, err := runGate(cmd.Context(), opts, args[0], os.Stdout, os.Stderr)
			if err != nil {
				fmt.Fprintln(os.Stderr, "morf gate:", err)
			}
			os.Exit(code)
		},
	}

	gateCmd.Flags().StringVar(&opts.baseline, "baseline", "", "Path to the accepted-findings baseline JSON")
	gateCmd.Flags().BoolVar(&opts.updateBaseline, "update-baseline", false, "Snapshot this scan as the new baseline and pass")
	gateCmd.Flags().BoolVar(&opts.verify, "verify", false, "Enable live (read-only) verification of findings")
	gateCmd.Flags().StringVar(&opts.failOn, "fail-on", "verified", "Gate threshold: none|any|verified|keep")
	gateCmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit the gate result (masked) as JSON to stdout")

	gateCmd.AddCommand(GetGateAllowCmd())

	return gateCmd
}
