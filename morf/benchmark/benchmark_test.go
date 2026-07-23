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

package benchmark

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// requireRG skips a test when ripgrep is not installed, mirroring the apk
// integration tests: the benchmark is a scan integration test and cannot run
// without rg.
func requireRG(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep (rg) not installed; skipping detection benchmark")
	}
}

// TestRunBenchmark is the regression guard: it runs the whole harness and
// asserts sane thresholds so a regression in the detection core or the precision
// engine fails the build. It is deterministic (fixed embedded corpus, no
// randomness/network) and hermetic (temp dir, env save/restore).
func TestRunBenchmark(t *testing.T) {
	requireRG(t)

	reports, err := RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("RunBenchmark returned error: %v", err)
	}
	if len(reports) == 0 {
		t.Fatal("RunBenchmark returned no platform reports")
	}

	var totBeforeFP, totAfterFP, totTP int
	for _, r := range reports {
		t.Logf("[%s] before P=%.2f R=%.2f F1=%.2f (TP=%d FP=%d FN=%d); after P=%.2f R=%.2f F1=%.2f (TP=%d FP=%d FN=%d); FP drop=%d raw=%d kept=%d tiers=%v",
			r.Platform,
			r.Before.Precision, r.Before.Recall, r.Before.F1, r.Before.TP, r.Before.FP, r.Before.FN,
			r.After.Precision, r.After.Recall, r.After.F1, r.After.TP, r.After.FP, r.After.FN,
			r.FalsePositiveDrop, r.RawFindings, r.KeptFindings, r.TierCounts)

		// RECALL: the precision engine must not discard planted true positives, so
		// recall on the retained findings must stay high (>= 0.8). The public-by-
		// design TPs (OAuth/Firebase/keychain) are downgraded to info, not dropped,
		// so they still count as recalled.
		if r.After.Recall < 0.8 {
			t.Errorf("[%s] after-precision recall %.2f < 0.80 (a planted true positive was dropped)", r.Platform, r.After.Recall)
		}

		// PRECISION: ApplyPrecision must improve or hold precision — it may never
		// make precision worse.
		if r.After.Precision+1e-9 < r.Before.Precision {
			t.Errorf("[%s] after-precision precision %.2f regressed below before %.2f", r.Platform, r.After.Precision, r.Before.Precision)
		}

		// FALSE POSITIVES: precision must never introduce new false positives.
		if r.After.FP > r.Before.FP {
			t.Errorf("[%s] after-precision FP %d exceeds before FP %d", r.Platform, r.After.FP, r.Before.FP)
		}

		// TIERING: every retained finding's tier must agree with its ground-truth
		// expectedTier (keep vs info), or the precision policy drifted.
		if len(r.TierMismatches) > 0 {
			t.Errorf("[%s] tier mismatches vs ground truth: %v", r.Platform, r.TierMismatches)
		}

		// The precision engine should retain at least some findings; a platform
		// that scanned to nothing means the corpus or patterns broke.
		if r.KeptFindings == 0 {
			t.Errorf("[%s] no findings retained after precision; corpus/patterns likely broken", r.Platform)
		}

		totBeforeFP += r.Before.FP
		totAfterFP += r.After.FP
		totTP += r.After.TP
	}

	// The headline value of the precision engine: it must remove at least one
	// false positive across the corpus (the corpus plants body-less private-key
	// markers, a public-cert JWT and a benign keychain group specifically to be
	// dropped).
	if totAfterFP >= totBeforeFP {
		t.Errorf("precision engine removed no false positives: before FP=%d, after FP=%d", totBeforeFP, totAfterFP)
	}

	// Sanity: the run must have recalled real secrets, not just emptied out.
	if totTP == 0 {
		t.Fatal("no true positives recalled across the corpus")
	}
}

// TestExtractCorpusIsHermetic verifies the embedded corpus extracts cleanly to a
// temp dir and that the extractor preserves the NUL-laden binary artifacts (the
// planted native .so / blob files) byte-for-byte, since binary recall depends on
// those bytes surviving the go:embed round-trip.
func TestExtractCorpusIsHermetic(t *testing.T) {
	corpusDir, patternsDir, cleanup, err := extractCorpus()
	if err != nil {
		t.Fatalf("extractCorpus: %v", err)
	}
	defer cleanup()

	for _, p := range []string{
		corpusDir + "/android/lib/arm64-v8a/libsecret.so",
		corpusDir + "/android/assets/flutter_assets/kernel_blob.bin",
		corpusDir + "/ios/Payload/App.app/Info.plist",
		corpusDir + "/ipa/fixture.ipa",
		patternsDir + "/high-confidence.yml",
		patternsDir + "/ios-high-confidence.yml",
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected extracted file missing: %s (%v)", p, err)
		}
	}

	// The .so must still contain a NUL byte (binary artifact preserved verbatim).
	data, err := os.ReadFile(corpusDir + "/android/lib/arm64-v8a/libsecret.so")
	if err != nil {
		t.Fatalf("read extracted .so: %v", err)
	}
	hasNUL := false
	for _, b := range data {
		if b == 0x00 {
			hasNUL = true
			break
		}
	}
	if !hasNUL {
		t.Error("extracted libsecret.so lost its NUL bytes; binary recall would silently pass via the text pass")
	}
}

// TestIPAContainerExtract verifies that unzipIPA correctly extracts the embedded
// fixture.ipa into a temp directory, preserving the NUL-laden binary artifact
// (libBench.bin) and the planted Info.plist bytes, so the container recall path
// does not silently degrade to nothing.
func TestIPAContainerExtract(t *testing.T) {
	corpusDir, _, cleanup, err := extractCorpus()
	if err != nil {
		t.Fatalf("extractCorpus: %v", err)
	}
	defer cleanup()

	ipaPath := corpusDir + "/ipa/fixture.ipa"
	if _, err := os.Stat(ipaPath); err != nil {
		t.Fatalf("fixture.ipa not found in extracted corpus: %v", err)
	}

	extractDir, err := os.MkdirTemp("", "morf-bench-ipa-test-*")
	if err != nil {
		t.Fatalf("create extract dir: %v", err)
	}
	defer os.RemoveAll(extractDir)

	if err := unzipIPA(ipaPath, extractDir); err != nil {
		t.Fatalf("unzipIPA: %v", err)
	}

	// Verify expected files are present.
	for _, rel := range []string{
		"Payload/BenchApp.app/Info.plist",
		"Payload/BenchApp.app/config.json",
		"Payload/BenchApp.app/libBench.bin",
	} {
		p := extractDir + "/" + rel
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected extracted file missing: %s (%v)", rel, err)
		}
	}

	// libBench.bin must contain NUL bytes (binary artifact preserved verbatim).
	binData, err := os.ReadFile(extractDir + "/Payload/BenchApp.app/libBench.bin")
	if err != nil {
		t.Fatalf("read libBench.bin: %v", err)
	}
	hasNUL := false
	for _, b := range binData {
		if b == 0x00 {
			hasNUL = true
			break
		}
	}
	if !hasNUL {
		t.Error("libBench.bin lost its NUL bytes; binary recall for IPA container case would silently skip the binary pass")
	}

	// Info.plist must still carry an AWS-key-shaped value after extraction. We
	// assert only on the "AKIA" prefix (not the full literal) so this test file
	// contains no secret-shaped string of its own; end-to-end detection of the
	// exact key is covered by TestIPAContainerRecall.
	plistData, err := os.ReadFile(extractDir + "/Payload/BenchApp.app/Info.plist")
	if err != nil {
		t.Fatalf("read Info.plist: %v", err)
	}
	if !contains(string(plistData), "AKIA") {
		t.Error("Info.plist does not contain the planted AWS key (AKIA-prefixed value missing)")
	}
}

// TestIPAContainerRecall runs the IPA container case end-to-end (unzip + scan)
// and asserts that the planted AWS and Stripe keys in Info.plist are recalled
// with precision >= 0.5 and recall >= 0.5 after ApplyPrecision.
func TestIPAContainerRecall(t *testing.T) {
	requireRG(t)

	corpusDir, patternsDir, cleanup, err := extractCorpus()
	if err != nil {
		t.Fatalf("extractCorpus: %v", err)
	}
	defer cleanup()

	prev, had := os.LookupEnv("MORF_PATTERNS_DIR")
	if setErr := os.Setenv("MORF_PATTERNS_DIR", patternsDir); setErr != nil {
		t.Fatalf("set MORF_PATTERNS_DIR: %v", setErr)
	}
	defer func() {
		if had {
			_ = os.Setenv("MORF_PATTERNS_DIR", prev)
		} else {
			_ = os.Unsetenv("MORF_PATTERNS_DIR")
		}
	}()

	labels, err := loadLabels()
	if err != nil {
		t.Fatalf("loadLabels: %v", err)
	}

	rep, err := runIPAContainerCase(t.Context(), corpusDir, labels)
	if err != nil {
		t.Fatalf("runIPAContainerCase: %v", err)
	}

	t.Logf("[ipa-container] before P=%.2f R=%.2f F1=%.2f (TP=%d FP=%d FN=%d); after P=%.2f R=%.2f F1=%.2f (TP=%d FP=%d FN=%d); FP drop=%d raw=%d kept=%d tiers=%v",
		rep.Before.Precision, rep.Before.Recall, rep.Before.F1, rep.Before.TP, rep.Before.FP, rep.Before.FN,
		rep.After.Precision, rep.After.Recall, rep.After.F1, rep.After.TP, rep.After.FP, rep.After.FN,
		rep.FalsePositiveDrop, rep.RawFindings, rep.KeptFindings, rep.TierCounts)

	if rep.KeptFindings == 0 {
		t.Error("IPA container case: no findings kept after precision; extraction or scanning likely broken")
	}
	if rep.After.Recall < 0.5 {
		t.Errorf("IPA container case: after-precision recall %.2f < 0.50 (planted secrets in IPA container were not recalled)", rep.After.Recall)
	}
	if rep.After.Precision < 0.5 {
		t.Errorf("IPA container case: after-precision precision %.2f < 0.50", rep.After.Precision)
	}
}

// contains reports whether s contains substr (helper avoids importing strings in tests).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsRune(s, substr))
}

func containsRune(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestLoadLabels asserts the embedded ground truth parses and covers all
// platforms (android, ios, ipa-container) with at least one true positive and
// one decoy each, so the metrics are meaningful.
func TestLoadLabels(t *testing.T) {
	labels, err := loadLabels()
	if err != nil {
		t.Fatalf("loadLabels: %v", err)
	}
	perPlatform := map[string]struct{ tp, fp int }{}
	for _, l := range labels {
		e := perPlatform[l.Platform]
		if l.Expect {
			e.tp++
		} else {
			e.fp++
		}
		perPlatform[l.Platform] = e
	}
	for _, plat := range benchPlatforms {
		e, ok := perPlatform[plat]
		if !ok {
			t.Errorf("no ground-truth labels for platform %q", plat)
			continue
		}
		if e.tp == 0 {
			t.Errorf("platform %q has no planted true positives", plat)
		}
		if e.fp == 0 {
			t.Errorf("platform %q has no false-positive bait", plat)
		}
	}
}
