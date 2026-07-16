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

// TestLoadLabels asserts the embedded ground truth parses and covers both
// platforms with at least one true positive and one decoy each, so the metrics
// are meaningful.
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
