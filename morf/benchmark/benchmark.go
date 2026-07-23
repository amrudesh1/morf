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

// Package benchmark provides a hermetic, apktool-free precision/recall benchmark
// for MORF's detection core (detect.ScanCorpus / ScanCorpusText / ApplyPrecision).
//
// It ships a small, fully-labeled corpus embedded via go:embed: planted
// true-positive secrets (real-format AWS / Google / Stripe / GitHub / Slack /
// SendGrid keys, JWTs, keychain groups, Firebase URLs, OAuth client ids) laid
// out across android-shaped and ios-shaped decompiled-app trees, alongside
// realistic false-positive bait (git SHAs, UUIDs, base64 blobs, placeholder
// keys, a public-cert JWT, a benign keychain group, a body-less private-key
// marker). Every planted value is described in corpus/labels.json.
//
// Additionally, corpus/ipa/fixture.ipa is a real archive container (a zip in the
// canonical Payload/*.app layout) that is extracted at benchmark time by
// RunBenchmark through the pure-Go archive/zip path — the same container-level
// extraction the production ios pipeline performs — before handing the extracted
// tree to detect.ScanCorpus. This ensures the benchmark exercises the full
// container path (unzip → file tree → rg scan) without any JVM or apktool
// dependency. Android stays as loose files because the Android container path
// requires apktool (a JVM tool) which would break hermeticity.
//
// At runtime the harness:
//  1. materializes the embedded corpus + a curated pattern set into a temp dir
//     that lives OUTSIDE any git repo (so ripgrep's .gitignore handling never
//     hides the planted *.so / binary artifacts), and points MORF_PATTERNS_DIR
//     at the extracted patterns;
//  2. runs the real detection core per platform — the text pass (ScanCorpus)
//     unioned with the binary --text pass (ScanCorpusText) so NUL-wrapped native
//     artifacts count toward recall — exactly as the production apk/ios pipelines
//     do, then dedups with detect.SanitizeSecrets; for the ipa-container platform
//     the .ipa is first unzipped via archive/zip into a temp directory and the
//     extracted Payload/ tree is then passed to the same detection core;
//  3. scores precision/recall/F1 against the ground truth BOTH before and after
//     detect.ApplyPrecision, so the false-positive drop from the precision engine
//     is measured directly.
//
// The only external dependency is ripgrep (rg); there is no apktool, no JVM, no
// device, no network and no randomness, so the result is deterministic.
package benchmark

import (
	"archive/zip"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"morf/detect"
	"morf/models"
)

//go:embed corpus benchpatterns
var embeddedFS embed.FS

// GroundTruth is a single labeled entry from corpus/labels.json.
type GroundTruth struct {
	Platform     string `json:"platform"`
	SecretType   string `json:"secretType"`
	FileBasename string `json:"fileBasename"`
	// Expect is true for a planted true positive that SHOULD be reported, false
	// for false-positive bait the precision engine is expected to drop.
	Expect bool `json:"expect"`
	// ExpectedTier pins the post-precision tier ("keep"|"info") for a retained
	// finding; "" means don't-care.
	ExpectedTier string `json:"expectedTier"`
}

// labelsFile is the on-disk shape of corpus/labels.json.
type labelsFile struct {
	Description string        `json:"description"`
	Labels      []GroundTruth `json:"labels"`
}

// Metrics captures confusion-matrix counts and the derived scores for one pass.
type Metrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Report is the per-platform benchmark result.
type Report struct {
	Platform string `json:"platform"`
	// Before is scored on the raw (deduped) findings; After is scored on the
	// findings that survive detect.ApplyPrecision.
	Before Metrics `json:"before"`
	After  Metrics `json:"after"`
	// FalsePositiveDrop is Before.FP - After.FP: the false positives eliminated by
	// the precision engine (the headline value it delivers).
	FalsePositiveDrop int `json:"falsePositiveDrop"`
	RawFindings       int `json:"rawFindings"`
	KeptFindings      int `json:"keptFindings"`
	// TierCounts is a histogram of the post-precision Tier field ("keep"/"info").
	TierCounts map[string]int `json:"tierCounts"`
	// TierMismatches lists retained findings whose tier disagreed with the
	// ground-truth expectedTier (empty when the precision tiering matched labels).
	TierMismatches []string `json:"tierMismatches,omitempty"`
}

// binaryExcludes keeps the binary --text pass from re-scanning roots already
// covered by the text pass (smali/res/original) and the unknown/ config tree
// (already text-scanned), mirroring apk.androidBinaryExcludes so a plain-text
// planted secret is not double-counted from both passes.
var binaryExcludes = []string{
	"-g", "!**/smali*/**",
	"-g", "!**/res/**",
	"-g", "!**/original/**",
	"-g", "!**/unknown/**",
}

// benchPlatforms are the platforms exercised by the benchmark, in report order.
// "ipa-container" is a special entry: instead of scanning a loose-file directory
// it unzips corpus/ipa/fixture.ipa first (the real archive container path) and
// then scans the extracted tree. Android stays as loose files because the Android
// container path requires apktool (a JVM tool), which would break hermeticity.
var benchPlatforms = []string{"android", "ios", "ipa-container"}

// ipaContainerPlatform is the pseudo-platform name used in labels.json for the
// IPA archive container case. It scans as "ios" (same pattern set) but exercises
// the zip-extraction step that the production ios.StartUnpack performs.
const ipaContainerPlatform = "ipa-container"

// ipaFixturePath is the embedded path of the synthetic .ipa archive fixture
// relative to the corpus root.
const ipaFixturePath = "corpus/ipa/fixture.ipa"

// RunBenchmark materializes the embedded corpus, runs the detection core against
// it per platform, and returns a per-platform precision/recall report scored
// before and after the precision engine. It returns an error only for a genuine
// harness failure (missing ripgrep, extraction failure, a scan error); an empty
// result set is reported as zeroed metrics, not an error.
func RunBenchmark(ctx context.Context) ([]Report, error) {
	if _, err := exec.LookPath("rg"); err != nil {
		return nil, fmt.Errorf("ripgrep (rg) not found on PATH; the benchmark needs rg to scan the corpus: %w", err)
	}

	corpusDir, patternsDir, cleanup, err := extractCorpus()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Point the detection core at the extracted curated patterns. Save/restore so
	// the process env is unchanged after RunBenchmark returns.
	prev, had := os.LookupEnv("MORF_PATTERNS_DIR")
	if err := os.Setenv("MORF_PATTERNS_DIR", patternsDir); err != nil {
		return nil, fmt.Errorf("set MORF_PATTERNS_DIR: %w", err)
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
		return nil, err
	}

	reports := make([]Report, 0, len(benchPlatforms))
	for _, plat := range benchPlatforms {
		var rep Report
		var repErr error
		if plat == ipaContainerPlatform {
			// IPA container case: unzip the fixture first, then scan the extracted
			// tree via the real detection core. This exercises the full container
			// path (archive/zip extraction -> Payload/*.app layout -> rg scan)
			// hermetically, without apktool or JVM.
			rep, repErr = runIPAContainerCase(ctx, corpusDir, labels)
		} else {
			rep, repErr = runPlatform(ctx, plat, filepath.Join(corpusDir, plat), labels)
		}
		if repErr != nil {
			return nil, fmt.Errorf("benchmark platform %s: %w", plat, repErr)
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

// runIPAContainerCase exercises the full IPA archive container path:
//  1. Reads corpus/ipa/fixture.ipa from the extracted corpus dir.
//  2. Unzips it into a fresh temp directory (mirroring ios.StartUnpack / unzipTo).
//  3. Scans the extracted Payload/ tree with the real detection core (text pass +
//     binary --text pass), exactly as the production ios pipeline does.
//
// Labels for this case carry platform = "ipa-container" in labels.json so they
// are distinct from the loose-file ios labels.
func runIPAContainerCase(ctx context.Context, corpusDir string, labels []GroundTruth) (Report, error) {
	ipaPath := filepath.Join(corpusDir, "ipa", "fixture.ipa")

	// Unzip the .ipa into a fresh temp dir outside the corpus so rg does not
	// re-scan the archive itself (it would appear as binary and match nothing).
	extractDir, err := os.MkdirTemp("", "morf-bench-ipa-*")
	if err != nil {
		return Report{}, fmt.Errorf("create ipa extract dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := unzipIPA(ipaPath, extractDir); err != nil {
		return Report{}, fmt.Errorf("unzip ipa fixture: %w", err)
	}

	return runPlatform(ctx, ipaContainerPlatform, extractDir, labels)
}

// unzipIPA is a minimal pure-Go IPA extractor used exclusively by the benchmark.
// It mirrors the production ios.unzipTo function: it rejects absolute paths and
// traversal entries, creates parent directories, and streams each entry to disk.
// The benchmark uses this instead of ios.StartUnpack to avoid the utils.JobContext
// dependency (which requires a full workspace tree), keeping the benchmark package
// self-contained.
func unzipIPA(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open ipa zip %q: %w", src, err)
	}
	defer r.Close()

	cleanDst := filepath.Clean(dst)
	for _, f := range r.File {
		if filepath.IsAbs(f.Name) || strings.HasPrefix(f.Name, "/") || strings.HasPrefix(f.Name, "\\") {
			return fmt.Errorf("zip entry %q has absolute path (zip-slip)", f.Name)
		}
		target := filepath.Join(cleanDst, filepath.FromSlash(f.Name))
		if target != cleanDst && !strings.HasPrefix(target, cleanDst+string(os.PathSeparator)) {
			return fmt.Errorf("zip entry %q escapes extraction root (zip-slip)", f.Name)
		}
		if f.FileInfo().IsDir() {
			if mkErr := os.MkdirAll(target, 0o755); mkErr != nil {
				return fmt.Errorf("mkdir %q: %w", target, mkErr)
			}
			continue
		}
		if mkErr := os.MkdirAll(filepath.Dir(target), 0o755); mkErr != nil {
			return fmt.Errorf("mkdir parent of %q: %w", target, mkErr)
		}
		if wErr := writeEntry(f, target); wErr != nil {
			return wErr
		}
	}
	return nil
}

// writeEntry streams a single zip entry to an on-disk file, preserving all bytes
// (including NUL bytes in binary artifacts such as libBench.bin).
func writeEntry(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create %q: %w", target, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, rc); err != nil {
		return fmt.Errorf("write %q: %w", target, err)
	}
	return nil
}

// runPlatform scans one platform subtree and scores it before/after precision.
// For "ipa-container", the scan platform is "ios" (same pattern set applies) but
// labels are keyed on "ipa-container" so they are distinct from the loose-file
// ios case.
func runPlatform(ctx context.Context, platform, root string, labels []GroundTruth) (Report, error) {
	roots := []string{root}

	// Resolve the scan platform for the detection core: "ipa-container" scans as
	// "ios" (same patterns) but is reported and labeled separately.
	scanPlatform := platform
	if platform == ipaContainerPlatform {
		scanPlatform = "ios"
	}

	// Text pass over the whole tree, unioned with the binary --text pass so
	// NUL-wrapped native artifacts (.so, Flutter/RN blobs, embedded frameworks)
	// are searched too. This mirrors the production apk path (StartScanE).
	textHits, err := detect.ScanCorpus(ctx, "benchmark-"+platform, roots, scanPlatform)
	if err != nil {
		return Report{}, fmt.Errorf("text scan: %w", err)
	}
	binHits, err := detect.ScanCorpusText(ctx, "benchmark-"+platform, roots, scanPlatform, binaryExcludes)
	if err != nil {
		return Report{}, fmt.Errorf("binary text scan: %w", err)
	}

	raw := detect.SanitizeSecrets(append(textHits, binHits...))
	kept := detect.ApplyPrecision(raw)

	platLabels := labelsForPlatform(labels, platform)

	rep := Report{
		Platform:     platform,
		Before:       score(raw, platLabels),
		RawFindings:  len(raw),
		KeptFindings: len(kept),
		TierCounts:   map[string]int{},
	}
	rep.After = score(kept, platLabels)
	rep.FalsePositiveDrop = rep.Before.FP - rep.After.FP
	for _, s := range kept {
		rep.TierCounts[s.Tier]++
	}
	rep.TierMismatches = tierMismatches(kept, platLabels)
	return rep, nil
}

// score attributes every finding to a ground-truth entry (by SecretType + file
// basename) and computes the confusion matrix and derived scores:
//   - a finding matching an Expect=true label     -> true positive
//   - a finding matching an Expect=false label,
//     or matching no label at all                 -> false positive
//   - an Expect=true label with no matching finding-> false negative
//
// Matching on (SecretType, basename) is unambiguous for this corpus: no two
// labeled secrets share both a type and a file. The exact matched value is not
// used as the key because ExtractSecret can trim it (quotes, colons, length
// caps), whereas type+location is stable.
func score(findings []models.SecretModel, labels []GroundTruth) Metrics {
	type key struct{ secretType, basename string }

	labelByKey := make(map[key]GroundTruth, len(labels))
	for _, l := range labels {
		labelByKey[key{l.SecretType, l.FileBasename}] = l
	}

	matched := make(map[key]bool, len(labels))
	var m Metrics
	for _, f := range findings {
		k := key{f.SecretType, filepath.Base(f.FileLocation)}
		l, ok := labelByKey[k]
		if !ok {
			// Attributed to no ground-truth entry: an unplanted finding is a false
			// positive (this is how the never-should-surface decoys are penalized).
			m.FP++
			continue
		}
		matched[k] = true
		if l.Expect {
			m.TP++
		} else {
			m.FP++
		}
	}
	// Any Expect=true label never matched by a finding is a false negative.
	for _, l := range labels {
		if !l.Expect {
			continue
		}
		if !matched[key{l.SecretType, l.FileBasename}] {
			m.FN++
		}
	}

	m.Precision = ratio(m.TP, m.TP+m.FP)
	m.Recall = ratio(m.TP, m.TP+m.FN)
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	return m
}

// tierMismatches returns human-readable descriptions of retained findings whose
// post-precision Tier disagreed with the ground-truth expectedTier. Findings
// with no matching label, or a label with an empty expectedTier, are ignored.
func tierMismatches(kept []models.SecretModel, labels []GroundTruth) []string {
	type key struct{ secretType, basename string }
	want := make(map[key]string, len(labels))
	for _, l := range labels {
		if l.Expect && l.ExpectedTier != "" {
			want[key{l.SecretType, l.FileBasename}] = l.ExpectedTier
		}
	}
	var out []string
	for _, s := range kept {
		k := key{s.SecretType, filepath.Base(s.FileLocation)}
		exp, ok := want[k]
		if !ok {
			continue
		}
		if s.Tier != exp {
			out = append(out, fmt.Sprintf("%s (%s): got tier %q, want %q",
				s.SecretType, k.basename, s.Tier, exp))
		}
	}
	sort.Strings(out)
	return out
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func labelsForPlatform(labels []GroundTruth, platform string) []GroundTruth {
	out := make([]GroundTruth, 0, len(labels))
	for _, l := range labels {
		if l.Platform == platform {
			out = append(out, l)
		}
	}
	return out
}

// loadLabels reads and parses the embedded ground-truth manifest.
func loadLabels() ([]GroundTruth, error) {
	raw, err := embeddedFS.ReadFile("corpus/labels.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded labels: %w", err)
	}
	var lf labelsFile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("parse labels.json: %w", err)
	}
	if len(lf.Labels) == 0 {
		return nil, fmt.Errorf("labels.json contained no labels")
	}
	return lf.Labels, nil
}

// extractCorpus materializes the embedded corpus and pattern files into a fresh
// temp directory tree and returns the corpus root, the patterns dir, and a
// cleanup func. The temp dir is created under os.TempDir() (outside any git
// checkout) so ripgrep's automatic .gitignore handling cannot hide the planted
// binary artifacts (*.so etc.) the way it would inside the repo.
func extractCorpus() (corpusDir, patternsDir string, cleanup func(), err error) {
	base, err := os.MkdirTemp("", "morf-benchmark-*")
	if err != nil {
		return "", "", func() {}, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(base) }

	if err := extractTree("corpus", base); err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	if err := extractTree("benchpatterns", base); err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	return filepath.Join(base, "corpus"), filepath.Join(base, "benchpatterns"), cleanup, nil
}

// extractTree copies one embedded subtree (rooted at prefix) verbatim into dst,
// preserving relative paths and file bytes (including embedded NUL bytes in the
// binary artifacts).
func extractTree(prefix, dst string) error {
	return fs.WalkDir(embeddedFS, prefix, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		target := filepath.Join(dst, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := embeddedFS.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", p, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
