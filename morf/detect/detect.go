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

// Package detect holds the shared, platform-agnostic secret pattern-scanning
// core extracted from apk/scanner.go. It loads the YAML SecretPatterns from
// utils.GetPatternsDir(), builds and caches the compiled pattern set plus a
// combined alternation regex for O(1) attribution, runs ripgrep over arbitrary
// filesystem roots, attributes each hit back to the owning pattern, and
// sanitizes the resulting findings. Both the Android (apk) pipeline and the
// upcoming iOS pipeline reuse this package so their detection behavior is
// identical.
package detect

import (
	"context"
	"fmt"
	"io/fs"
	"morf/metrics"
	"morf/models"
	"morf/utils"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// SecretPatterns is the on-disk YAML shape of a pattern file under patternsDir.
type SecretPatterns struct {
	// Platform optionally scopes an ENTIRE file to one platform: "ios",
	// "android", or "any" (default). When absent, the platform is inferred from
	// the file name prefix ("ios-*" -> ios, "android-*" -> android, else any).
	// A scan only compiles patterns whose platform is "any" or matches the scan,
	// so iOS-only rules never run against an Android app and vice-versa.
	Platform string `yaml:"platform"`
	// MASVS optionally tags the ENTIRE file with an OWASP MASVS control id (e.g.
	// "MASVS-CRYPTO-1"). It is the default for every pattern in the file; a
	// pattern's own `masvs:` (below) overrides it. Absent means no MASVS id.
	MASVS    string `yaml:"masvs"`
	Patterns []struct {
		Pattern struct {
			Name       string `yaml:"name"`
			Regex      string `yaml:"regex"`
			Confidence string `yaml:"confidence"`
			// MASVS optionally tags THIS pattern with an OWASP MASVS control id;
			// when set it overrides the file-level MASVS. Absent falls back to the
			// file-level value.
			MASVS string `yaml:"masvs"`
			// Enabled is decoded as a pointer so an absent value (nil) is
			// distinguishable from an explicit `enabled: false`. nil/absent
			// defaults to enabled; only an explicit false skips the pattern.
			Enabled *bool `yaml:"enabled"`
		} `yaml:"pattern"`
	} `yaml:"patterns"`
}

// PatternInfo stores pattern information for batch scanning.
// Compiled is the pre-compiled regex; nil only if Regex failed to compile.
type PatternInfo struct {
	Name       string
	Regex      string
	Confidence string
	Platform   string // "ios" | "android" | "any" — scan scope (see SecretPatterns.Platform)
	// MASVS is the resolved OWASP MASVS control id for this pattern: the
	// pattern-level `masvs:` if present, else the file-level `masvs:`, else "".
	MASVS    string
	Compiled *regexp.Regexp
}

// normalizePlatform coerces an arbitrary string to a known scope value.
func normalizePlatform(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ios":
		return "ios"
	case "android":
		return "android"
	default:
		return "any"
	}
}

// filePlatform resolves a pattern file's platform scope from its declared
// `platform:` field, falling back to the file-name prefix, else "any".
func filePlatform(fileName, declared string) string {
	if p := normalizePlatform(declared); p != "any" {
		return p
	}
	lower := strings.ToLower(fileName)
	switch {
	case strings.HasPrefix(lower, "ios-"):
		return "ios"
	case strings.HasPrefix(lower, "android-"):
		return "android"
	default:
		return "any"
	}
}

// patternApplies reports whether a pattern with the given platform scope should
// run in a scan of scanPlatform. Cross-platform ("any") patterns always apply.
func patternApplies(patternPlatform, scanPlatform string) bool {
	return patternPlatform == "any" || patternPlatform == scanPlatform
}

// patternsDir is the on-disk location of the secret pattern YAML files.
// MED-hardcoded-paths: it delegates to utils.GetPatternsDir so it honours the
// SAME MORF_PATTERNS_DIR env var (default "/app/patterns") used by the utils
// pattern-CRUD track, rather than hardcoding the literal.
func patternsDir() string { return utils.GetPatternsDir() }

func readPatternFile(patternFilePath string) []byte {
	yamlFile, _ := utils.ReadFile(utils.GetAppFS(), patternFilePath)
	return yamlFile
}

// PatternCache is an immutable snapshot of the loaded+compiled pattern set
// together with the precomputed artifacts derived from it. Once published it is
// never mutated, so concurrent scans can read it without locking — the only
// synchronization is around swapping the package-level pointer (SCAN-4).
type PatternCache struct {
	// Patterns is every pattern loaded from patternsDir (RE2-compilable or not).
	Patterns []PatternInfo
	// Combined is a single alternation regex "(p0)|(p1)|..." built from the
	// RE2-compilable patterns only; nil if none compile or the union fails.
	Combined *regexp.Regexp
	// GroupToPattern maps a submatch-group index of `Combined` back to the
	// index into `Patterns` it belongs to (index 0 == whole match == -1).
	GroupToPattern []int
	// PatternsTxt is the generated patterns.txt body (one regex per line),
	// cached so it is built once rather than per scan.
	PatternsTxt []byte
	// BuiltFrom is the max ModTime observed in patternsDir at build time; the
	// cache is rebuilt when a newer entry appears.
	BuiltFrom time.Time
}

// cacheMu guards the per-platform pattern caches (SCAN-4). Each scan platform
// ("android"/"ios"/"any") gets its own immutable snapshot, since the compiled
// pattern set differs by platform scope.
var (
	cacheMu sync.RWMutex
	caches  = map[string]*PatternCache{}
)

// GetPatternCache returns a fresh, immutable pattern cache scoped to the given
// scan platform ("android"/"ios"; anything else -> "any"), rebuilding it only
// when patternsDir has changed since the last build (detected via the max entry
// ModTime). This replaces a per-scan load+compile (SCAN-4).
func GetPatternCache(jobID, platform string) (*PatternCache, error) {
	platform = normalizePlatform(platform)
	files := utils.ReadDir(utils.GetAppFS(), patternsDir())

	var maxMod time.Time
	for _, f := range files {
		if mt := f.ModTime(); mt.After(maxMod) {
			maxMod = mt
		}
	}

	// Fast path: an existing cache for this platform at least as new as patternsDir.
	cacheMu.RLock()
	cached := caches[platform]
	cacheMu.RUnlock()
	if cached != nil && !maxMod.After(cached.BuiltFrom) {
		return cached, nil
	}

	// Slow path: (re)build under the write lock, double-checking after acquiring
	// it so concurrent scans build at most once.
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c := caches[platform]; c != nil && !maxMod.After(c.BuiltFrom) {
		return c, nil
	}

	built, err := buildPatternCache(files, maxMod, jobID, platform)
	if err != nil {
		return nil, err
	}
	caches[platform] = built
	return built, nil
}

// buildPatternCache loads every YAML pattern file in patternsDir, compiles the
// patterns, and precomputes the combined regex, group map and patterns.txt body.
func buildPatternCache(files []fs.FileInfo, maxMod time.Time, jobID, platform string) (*PatternCache, error) {
	var allPatterns []PatternInfo

	for _, file := range files {
		name := file.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		yamlFile := readPatternFile(filepath.Join(patternsDir(), name))
		var secretPatterns SecretPatterns
		if err := yaml.Unmarshal(yamlFile, &secretPatterns); err != nil {
			log.WithFields(log.Fields{
				"job_id": jobID,
				"file":   name,
				"error":  err.Error(),
			}).Error("Error unmarshaling YAML file")
			continue
		}

		// PLATFORM-SCOPE: skip whole files that don't apply to this scan so
		// iOS-only rules never run on Android apps (and vice-versa). "any"
		// (cross-platform) files always apply.
		fp := filePlatform(name, secretPatterns.Platform)
		if !patternApplies(fp, platform) {
			continue
		}

		for _, pattern := range secretPatterns.Patterns {
			// Row 070: honor the enable/disable flag. A pattern explicitly
			// marked `enabled: false` is excluded from the compiled set; a
			// nil/absent flag defaults to enabled.
			if pattern.Pattern.Enabled != nil && !*pattern.Pattern.Enabled {
				continue
			}
			// Pre-compile regex once at load time. RE2 is used by Go's regexp,
			// which doesn't support backreferences/lookarounds; ripgrep does
			// support them, so a pattern may compile in ripgrep but fail here.
			// In that case Compiled stays nil and attribution falls back to the
			// non-RE2 path for lines the combined regex did not attribute.
			compiled, compileErr := regexp.Compile(pattern.Pattern.Regex)
			if compileErr != nil {
				log.WithFields(log.Fields{
					"job_id":  jobID,
					"pattern": pattern.Pattern.Name,
					"error":   compileErr.Error(),
				}).Debug("Pattern not compilable by Go regexp (RE2); attribution will fall back")
			}
			// Resolve the MASVS control id: the pattern-level `masvs:` overrides
			// the file-level `masvs:`; an absent pattern value inherits the file
			// value (which may itself be empty).
			masvs := secretPatterns.MASVS
			if pattern.Pattern.MASVS != "" {
				masvs = pattern.Pattern.MASVS
			}
			allPatterns = append(allPatterns, PatternInfo{
				Name:       pattern.Pattern.Name,
				Regex:      pattern.Pattern.Regex,
				Confidence: pattern.Pattern.Confidence,
				Platform:   fp,
				MASVS:      masvs,
				Compiled:   compiled,
			})
		}
	}

	if len(allPatterns) == 0 {
		return nil, fmt.Errorf("no secret patterns found in %s for platform %q", patternsDir(), platform)
	}

	// Build the patterns.txt body once (one regex per line).
	var txt strings.Builder
	for _, p := range allPatterns {
		txt.WriteString(p.Regex)
		txt.WriteByte('\n')
	}

	combined, groupToPattern := BuildCombinedRegex(allPatterns)

	log.WithFields(log.Fields{
		"job_id":        jobID,
		"platform":      platform,
		"pattern_count": len(allPatterns),
		"combined":      combined != nil,
	}).Info("Built pattern cache for batch scanning")

	return &PatternCache{
		Patterns:       allPatterns,
		Combined:       combined,
		GroupToPattern: groupToPattern,
		PatternsTxt:    []byte(txt.String()),
		BuiltFrom:      maxMod,
	}, nil
}

// BuildCombinedRegex builds a single alternation regex with one wrapping
// capture group per RE2-compilable pattern: "(p0)|(p1)|...". The returned slice
// maps every submatch-group index of the combined regex back to the index into
// `patterns` that owns it, so a single FindStringSubmatchIndex call identifies
// the matching pattern in O(1) amortized per line (SCAN-3). Returns (nil, nil)
// when no pattern is RE2-compilable or the union itself fails to compile.
func BuildCombinedRegex(patterns []PatternInfo) (*regexp.Regexp, []int) {
	var sb strings.Builder
	groupToPattern := []int{-1} // index 0 is the whole match; owns no pattern.
	wrote := false

	for i := range patterns {
		if patterns[i].Compiled == nil {
			continue
		}
		if wrote {
			sb.WriteByte('|')
		}
		wrote = true
		sb.WriteByte('(')
		sb.WriteString(patterns[i].Regex)
		sb.WriteByte(')')

		// This pattern occupies its wrapping group plus any internal capturing
		// groups it already contains; all of them attribute to pattern i.
		groups := 1 + patterns[i].Compiled.NumSubexp()
		for k := 0; k < groups; k++ {
			groupToPattern = append(groupToPattern, i)
		}
	}

	if !wrote {
		return nil, nil
	}

	combined, err := regexp.Compile(sb.String())
	if err != nil {
		// Degrade gracefully: FindMatchingPattern falls back to per-pattern
		// matching when combined is nil.
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to build combined pattern regex; using per-pattern attribution fallback")
		return nil, nil
	}
	return combined, groupToPattern
}

// FindMatchingPattern identifies which loaded pattern matches content. It runs
// the cached combined regex exactly once (SCAN-3); the first non-empty submatch
// group names the owning pattern. Lines the combined regex cannot attribute fall
// through to the non-RE2 pattern path.
func (c *PatternCache) FindMatchingPattern(content string) *PatternInfo {
	if c.Combined != nil {
		loc := c.Combined.FindStringSubmatchIndex(content)
		if loc != nil {
			// loc[2*g], loc[2*g+1] are the bounds of group g (g==0 is whole match).
			for g := 1; 2*g+1 < len(loc); g++ {
				if loc[2*g] < 0 {
					continue // group g did not participate in the match.
				}
				if g < len(c.GroupToPattern) {
					if pi := c.GroupToPattern[g]; pi >= 0 && pi < len(c.Patterns) {
						return &c.Patterns[pi]
					}
				}
			}
		}
	} else {
		// Safety net: the combined regex could not be built. Fall back to the
		// original per-pattern scan over the RE2-compilable patterns.
		for i := range c.Patterns {
			if c.Patterns[i].Compiled != nil && c.Patterns[i].Compiled.MatchString(content) {
				return &c.Patterns[i]
			}
		}
	}

	// The combined regex did not attribute this line. It may have been matched
	// in ripgrep by a non-RE2 pattern (lookaround/backref/multiline semantics Go
	// cannot run); attribute it to the first such pattern as a best effort.
	for i := range c.Patterns {
		if c.Patterns[i].Compiled == nil {
			return &c.Patterns[i]
		}
	}
	return nil
}

// FindingsForLine converts a single ripgrep-matched corpus line into one or more
// SecretModel findings. This is the security-critical value-extraction core:
//
//   - RECALL — it emits a finding for EVERY match span on the line, not just the
//     first. A densely packed line (a terminator-less __rodata blob, minified or
//     obfuscated code, concatenated literals) can carry several distinct secrets;
//     collapsing them into one finding would silently drop real secrets. And the
//     line always yields at least one finding, so a ripgrep hit is never lost.
//   - PRECISION — each finding's value is derived from the EXACT regex match span
//     (via the owning compiled pattern), then passed through ExtractSecret to peel
//     surrounding quotes/keys. It is never a heuristic applied to the whole line,
//     which is what previously returned the wrong token on packed lines.
//   - SAFETY — SecretString is never empty (falls back to the raw span), and
//     confidence always defaults to a valid ENUM member ("low").
//
// Attribution reuses the same combined-regex group map as FindMatchingPattern.
func (c *PatternCache) FindingsForLine(fileLocation string, lineNo int, content string) []models.SecretModel {
	out := make([]models.SecretModel, 0, 4)
	add := func(patternIdx int, span string) {
		secretType := "unattributed"
		confidence := "low"
		masvsID := ""
		if patternIdx >= 0 && patternIdx < len(c.Patterns) {
			secretType = c.Patterns[patternIdx].Name
			confidence = c.Patterns[patternIdx].Confidence
			masvsID = c.Patterns[patternIdx].MASVS
		}
		value := ExtractSecret(span)
		if strings.TrimSpace(value) == "" {
			// Never emit an empty secret value: fall back to the exact span.
			value = span
		}
		out = append(out, models.SecretModel{
			Type:             secretType,
			LineNo:           lineNo,
			FileLocation:     strings.Clone(fileLocation),
			SecretType:       secretType,
			SecretString:     strings.Clone(value),
			SecretConfidence: confidence,
			MASVSID:          masvsID,
		})
	}

	// Preferred path: enumerate EVERY match of the combined RE2 regex and
	// attribute each to its owning pattern via the group map. content[loc[0]:loc[1]]
	// is the exact text the matching alternative consumed — i.e. that pattern's
	// match — so packed lines yield the true per-secret value.
	if c.Combined != nil {
		for _, loc := range c.Combined.FindAllStringSubmatchIndex(content, -1) {
			if len(loc) < 2 || loc[0] < 0 || loc[1] < loc[0] {
				continue
			}
			span := content[loc[0]:loc[1]]
			patternIdx := -1
			for g := 1; 2*g+1 < len(loc); g++ {
				if loc[2*g] < 0 {
					continue // group g did not participate in this match.
				}
				if g < len(c.GroupToPattern) {
					if pi := c.GroupToPattern[g]; pi >= 0 && pi < len(c.Patterns) {
						patternIdx = pi
						break
					}
				}
			}
			add(patternIdx, span)
		}
		if len(out) > 0 {
			return out
		}
		// Combined matched nothing on this line: fall through to the non-RE2 path.
	} else {
		// No combined regex (union failed to build): scan each RE2 pattern's
		// every match individually so recall/precision are preserved.
		for i := range c.Patterns {
			if c.Patterns[i].Compiled == nil {
				continue
			}
			for _, span := range c.Patterns[i].Compiled.FindAllString(content, -1) {
				add(i, span)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// ripgrep flagged the line but no RE2 pattern attributed it — it matched a
	// non-RE2 ripgrep pattern (lookaround/backref/multiline Go cannot run). Never
	// drop the hit: emit one best-effort finding attributed to the first non-RE2
	// pattern (or "unattributed"), with the heuristic value over the whole line.
	patternIdx := -1
	for i := range c.Patterns {
		if c.Patterns[i].Compiled == nil {
			patternIdx = i
			break
		}
	}
	add(patternIdx, content)
	return out
}

// ScanCorpus runs the batch ripgrep pattern scan over the given filesystem
// roots and returns the attributed (unsanitized) secrets plus an error. It is
// the platform-agnostic core shared by the apk and ios pipelines: the caller
// supplies the search roots (decompiled sources, decoded resources, an
// extracted .ipa payload, …) and ScanCorpus loads/caches the patterns, writes
// the patterns.txt body to a temp file for ripgrep --file, streams the output
// line-by-line and attributes every hit back to the owning pattern.
//
//   - SCAN-1: ripgrep failures are not silently swallowed. Exit code 1 is a
//     genuine "no matches" (empty result, nil error); a timeout or exit >= 2 is
//     surfaced as an error so a failed scan is never mistaken for "no secrets".
//   - SCAN-7 / SCAN-2mem: ripgrep output is consumed line-by-line via
//     utils.RunWithContextStream instead of buffering the whole stdout.
//
// Only roots that exist as directories are scanned; when none exist the scan is
// a no-op returning an empty slice (not an error).
func ScanCorpus(ctx context.Context, jobID string, roots []string, platform string) ([]models.SecretModel, error) {
	return scanCorpusWithOpts(ctx, jobID, roots, platform, ScanOptions{})
}

// ScanOptions tunes a single scanCorpusWithOpts pass without changing the
// stable ScanCorpus signature. Text enables ripgrep's -a/--text so packed
// binary artifacts (native .so libraries, resources.arsc, Flutter kernel blobs,
// React-Native bundles) are scanned instead of skipped as binary; ExtraExcludes
// are additional ripgrep "-g","!glob" pairs appended after the default
// asset/binary-resource excludes (used to keep the binary pass from re-scanning
// the already-text-scanned smali/res/original trees).
type ScanOptions struct {
	Text          bool
	ExtraExcludes []string
}

// ScanCorpusText is the binary-safe sibling of ScanCorpus: it runs ripgrep with
// -a/--text so native libraries, resources.arsc and bundled assets (which
// ripgrep would otherwise skip as binary) are searched. extraExcludes are extra
// "-g","!glob" pairs appended after the default excludes so the caller can keep
// this pass from re-scanning roots already covered by the text pass. Attribution,
// precision and sanitize are identical to ScanCorpus (SCAN-1/RECALL/PRECISION).
func ScanCorpusText(ctx context.Context, jobID string, roots []string, platform string, extraExcludes []string) ([]models.SecretModel, error) {
	return scanCorpusWithOpts(ctx, jobID, roots, platform, ScanOptions{Text: true, ExtraExcludes: extraExcludes})
}

// buildRgArgs assembles the ripgrep argument list for a corpus scan. It is
// factored out of scanCorpusWithOpts so the arg shaping (the -a/--text toggle,
// exclude ordering, root placement) is unit-testable without shelling out to rg.
func buildRgArgs(patternFilePath string, excludeGlobs, existing []string, opts ScanOptions) []string {
	base := []string{"-n", "--file", patternFilePath, "--multiline"}
	if opts.Text {
		// -a/--text: scan binary files as text so NUL-laden artifacts (.so,
		// resources.arsc, kernel_blob.bin, index.android.bundle) are searched
		// rather than silently skipped by ripgrep's binary detection.
		//
		// -o/--only-matching: emit only the matched secret, not the whole line.
		// Packed binaries have newline-sparse regions, so a whole-line match can
		// span megabytes; -o keeps each emitted token down to the secret itself,
		// which is both the correct SecretString for a binary hit and the primary
		// guard against pathological line lengths (the stream reader truncates as
		// a backstop).
		base = append(base, "-a", "-o")
	}
	args := append(base, excludeGlobs...)
	args = append(args, opts.ExtraExcludes...)
	args = append(args, existing...)
	return args
}

func scanCorpusWithOpts(ctx context.Context, jobID string, roots []string, platform string, opts ScanOptions) ([]models.SecretModel, error) {
	log.WithFields(log.Fields{
		"job_id":   jobID,
		"platform": normalizePlatform(platform),
		"text":     opts.Text,
	}).Info("Starting batch pattern scan")

	patternCache, err := GetPatternCache(jobID, platform)
	if err != nil {
		// No patterns to scan is not a scan failure; mirror the historical
		// "empty result" behavior rather than erroring.
		log.WithFields(log.Fields{
			"job_id": jobID,
			"error":  err.Error(),
		}).Warn("No patterns available for scanning")
		return []models.SecretModel{}, nil
	}

	// Keep only roots that actually exist as directories so a missing dir does
	// not make ripgrep exit 2 and clobber otherwise-valid results (SCAN-2).
	var existing []string
	for _, dir := range roots {
		if st, statErr := os.Stat(dir); statErr == nil && st.IsDir() {
			existing = append(existing, dir)
		}
	}
	if len(existing) == 0 {
		log.WithFields(log.Fields{
			"job_id": jobID,
		}).Warn("No search roots exist; nothing to scan")
		return []models.SecretModel{}, nil
	}

	// Write the cached patterns.txt body to a temp file for ripgrep --file.
	patternFile, tmpErr := os.CreateTemp("", "morf-patterns-*.txt")
	if tmpErr != nil {
		log.WithFields(log.Fields{
			"job_id": jobID,
			"error":  tmpErr.Error(),
		}).Error("Failed to create pattern file")
		return nil, fmt.Errorf("failed to create pattern file: %w", tmpErr)
	}
	patternFilePath := patternFile.Name()
	defer os.Remove(patternFilePath)
	if _, writeErr := patternFile.Write(patternCache.PatternsTxt); writeErr != nil {
		patternFile.Close()
		log.WithFields(log.Fields{
			"job_id": jobID,
			"error":  writeErr.Error(),
		}).Error("Failed to write pattern file")
		return nil, fmt.Errorf("failed to write pattern file: %w", writeErr)
	}
	if closeErr := patternFile.Close(); closeErr != nil {
		return nil, fmt.Errorf("failed to close pattern file: %w", closeErr)
	}

	// NOISE-1: exclude asset/binary resource directories that never hold real
	// secrets (decompiled drawables, mipmaps, colors, animations, fonts). apktool
	// decodes binary XML to text, so ripgrep would otherwise grep e.g.
	// res/drawable/*.xml and surface hundreds of low-confidence false positives.
	// res/values (strings.xml can legitimately hold API keys) and the smali
	// source tree are deliberately kept. Harmless for iOS (no such paths).
	excludeGlobs := []string{
		"-g", "!**/res/drawable*/**",
		"-g", "!**/res/mipmap*/**",
		"-g", "!**/res/color*/**",
		"-g", "!**/res/anim*/**",
		"-g", "!**/res/animator*/**",
		"-g", "!**/res/font*/**",
	}
	args := buildRgArgs(patternFilePath, excludeGlobs, existing, opts)

	log.WithFields(log.Fields{
		"job_id": jobID,
		"roots":  existing,
		"text":   opts.Text,
	}).Info("Running batch pattern scan with ripgrep")

	// SCAN-7 / SCAN-2mem: build the result slice incrementally from streamed
	// ripgrep output instead of buffering+splitting the whole stdout.
	secretModel := make([]models.SecretModel, 0, 256)
	onLine := func(b []byte) error {
		line := strings.TrimSpace(string(b))
		if line == "" {
			return nil
		}
		// ripgrep -n output is "file:lineno:content".
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			return nil
		}
		lineNumber, convErr := strconv.Atoi(parts[1])
		if convErr != nil {
			// Malformed line number; skip this line rather than aborting the scan.
			return nil
		}
		content := strings.TrimSpace(parts[2])

		// Emit one finding per match span on the line: a packed line can carry
		// multiple distinct secrets (RECALL), each reported with its exact matched
		// value (PRECISION). FindingsForLine guarantees at least one finding so a
		// ripgrep hit is never dropped, and never an empty SecretString. Row 028's
		// "unattributed" sentinel is preserved inside FindingsForLine.
		secretModel = append(secretModel, patternCache.FindingsForLine(parts[0], lineNumber, content)...)
		return nil
	}

	ripgrepStart := time.Now()
	scanErr := utils.RunWithContextStream(ctx, onLine, "rg", args...)
	metrics.RecordToolExecution("ripgrep", time.Since(ripgrepStart).Seconds())

	if scanErr != nil {
		code := utils.ExitCodeOf(scanErr)
		if code == 1 {
			// ripgrep exit 1 == genuinely no matches (no lines were streamed).
			log.WithFields(log.Fields{
				"job_id": jobID,
			}).Info("Batch scan completed, no secrets found")
			return []models.SecretModel{}, nil
		}
		// SCAN-1: a timeout (-2), a ripgrep error (>= 2) or any other failure
		// must NOT be silently treated as "no secrets".
		log.WithFields(log.Fields{
			"job_id":    jobID,
			"exit_code": code,
			"error":     scanErr.Error(),
		}).Error("Ripgrep batch scan failed")
		return nil, fmt.Errorf("ripgrep failed (exit %d): %w", code, scanErr)
	}

	log.WithFields(log.Fields{
		"job_id":       jobID,
		"secret_count": len(secretModel),
	}).Info("Batch pattern scan completed")

	return secretModel, nil
}

// ExtractSecret pulls the likely secret value out of a matched ripgrep line
// using a small ordered set of heuristics: value between XML tags, then value
// between the first pair of quotes, then value after the last colon, else the
// whole content.
func ExtractSecret(content string) string {
	// Check for content enclosed in XML tags.
	if strings.Contains(content, ">") && strings.Contains(content, "<") {
		begin := strings.Index(content, ">") + 1
		end := strings.LastIndex(content, "<")
		if begin < end && begin > 0 && end > 0 { // Ensure indices are valid
			return strings.TrimSpace(content[begin:end])
		}
	}

	// Check if the content contains quotes, often used to enclose secrets.
	if strings.Count(content, "\"") >= 2 {
		// Extract the content between the first pair of quotes.
		parts := strings.SplitN(content, "\"", 3)
		if len(parts) > 1 {
			return parts[1]
		}
	}

	// Fallback: use the content after the last colon, if present.
	lastColon := strings.LastIndex(content, ":")
	if lastColon != -1 {
		// Trim any potential leading or trailing whitespace around the secret.
		return strings.TrimSpace(content[lastColon+1:])
	}

	// If no known patterns are detected, return the full content as a fallback.
	return content
}

// SanitizeSecrets deduplicates findings on the (SecretType, SecretString) key,
// preserving the first occurrence of each, and logs only non-sensitive metadata
// per finding (never the plaintext secret value, SCAN-9).
//
// DEDUP-BY-VALUE: a hardcoded secret is ONE finding no matter how many files or
// lines it appears on — the same key literal repeated across a large app was
// previously counted once per (file,line), inflating the count into the
// hundreds. Keying on (type, value) collapses those into a single distinct
// finding (first location preserved), which is what "N secrets exposed" should
// mean. Two genuinely different values, or the same value flagged by two
// different rule types, remain distinct.
func SanitizeSecrets(scannerData []models.SecretModel) []models.SecretModel {
	sanitizedSecrets := make([]models.SecretModel, 0, len(scannerData))
	type secretKey struct {
		secretType   string
		secretString string
	}
	uniqueSecrets := make(map[secretKey]struct{}, len(scannerData))

	for _, secret := range scannerData {
		key := secretKey{
			secretType:   secret.SecretType,
			secretString: secret.SecretString,
		}
		// If the secret is not already in uniqueSecrets, add it.
		if _, exists := uniqueSecrets[key]; !exists {
			uniqueSecrets[key] = struct{}{}
			sanitizedSecrets = append(sanitizedSecrets, secret)
		}
	}

	// SCAN-9: do NOT log or print the plaintext secret value. Log only
	// non-sensitive metadata per finding (type, file, line, confidence) plus an
	// aggregate count. The secret string never leaves this process via logs.
	for _, secret := range sanitizedSecrets {
		log.WithFields(log.Fields{
			"secret_type":   secret.Type,
			"file_location": secret.FileLocation,
			"line_no":       secret.LineNo,
			"confidence":    secret.SecretConfidence,
		}).Info("Secret detected")
	}
	log.WithFields(log.Fields{
		"secret_count": len(sanitizedSecrets),
	}).Info("Secret scan finished")

	return sanitizedSecrets
}
