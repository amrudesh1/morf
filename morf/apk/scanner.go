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
package apk

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

// toolsDir returns the directory holding the bundled JVM tools (apktool.jar,
// apkanalyzer.jar). MED-hardcoded-paths: it honours MORF_TOOLS_DIR, falling back
// to the historical "/app/tools" default so containerized deployments keep
// working unchanged.
func toolsDir() string {
	if d := strings.TrimSpace(os.Getenv("MORF_TOOLS_DIR")); d != "" {
		return d
	}
	return "/app/tools"
}

// apktoolJar / apkanalyzerJar build the absolute jar path under toolsDir().
func apktoolJar() string     { return filepath.Join(toolsDir(), "apktool.jar") }
func apkanalyzerJar() string { return filepath.Join(toolsDir(), "apkanalyzer.jar") }

// jvmHeapFlag returns the JVM -Xmx flag that bounds per-process heap (and thus
// caps per-JVM RSS) for the apktool / apkanalyzer invocations (SC-3). It honours
// MORF_JVM_MAX_HEAP_MB (default 2048 MB) and must be passed as a JVM argument
// BEFORE -jar / -cp.
func jvmHeapFlag() string {
	mb := 2048
	if v := strings.TrimSpace(os.Getenv("MORF_JVM_MAX_HEAP_MB")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			mb = n
		}
	}
	return fmt.Sprintf("-Xmx%dm", mb)
}

type SecretPatterns struct {
	Patterns []struct {
		Pattern struct {
			Name       string `yaml:"name"`
			Regex      string `yaml:"regex"`
			Confidence string `yaml:"confidence"`
			// Enabled is decoded as a pointer so an absent value (nil) is
			// distinguishable from an explicit `enabled: false`. nil/absent
			// defaults to enabled; only an explicit false skips the pattern.
			Enabled *bool `yaml:"enabled"`
		} `yaml:"pattern"`
	} `yaml:"patterns"`
}

// StartSecScan is the historical, error-swallowing entry point preserved for
// existing callers. It delegates to StartSecScanE with a background context.
func StartSecScan(apkPath string, jobCtx *utils.JobContext) []models.SecretModel {
	secrets, _ := StartSecScanE(context.Background(), apkPath, jobCtx)
	return secrets
}

// StartSecScanE decompiles the APK (sources + resources in parallel) and runs
// the batch pattern scan, returning the sanitized secrets plus an error.
//
//   - ZIPBOMB-1: the archive is validated with utils.CheckAPKSafe BEFORE any
//     decompilation; an unsafe archive is rejected and never handed to apktool.
//   - CONC-1: the caller-supplied ctx is threaded into every subprocess — the
//     two apktool invocations derive a timeout-context from ctx, and ctx flows
//     into the ripgrep scan via StartScanE.
func StartSecScanE(ctx context.Context, apkPath string, jobCtx *utils.JobContext) ([]models.SecretModel, error) {
	// ZIPBOMB-1: refuse to decompile an archive that fails the zip-bomb guard.
	if safeErr := utils.CheckAPKSafe(apkPath); safeErr != nil {
		log.WithFields(log.Fields{
			"job_id":   jobCtx.JobID,
			"apk_path": apkPath,
			"error":    safeErr.Error(),
		}).Error("APK rejected by zip-bomb safety check; refusing to decompile")
		metrics.RecordScan("failed")
		metrics.RecordError("zipbomb")
		return nil, fmt.Errorf("apk safety check failed for %q: %w", apkPath, safeErr)
	}

	scanStart := time.Now()
	metrics.IncrementActiveScans()
	defer metrics.DecrementActiveScans()

	log.WithFields(log.Fields{
		"job_id":   jobCtx.JobID,
		"apk_path": apkPath,
	}).Info("Starting parallel decompilation of APK file (sources and resources)")

	var wg sync.WaitGroup
	var sourceError error
	var resError error
	var sourceStart, resStart time.Time

	// Decompile sources and resources in parallel.
	wg.Add(2)

	// Goroutine 1: Decompile sources (-r flag).
	go func() {
		defer wg.Done()
		sourceStart = time.Now()
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Info("Decompiling APK sources (parallel)")

		// CONC-1: derive the decompile timeout from the caller's ctx so a
		// cancelled/expired request also tears down apktool and its children.
		srcCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		_, sourceError = utils.RunWithContext(srcCtx, "java", jvmHeapFlag(), "-jar", apktoolJar(), "d", "-r", apkPath, "-o", jobCtx.GetSourceDir())
		metrics.RecordToolExecution("apktool_sources", time.Since(sourceStart).Seconds())

		if sourceError != nil {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"error":  sourceError.Error(),
			}).Error("Error while decompiling APK sources")
		} else {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
			}).Info("Decompiling APK sources successful")
		}
	}()

	// Goroutine 2: Decompile resources (-s flag).
	go func() {
		defer wg.Done()
		resStart = time.Now()
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Info("Decompiling APK resources (parallel)")

		resCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		_, resError = utils.RunWithContext(resCtx, "java", jvmHeapFlag(), "-jar", apktoolJar(), "d", "-s", apkPath, "-o", jobCtx.GetResDir())
		metrics.RecordToolExecution("apktool_resources", time.Since(resStart).Seconds())

		if resError != nil {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"error":  resError.Error(),
			}).Error("Error while decompiling APK resources")
		} else {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
			}).Info("Decompiling APK resources successful")
		}
	}()

	// Wait for both decompilation phases to complete.
	wg.Wait()

	// Check if both phases completed successfully.
	if sourceError != nil || resError != nil {
		log.WithFields(log.Fields{
			"job_id":       jobCtx.JobID,
			"source_error": sourceError != nil,
			"res_error":    resError != nil,
		}).Error("Decompilation failed in one or more phases")
		metrics.RecordScan("failed")
		metrics.RecordError("decompilation")
		// A corrupt/unparseable archive fails identically on every attempt, so
		// tag the error with ErrNonRetryable: the worker's isRetryable then
		// classifies it via errors.Is (typed) rather than message-text matching,
		// sending it straight to the DLQ with no wasted retries.
		return nil, fmt.Errorf("apk decompilation failed (source_err=%v, res_err=%v): %w", sourceError, resError, utils.ErrNonRetryable)
	}

	decompileDuration := time.Since(scanStart).Seconds()
	metrics.RecordScanDuration("decompile", decompileDuration)

	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
	}).Info("Parallel decompilation of APK file successful")

	// Start pattern scanning (ctx threaded through to ripgrep).
	patternStart := time.Now()
	rawSecrets, scanErr := StartScanE(ctx, jobCtx)
	if scanErr != nil {
		metrics.RecordScanDuration("pattern_scan", time.Since(patternStart).Seconds())
		metrics.RecordScan("failed")
		metrics.RecordError("pattern_scan")
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  scanErr.Error(),
		}).Error("Pattern scan failed")
		return nil, fmt.Errorf("pattern scan failed: %w", scanErr)
	}

	secrets := SanitizeSecrets(rawSecrets)
	patternDuration := time.Since(patternStart).Seconds()
	metrics.RecordScanDuration("pattern_scan", patternDuration)

	// Record secrets found.
	metrics.RecordSecretsFound(float64(len(secrets)))

	totalDuration := time.Since(scanStart).Seconds()
	metrics.RecordScanDuration("total", totalDuration)
	metrics.RecordScan("success")

	return secrets, nil
}

func readPatternFile(patternFilePath string) []byte {
	yamlFile, _ := utils.ReadFile(utils.GetAppFS(), patternFilePath)
	return yamlFile
}

// PatternInfo stores pattern information for batch scanning.
// Compiled is the pre-compiled regex; nil only if Regex failed to compile.
type PatternInfo struct {
	Name       string
	Regex      string
	Confidence string
	Compiled   *regexp.Regexp
}

// patternsDir is the on-disk location of the secret pattern YAML files.
// MED-hardcoded-paths: it delegates to utils.GetPatternsDir so it honours the
// SAME MORF_PATTERNS_DIR env var (default "/app/patterns") used by the utils
// pattern-CRUD track, rather than hardcoding the literal.
func patternsDir() string { return utils.GetPatternsDir() }

// scPatternCache is an immutable snapshot of the loaded+compiled pattern set
// together with the precomputed artifacts derived from it. Once published it is
// never mutated, so concurrent scans can read it without locking — the only
// synchronization is around swapping the package-level pointer (SCAN-4).
type scPatternCache struct {
	// patterns is every pattern loaded from patternsDir (RE2-compilable or not).
	patterns []PatternInfo
	// combined is a single alternation regex "(p0)|(p1)|..." built from the
	// RE2-compilable patterns only; nil if none compile or the union fails.
	combined *regexp.Regexp
	// groupToPattern maps a submatch-group index of `combined` back to the
	// index into `patterns` it belongs to (index 0 == whole match == -1).
	groupToPattern []int
	// patternsTxt is the generated patterns.txt body (one regex per line),
	// cached so it is built once rather than per scan.
	patternsTxt []byte
	// builtFrom is the max ModTime observed in patternsDir at build time; the
	// cache is rebuilt when a newer entry appears.
	builtFrom time.Time
}

// scCache holds the current pattern cache, guarded by scCacheMu (SCAN-4).
var (
	scCacheMu sync.RWMutex
	scCache   *scPatternCache
)

// scGetPatternCache returns a fresh, immutable pattern cache, rebuilding it only
// when patternsDir has changed since the last build (detected via the max entry
// ModTime). This replaces the per-scan load+compile that previously ran on every
// invocation (SCAN-4).
func scGetPatternCache(jobID string) (*scPatternCache, error) {
	files := utils.ReadDir(utils.GetAppFS(), patternsDir())

	var maxMod time.Time
	for _, f := range files {
		if mt := f.ModTime(); mt.After(maxMod) {
			maxMod = mt
		}
	}

	// Fast path: an existing cache that is at least as new as patternsDir.
	scCacheMu.RLock()
	cached := scCache
	scCacheMu.RUnlock()
	if cached != nil && !maxMod.After(cached.builtFrom) {
		return cached, nil
	}

	// Slow path: (re)build under the write lock, double-checking after acquiring
	// it so concurrent scans build at most once.
	scCacheMu.Lock()
	defer scCacheMu.Unlock()
	if scCache != nil && !maxMod.After(scCache.builtFrom) {
		return scCache, nil
	}

	built, err := scBuildPatternCache(files, maxMod, jobID)
	if err != nil {
		return nil, err
	}
	scCache = built
	return built, nil
}

// scBuildPatternCache loads every YAML pattern file in patternsDir, compiles the
// patterns, and precomputes the combined regex, group map and patterns.txt body.
func scBuildPatternCache(files []fs.FileInfo, maxMod time.Time, jobID string) (*scPatternCache, error) {
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
			allPatterns = append(allPatterns, PatternInfo{
				Name:       pattern.Pattern.Name,
				Regex:      pattern.Pattern.Regex,
				Confidence: pattern.Pattern.Confidence,
				Compiled:   compiled,
			})
		}
	}

	if len(allPatterns) == 0 {
		return nil, fmt.Errorf("no secret patterns found in %s", patternsDir())
	}

	// Build the patterns.txt body once (one regex per line).
	var txt strings.Builder
	for _, p := range allPatterns {
		txt.WriteString(p.Regex)
		txt.WriteByte('\n')
	}

	combined, groupToPattern := scBuildCombinedRegex(allPatterns)

	log.WithFields(log.Fields{
		"job_id":        jobID,
		"pattern_count": len(allPatterns),
		"combined":      combined != nil,
	}).Info("Built pattern cache for batch scanning")

	return &scPatternCache{
		patterns:       allPatterns,
		combined:       combined,
		groupToPattern: groupToPattern,
		patternsTxt:    []byte(txt.String()),
		builtFrom:      maxMod,
	}, nil
}

// scBuildCombinedRegex builds a single alternation regex with one wrapping
// capture group per RE2-compilable pattern: "(p0)|(p1)|...". The returned slice
// maps every submatch-group index of the combined regex back to the index into
// `patterns` that owns it, so a single FindStringSubmatchIndex call identifies
// the matching pattern in O(1) amortized per line (SCAN-3). Returns (nil, nil)
// when no pattern is RE2-compilable or the union itself fails to compile.
func scBuildCombinedRegex(patterns []PatternInfo) (*regexp.Regexp, []int) {
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
		// Degrade gracefully: findMatchingPattern falls back to per-pattern
		// matching when combined is nil.
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to build combined pattern regex; using per-pattern attribution fallback")
		return nil, nil
	}
	return combined, groupToPattern
}

// findMatchingPattern identifies which loaded pattern matches content. It runs
// the cached combined regex exactly once (SCAN-3); the first non-empty submatch
// group names the owning pattern. Lines the combined regex cannot attribute fall
// through to the non-RE2 pattern path.
func (c *scPatternCache) findMatchingPattern(content string) *PatternInfo {
	if c.combined != nil {
		loc := c.combined.FindStringSubmatchIndex(content)
		if loc != nil {
			// loc[2*g], loc[2*g+1] are the bounds of group g (g==0 is whole match).
			for g := 1; 2*g+1 < len(loc); g++ {
				if loc[2*g] < 0 {
					continue // group g did not participate in the match.
				}
				if g < len(c.groupToPattern) {
					if pi := c.groupToPattern[g]; pi >= 0 && pi < len(c.patterns) {
						return &c.patterns[pi]
					}
				}
			}
		}
	} else {
		// Safety net: the combined regex could not be built. Fall back to the
		// original per-pattern scan over the RE2-compilable patterns.
		for i := range c.patterns {
			if c.patterns[i].Compiled != nil && c.patterns[i].Compiled.MatchString(content) {
				return &c.patterns[i]
			}
		}
	}

	// The combined regex did not attribute this line. It may have been matched
	// in ripgrep by a non-RE2 pattern (lookaround/backref) that Go cannot run;
	// attribute it to the first such pattern as a best effort.
	for i := range c.patterns {
		if c.patterns[i].Compiled == nil {
			return &c.patterns[i]
		}
	}
	return nil
}

// StartScan is the historical, error-swallowing entry point preserved for
// existing callers. It delegates to StartScanE with a background context.
func StartScan(jobCtx *utils.JobContext) []models.SecretModel {
	secrets, _ := StartScanE(context.Background(), jobCtx)
	return secrets
}

// StartScanE runs the batch ripgrep pattern scan and returns the detected
// secrets plus an error.
//
//   - SCAN-1: ripgrep failures are no longer silently swallowed. Exit code 1 is
//     a genuine "no matches" (empty result, nil error); a timeout or exit >= 2
//     is surfaced as an error so a failed scan is never mistaken for "no secrets".
//   - SCAN-2: both the decompiled sources and the decoded resources (appres) are
//     handed to ripgrep as search roots, so decoded resources are actually scanned.
//   - SCAN-7 / SCAN-2mem: ripgrep output is consumed line-by-line via
//     RunWithContextStream instead of buffering the whole stdout and splitting it.
func StartScanE(ctx context.Context, jobCtx *utils.JobContext) ([]models.SecretModel, error) {
	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
	}).Info("Starting batch pattern scan on the APK file")

	cache, err := scGetPatternCache(jobCtx.JobID)
	if err != nil {
		// No patterns to scan is not a scan failure; mirror the historical
		// "empty result" behavior rather than erroring.
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  err.Error(),
		}).Warn("No patterns available for scanning")
		return []models.SecretModel{}, nil
	}

	// Write the cached patterns.txt body to this job's tmp dir for ripgrep --file.
	patternFile := filepath.Join(jobCtx.GetTmpDir(), "patterns.txt")
	if writeErr := os.WriteFile(patternFile, cache.patternsTxt, 0o600); writeErr != nil {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
			"error":  writeErr.Error(),
		}).Error("Failed to create pattern file")
		return nil, fmt.Errorf("failed to write pattern file: %w", writeErr)
	}
	defer os.Remove(patternFile)

	// SCAN-2: search both decompiled sources and decoded resources. Only include
	// roots that actually exist so a missing appres dir does not make ripgrep
	// exit 2 and clobber otherwise-valid results.
	var roots []string
	for _, dir := range []string{jobCtx.GetSourceDir(), jobCtx.GetResDir()} {
		if st, statErr := os.Stat(dir); statErr == nil && st.IsDir() {
			roots = append(roots, dir)
		}
	}
	if len(roots) == 0 {
		log.WithFields(log.Fields{
			"job_id": jobCtx.JobID,
		}).Warn("No search roots exist; nothing to scan")
		return []models.SecretModel{}, nil
	}

	args := append([]string{"-n", "--file", patternFile, "--multiline"}, roots...)

	log.WithFields(log.Fields{
		"job_id": jobCtx.JobID,
		"roots":  roots,
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

		// Row 028: when neither the combined RE2 regex nor the non-RE2 fallback
		// can attribute a ripgrep hit (ripgrep supports lookaround/backref/
		// multiline semantics Go's regexp does not), label it with an explicit
		// sentinel type rather than silently borrowing patterns[0]'s identity.
		matched := cache.findMatchingPattern(content)
		secretType := "unattributed"
		// D-1: default to a valid ENUM member ("low") so an unattributed hit
		// never inserts an empty-string confidence into the column.
		secretConfidence := "low"
		if matched != nil {
			secretType = matched.Name
			secretConfidence = matched.Confidence
		}

		secretModel = append(secretModel, models.SecretModel{
			Type:             secretType,
			LineNo:           lineNumber,
			FileLocation:     strings.Clone(parts[0]),
			SecretType:       secretType,
			SecretString:     strings.Clone(extractSecret(content)),
			SecretConfidence: secretConfidence,
		})
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
				"job_id": jobCtx.JobID,
			}).Info("Batch scan completed, no secrets found")
			return []models.SecretModel{}, nil
		}
		// SCAN-1: a timeout (-2), a ripgrep error (>= 2) or any other failure
		// must NOT be silently treated as "no secrets".
		log.WithFields(log.Fields{
			"job_id":    jobCtx.JobID,
			"exit_code": code,
			"error":     scanErr.Error(),
		}).Error("Ripgrep batch scan failed")
		return nil, fmt.Errorf("ripgrep failed (exit %d): %w", code, scanErr)
	}

	log.WithFields(log.Fields{
		"job_id":       jobCtx.JobID,
		"secret_count": len(secretModel),
	}).Info("Batch pattern scan completed")

	return secretModel, nil
}

func extractSecret(content string) string {

	// Check for content enclosed in XML tags

	if strings.Contains(content, ">") && strings.Contains(content, "<") {
		begin := strings.Index(content, ">") + 1
		end := strings.LastIndex(content, "<")
		if begin < end && begin > 0 && end > 0 { // Ensure indices are valid
			return strings.TrimSpace(content[begin:end])
		}
	}

	// Check if the content contains quotes, often used to enclose secrets
	if strings.Count(content, "\"") >= 2 {
		// Extract the content between the first pair of quotes
		parts := strings.SplitN(content, "\"", 3)
		if len(parts) > 1 {
			return parts[1]
		}
	}

	// Fallback: use the content after the last colon, if present
	lastColon := strings.LastIndex(content, ":")
	if lastColon != -1 {
		// Trim any potential leading or trailing whitespace around the secret
		return strings.TrimSpace(content[lastColon+1:])
	}

	// If no known patterns are detected, return the full content as a fallback
	return content
}

func SanitizeSecrets(scanner_data []models.SecretModel) []models.SecretModel {
	sanitizedSecrets := make([]models.SecretModel, 0, len(scanner_data))
	// Row 025: key uniqueness on the composite (FileLocation, LineNo,
	// SecretString) so two genuinely distinct findings that happen to share an
	// extracted value are preserved, and empty-value matches at different
	// locations are not all collapsed into a single "" entry.
	type secretKey struct {
		fileLocation string
		lineNo       int
		secretString string
	}
	uniqueSecrets := make(map[secretKey]struct{}, len(scanner_data))

	for _, secret := range scanner_data {
		key := secretKey{
			fileLocation: secret.FileLocation,
			lineNo:       secret.LineNo,
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
