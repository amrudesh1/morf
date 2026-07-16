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
	"morf/detect"
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
		// -f (force): CreateWorkspace pre-creates the output/apk/source dir, and
		// apktool refuses to write into an existing directory without -f. The
		// per-job workspace is freshly created and isolated, so forcing is safe.
		_, sourceError = utils.RunWithContext(srcCtx, "java", jvmHeapFlag(), "-jar", apktoolJar(), "d", "-f", "-r", apkPath, "-o", jobCtx.GetSourceDir())
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
		// -f (force): see the sources goroutine above — the res dir is pre-created
		// by CreateWorkspace, so apktool needs -f to decode into it.
		_, resError = utils.RunWithContext(resCtx, "java", jvmHeapFlag(), "-jar", apktoolJar(), "d", "-f", "-s", apkPath, "-o", jobCtx.GetResDir())
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

// PatternInfo re-exports the shared detect.PatternInfo so existing apk code and
// tests keep referring to the type by its historical local name. The pattern
// matching CORE now lives in the morf/detect package (shared with ios).
type PatternInfo = detect.PatternInfo

// scPatternCache is a thin, test-facing wrapper over the shared detect pattern
// cache. It keeps the historical unexported field surface (patterns/combined/
// groupToPattern) so the apk pure tests can construct it directly and exercise
// the shared attribution logic via findMatchingPattern.
type scPatternCache struct {
	patterns       []PatternInfo
	combined       *regexp.Regexp
	groupToPattern []int
}

// detectView adapts this wrapper back into a detect.PatternCache so attribution
// runs the single shared implementation.
func (c *scPatternCache) detectView() *detect.PatternCache {
	return &detect.PatternCache{
		Patterns:       c.patterns,
		Combined:       c.combined,
		GroupToPattern: c.groupToPattern,
	}
}

// findMatchingPattern delegates to the shared detect attribution logic.
func (c *scPatternCache) findMatchingPattern(content string) *PatternInfo {
	return c.detectView().FindMatchingPattern(content)
}

// scBuildCombinedRegex delegates to the shared detect implementation, preserved
// under its historical name for the apk pure tests.
func scBuildCombinedRegex(patterns []PatternInfo) (*regexp.Regexp, []int) {
	return detect.BuildCombinedRegex(patterns)
}

// StartScan is the historical, error-swallowing entry point preserved for
// existing callers. It delegates to StartScanE with a background context.
func StartScan(jobCtx *utils.JobContext) []models.SecretModel {
	secrets, _ := StartScanE(context.Background(), jobCtx)
	return secrets
}

// StartScanE runs the batch ripgrep pattern scan over the APK's decompiled
// sources and decoded resources and returns the detected secrets plus an error.
// The pattern-load/compile/attribution/scan CORE lives in morf/detect; this
// wrapper only assembles the APK-specific search roots (SCAN-2) and hands them
// to detect.ScanCorpus, keeping the Android pipeline behavior unchanged.
func StartScanE(ctx context.Context, jobCtx *utils.JobContext) ([]models.SecretModel, error) {
	// SCAN-2: text pass over decompiled sources (smali) and decoded resources.
	// PLATFORM-SCOPE: Android scan → only "android"/"any" patterns run (iOS-only
	// rules like "iOS Keychain Access Group" are excluded).
	roots := []string{jobCtx.GetSourceDir(), jobCtx.GetResDir()}
	textSecrets, err := detect.ScanCorpus(ctx, jobCtx.JobID, roots, "android")
	if err != nil {
		return nil, err
	}

	// SCAN-2 (binary coverage): native libraries (lib/**/*.so), bundled assets
	// (Flutter flutter_assets/ blobs, React-Native index.android.bundle), the
	// compiled resources.arsc and embedded config JSON (google-services.json)
	// are binary and would be skipped by ripgrep's binary detection, so a second
	// --text pass is required. SCAN-1: a failure here is surfaced, never treated
	// as "no secrets". Downstream SanitizeSecrets dedups across the two passes.
	binRoots := androidBinaryRoots(jobCtx)
	binSecrets, binErr := detect.ScanCorpusText(ctx, jobCtx.JobID, binRoots, "android", androidBinaryExcludes())
	if binErr != nil {
		return nil, binErr
	}

	return append(textSecrets, binSecrets...), nil
}

// SanitizeSecrets deduplicates findings and logs only non-sensitive metadata.
// It is preserved as an apk-package entry point delegating to the shared core.
func SanitizeSecrets(scannerData []models.SecretModel) []models.SecretModel {
	return detect.SanitizeSecrets(scannerData)
}

// extractSecret pulls the likely secret value out of a matched ripgrep line.
// Preserved under its historical local name for the apk pure tests; delegates
// to the shared detect implementation.
func extractSecret(content string) string {
	return detect.ExtractSecret(content)
}
