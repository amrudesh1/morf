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

// firebase_misconfig.go — unit P2b
//
// Passive (always-on, offline) and opt-in active Firebase/GCP misconfiguration
// finder for Android APK scans.
//
// PASSIVE findings (emitted unconditionally, no network):
//   - firebase-rtdb-present    when a Firebase Realtime Database URL is found.
//   - firebase-storage-present when a Cloud Storage bucket is found.
//
// ACTIVE finding (only when MORF_ENABLE_VERIFICATION=="true"):
//   - firebase-rtdb-world-readable when the RTDB rules endpoint returns HTTP 200
//     (world-readable). A 401/403 means the rules are locked.
//
// Active probe safety: read-only GET, no redirects, bounded timeout, rate-limited
// (matching verify/ package posture). Evidence fields NEVER contain server-returned
// data — only the DB host and the HTTP status code.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"morf/models"
	"morf/utils"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// MASVS / rule constants for Firebase misconfig findings.
const (
	// masvsIDStorage1 is the OWASP MASVS control for data-storage exposure.
	masvsIDStorage1 = "MASVS-STORAGE-1"

	// ruleFirebaseRTDBPresent is the stable rule ID for the passive RTDB finding.
	ruleFirebaseRTDBPresent = "firebase-rtdb-present"
	// ruleFirebaseStoragePresent is the stable rule ID for the passive storage finding.
	ruleFirebaseStoragePresent = "firebase-storage-present"
	// ruleFirebaseRTDBWorldReadable is the stable rule ID for the active RTDB finding.
	ruleFirebaseRTDBWorldReadable = "firebase-rtdb-world-readable"

	// categoryConfig is the finding category for Firebase config findings.
	categoryConfig = "config"

	// locationGoogleServices is the file location reported for Android Firebase findings.
	locationGoogleServices = "google-services.json"

	// firebaseEnvVerificationEnabled is the environment variable gate for active probing.
	// Matches the verify/ package constant (MORF_ENABLE_VERIFICATION) so the same
	// env var controls both secret verification and Firebase active probes.
	firebaseEnvVerificationEnabled = "MORF_ENABLE_VERIFICATION"

	// rtdbProbeTimeout caps a single RTDB rules probe request.
	rtdbProbeTimeout = 8 * time.Second
	// rtdbUserAgent is sent on every outbound RTDB probe.
	rtdbUserAgent = "MORF-firebase-probe"
)

// rtdbLimiter is the module-level rate limiter for RTDB probe requests.
// 5 req/s steady state, burst 5 — matching the verify/ package safety controls.
var rtdbLimiter = rate.NewLimiter(rate.Limit(5), 5)

// FirebaseResourceConfig holds the Firebase resource URLs/names extracted from a
// config file. These are resource identifiers, not secrets, and are safe to
// include in Evidence fields.
type FirebaseResourceConfig struct {
	// RTDBURL is the Firebase Realtime Database URL, e.g.
	// "https://myproject.firebaseio.com" or
	// "https://myproject-default-rtdb.firebaseio.com".
	RTDBURL string
	// StorageBucket is the Cloud Storage bucket name, e.g. "myproject.appspot.com".
	StorageBucket string
}

// googleServicesTopLevel is the minimal top-level google-services.json shape
// needed to extract DATABASE_URL and STORAGE_BUCKET from project_info. These
// fields are absent from the internal googleServicesConfig struct (which only
// models project_id and project_number), so we parse them independently.
type googleServicesTopLevel struct {
	ProjectInfo struct {
		DatabaseURL   string `json:"database_url"`
		StorageBucket string `json:"storage_bucket"`
	} `json:"project_info"`
}

// AndroidFirebaseResourceConfig extracts the FirebaseResourceConfig from the raw
// google-services.json bytes and the already-parsed googleServicesConfig.
//
// DATABASE_URL and STORAGE_BUCKET live in project_info in the full
// google-services.json (the Firebase console emits them). When DATABASE_URL is
// absent we derive the conventional RTDB URL from the project_id:
//
//	https://<project_id>-default-rtdb.firebaseio.com
//
// (Firebase projects created after 2021 use this naming; older projects use
// https://<project_id>.firebaseio.com, which the Firebase console always writes
// as the explicit database_url). When neither is resolvable we return an empty
// RTDBURL and skip the RTDB findings.
func AndroidFirebaseResourceConfig(rawJSON []byte, cfg *googleServicesConfig) FirebaseResourceConfig {
	if cfg == nil {
		return FirebaseResourceConfig{}
	}

	var top googleServicesTopLevel
	// Best-effort parse; ignore errors — if this fails we fall back to the
	// project_id-derived URL.
	_ = json.Unmarshal(rawJSON, &top)

	dbURL := top.ProjectInfo.DatabaseURL
	if dbURL == "" && cfg.ProjectInfo.ProjectID != "" {
		// Derive the default RTDB URL from the project_id. We only emit this
		// as a passive finding when the derived host looks like a real Firebase URL.
		dbURL = "https://" + cfg.ProjectInfo.ProjectID + "-default-rtdb.firebaseio.com"
	}

	return FirebaseResourceConfig{
		RTDBURL:       dbURL,
		StorageBucket: top.ProjectInfo.StorageBucket,
	}
}

// AnalyzeAndroidFirebaseMisconfig is the Android entry point for the Firebase
// misconfig detector. It parses the raw google-services.json bytes, extracts the
// Firebase resource config, and delegates to FirebaseMisconfigFindings.
//
// It is best-effort: a nil cfg or empty rawJSON yields nil (no findings), never
// an error. The caller (detectFirebase / CollectSBOMComponents callers) already
// owns the raw bytes and the parsed config; this function reuses both.
//
// The client parameter is the HTTP transport for the active probe (injected for
// tests; pass nil for the production default). jobID is used for log correlation.
func AnalyzeAndroidFirebaseMisconfig(ctx context.Context, rawJSON []byte, cfg *googleServicesConfig, jobID string, client *http.Client) []models.PlatformFinding {
	if cfg == nil || cfg.ProjectInfo.ProjectID == "" {
		return nil
	}
	res := AndroidFirebaseResourceConfig(rawJSON, cfg)
	return FirebaseMisconfigFindings(ctx, res, locationGoogleServices, jobID, client)
}

// rtdbHostFromURL returns just the scheme+host of a Firebase Realtime Database
// URL, which is safe to include in Evidence (it is a resource address, not a
// secret). Returns the input as-is when it cannot be parsed.
func rtdbHostFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// isFirebaseRTDB reports whether the given URL looks like a Firebase Realtime
// Database URL (hosted under firebaseio.com or firebasedatabase.app).
func isFirebaseRTDB(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.Contains(lower, "firebaseio.com") ||
		strings.Contains(lower, "firebasedatabase.app")
}

// FirebaseMisconfigFindings is the shared, platform-agnostic core of the
// Firebase misconfig detector. It accepts a FirebaseResourceConfig (URLs already
// extracted from the platform-specific config), a configLocation label (the
// file path to report in findings), and an optional HTTP client for the active
// probe. Both Android (AndroidFirebaseResourceConfig) and iOS
// (IOSFirebaseResourceConfig in ios/firebase_misconfig.go) use this function.
//
// Passive findings are always emitted when a DATABASE_URL or StorageBucket is
// present. The active RTDB probe runs only when MORF_ENABLE_VERIFICATION=="true".
// Evidence fields carry only the DB host or bucket name — never secrets or
// server-returned data.
func FirebaseMisconfigFindings(ctx context.Context, res FirebaseResourceConfig, configLocation string, jobID string, client *http.Client) []models.PlatformFinding {
	var findings []models.PlatformFinding

	// --- Passive: RTDB URL present ---
	if res.RTDBURL != "" && isFirebaseRTDB(res.RTDBURL) {
		host := rtdbHostFromURL(res.RTDBURL)
		findings = append(findings, models.PlatformFinding{
			RuleID:   ruleFirebaseRTDBPresent,
			Title:    "Firebase Realtime Database URL present in config",
			Severity: models.SeverityInfo,
			MASVSID:  masvsIDPlatform1,
			Category: categoryConfig,
			Location: configLocation,
			Evidence: fmt.Sprintf("%s — verify security rules are not world-readable", host),
			Tier:     models.TierForSeverity(models.SeverityInfo),
		})

		// --- Active: probe RTDB rules (opt-in, MORF_ENABLE_VERIFICATION only) ---
		if os.Getenv(firebaseEnvVerificationEnabled) == "true" {
			worldReadable, probeErr := probeRTDBWorldReadable(ctx, res.RTDBURL, client, jobID)
			if probeErr != nil {
				log.WithFields(log.Fields{
					"job_id": jobID,
					"db":     host,
					"error":  probeErr.Error(),
				}).Debug("Firebase RTDB world-readable probe failed; passive finding only")
			} else if worldReadable {
				findings = append(findings, models.PlatformFinding{
					RuleID:   ruleFirebaseRTDBWorldReadable,
					Title:    "Firebase Realtime Database is world-readable",
					Severity: models.SeverityHigh,
					MASVSID:  masvsIDPlatform1,
					Category: categoryConfig,
					Location: configLocation,
					Evidence: fmt.Sprintf("%s — returned HTTP 200 (no authentication required)", host),
					Tier:     models.TierForSeverity(models.SeverityHigh),
				})
			}
		}
	}

	// --- Passive: Storage bucket present ---
	if res.StorageBucket != "" {
		findings = append(findings, models.PlatformFinding{
			RuleID:   ruleFirebaseStoragePresent,
			Title:    "Firebase Cloud Storage bucket present in config",
			Severity: models.SeverityInfo,
			MASVSID:  masvsIDStorage1,
			Category: categoryConfig,
			Location: configLocation,
			Evidence: fmt.Sprintf("%s — verify bucket security rules are not world-readable", res.StorageBucket),
			Tier:     models.TierForSeverity(models.SeverityInfo),
		})
	}

	return findings
}

// CollectFirebaseMisconfigFindings is the main integration point for the Android
// scan pipeline. It reads the google-services.json from the decompiled tree
// (same search-path priority order as detectFirebase), parses it, and returns
// all Firebase misconfig findings (passive + optional active).
//
// It is best-effort: a missing or unparseable config yields nil (no findings)
// and never returns an error. The client parameter is the HTTP transport for
// the active probe (nil = production default). This mirrors the "no-fail" design
// of detectFirebase and CollectSBOMComponents.
func CollectFirebaseMisconfigFindings(ctx context.Context, jobCtx *utils.JobContext, client *http.Client) []models.PlatformFinding {
	src := jobCtx.GetSourceDir()
	for _, path := range googleServicesSearchPaths(jobCtx) {
		rawJSON, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var cfg googleServicesConfig
		if jErr := json.Unmarshal(rawJSON, &cfg); jErr != nil {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"path":   path,
				"error":  jErr.Error(),
			}).Debug("Skipping unparseable google-services.json for Firebase misconfig analysis")
			continue
		}
		if cfg.ProjectInfo.ProjectID == "" {
			continue
		}

		log.WithFields(log.Fields{
			"job_id":     jobCtx.JobID,
			"project_id": cfg.ProjectInfo.ProjectID,
			"path":       path,
		}).Debug("Running Firebase misconfig analysis from google-services.json")

		findings := AnalyzeAndroidFirebaseMisconfig(ctx, rawJSON, &cfg, jobCtx.JobID, client)

		// Update the location to be the tree-relative path for clarity.
		rel, relErr := filepath.Rel(src, path)
		if relErr == nil && rel != "" {
			for i := range findings {
				findings[i].Location = rel
			}
		}

		return findings // use the first config found (same priority as detectFirebase)
	}
	return nil
}

// probeRTDBWorldReadable performs a single, read-only GET <dbURL>/.json to test
// whether the Firebase Realtime Database allows unauthenticated read access.
//
// Safety posture:
//   - Read-only GET only; never POST/PUT/PATCH/DELETE.
//   - No redirects (an unexpected redirect might replay the request to a
//     different host).
//   - Bounded by rtdbProbeTimeout.
//   - Rate-limited by rtdbLimiter (shared across the process).
//   - Response body is drained but its content is NEVER logged or included in
//     findings; only the HTTP status code is examined.
//
// Returns (true, nil) for a world-readable DB (HTTP 200), (false, nil) for a
// locked DB (HTTP 401 or 403), or (false, err) for transport errors or
// inconclusive responses.
func probeRTDBWorldReadable(ctx context.Context, dbURL string, client *http.Client, jobID string) (bool, error) {
	// Rate-limit before making the request.
	if err := rtdbLimiter.Wait(ctx); err != nil {
		return false, fmt.Errorf("rate limiter: %w", err)
	}

	// Append /.json to reach the Firebase REST API root endpoint.
	probeURL := strings.TrimRight(dbURL, "/") + "/.json"

	// Build a no-redirect client for the production path when none was injected.
	if client == nil {
		client = &http.Client{
			Timeout: rtdbProbeTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, rtdbProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return false, fmt.Errorf("build probe request: %w", err)
	}
	req.Header.Set("User-Agent", rtdbUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("probe request: %w", err)
	}
	defer func() {
		// Drain (bounded) so the connection can be reused; never log the body.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

	log.WithFields(log.Fields{
		"job_id":  jobID,
		"db_host": rtdbHostFromURL(dbURL),
		"status":  resp.StatusCode,
	}).Debug("Firebase RTDB world-readable probe completed")

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP %d from RTDB probe", resp.StatusCode)
	}
}
