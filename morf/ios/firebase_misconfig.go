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

package ios

// firebase_misconfig.go — unit P2b (iOS side)
//
// iOS entry point for the Firebase misconfig detector. It wraps the shared
// apk.FirebaseMisconfigFindings function (the platform-agnostic core) and
// adapts the iOS-specific FirebaseConfig (from ParseGoogleServiceInfoPlist) into
// the apk.FirebaseResourceConfig shape expected by the shared core.
//
// DATABASE_URL and STORAGE_BUCKET are GoogleService-Info.plist keys that the
// Firebase iOS SDK reads. ParseGoogleServiceInfoPlist already surfaces them in
// FirebaseConfig.SDKs (as "DATABASE_URL" and "STORAGE_BUCKET") when they are
// present and non-empty. We re-parse the raw plist for the actual URL / bucket
// string values because SDKs only carries the key names, not the values.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"

	"howett.net/plist"
	"morf/apk"
	"morf/models"
	"morf/utils"
)

// locationGoogleServiceInfoPlist is the file location reported for iOS Firebase
// findings. Matches the GoogleService-Info.plist plist name used in SBOM.
const locationGoogleServiceInfoPlist = "GoogleService-Info.plist"

// iosFirebaseRawPlist is the minimal plist shape for extracting DATABASE_URL and
// STORAGE_BUCKET. We decode into a flat map[string]interface{} to handle both
// string and bool plist scalars uniformly.

// IOSFirebaseResourceConfig extracts the apk.FirebaseResourceConfig from raw
// GoogleService-Info.plist bytes. The plist keys DATABASE_URL and STORAGE_BUCKET
// carry the resource identifiers needed for passive findings.
//
// It is best-effort: a decode failure yields an empty config (no findings),
// never an error — a failed plist parse must not fail the scan.
func IOSFirebaseResourceConfig(data []byte) apk.FirebaseResourceConfig {
	if len(data) == 0 {
		return apk.FirebaseResourceConfig{}
	}

	var raw map[string]interface{}
	if _, err := plist.Unmarshal(data, &raw); err != nil {
		return apk.FirebaseResourceConfig{}
	}

	// Flatten scalar values to strings using the same technique as
	// ParseGoogleServiceInfoPlist.
	flat := map[string]string{}
	flattenPlistMap("", raw, flat)

	return apk.FirebaseResourceConfig{
		RTDBURL:       flat["DATABASE_URL"],
		StorageBucket: flat["STORAGE_BUCKET"],
	}
}

// AnalyzeIOSFirebaseMisconfig is the iOS entry point for the Firebase misconfig
// detector. It accepts the raw GoogleService-Info.plist bytes and the
// already-parsed FirebaseConfig (from ParseGoogleServiceInfoPlist), extracts the
// resource config, and delegates to the platform-agnostic core.
//
// It is best-effort: nil or unparseable data yields nil (no findings). The
// client parameter is the HTTP transport for the active probe (nil = production
// default with no-redirect + timeout). jobID is used for log correlation.
func AnalyzeIOSFirebaseMisconfig(ctx context.Context, data []byte, cfg *FirebaseConfig, jobID string, client *http.Client) []models.PlatformFinding {
	if cfg == nil || cfg.ProjectID == "" {
		return nil
	}
	res := IOSFirebaseResourceConfig(data)
	// When DATABASE_URL is absent from the plist, there is no RTDB finding to
	// emit: unlike Android (where we can derive a conventional URL from the
	// project_id), iOS apps that do not use the Realtime Database simply do not
	// include DATABASE_URL in their plist. We do NOT synthesize a URL.
	if res.RTDBURL == "" && res.StorageBucket == "" {
		return nil
	}
	return apk.FirebaseMisconfigFindings(ctx, res, locationGoogleServiceInfoPlist, jobID, client)
}

// CollectIOSFirebaseMisconfigFindings is the pipeline integration point for the
// iOS scan path. It looks for a GoogleService-Info.plist in the app bundle
// (at the bundle root, same location as firebaseComponent in analysis.go),
// parses it, and returns all Firebase misconfig findings.
//
// Returns nil (no findings) when no plist is found or when the plist cannot be
// parsed — never an error. The client parameter is the HTTP transport for the
// active probe (nil = production default).
func CollectIOSFirebaseMisconfigFindings(ctx context.Context, appBundlePath string, jobID string, client *http.Client) []models.PlatformFinding {
	if appBundlePath == "" {
		return nil
	}
	plistPath := filepath.Join(appBundlePath, GoogleServiceInfoName)
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return nil // no plist — not an error
	}
	fc, err := ParseGoogleServiceInfoPlist(data)
	if err != nil {
		return nil // unparseable plist — best-effort, skip
	}
	return AnalyzeIOSFirebaseMisconfig(ctx, data, fc, jobID, client)
}

// CollectIOSFirebaseMisconfigFindingsFromIPA is the worker-path integration
// point. After StartIOSExtraction has run and the .ipa has been unpacked into
// jobCtx.GetIOSDir(), this function locates the app bundle, finds the
// GoogleService-Info.plist, and returns Firebase misconfig findings.
//
// It reuses locateAppBundle (the same discovery used by StartUnpack) to find
// the Payload/<Name>.app directory, then delegates to
// CollectIOSFirebaseMisconfigFindings. Returns nil on any error (best-effort).
func CollectIOSFirebaseMisconfigFindingsFromIPA(ctx context.Context, jobCtx *utils.JobContext, client *http.Client) []models.PlatformFinding {
	if jobCtx == nil {
		return nil
	}
	extractRoot := jobCtx.GetIOSDir()
	if extractRoot == "" {
		return nil
	}
	appBundle, err := locateAppBundle(extractRoot)
	if err != nil {
		return nil // no app bundle found — not an error for Firebase detection
	}
	return CollectIOSFirebaseMisconfigFindings(ctx, appBundle, jobCtx.JobID, client)
}
