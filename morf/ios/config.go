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

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"howett.net/plist"
)

// AppendJSONCorpus reads the (JSON) config file at jsonPath and appends its
// lines to the corpus file, each tagged with a provenance prefix so a scanner
// hit is attributable back to the source file.
//
// Unlike the plist path, this treats the file as raw text rather than parsing
// it: embedded JSON config (e.g. Firebase's GoogleService-Info.json,
// google-services.json, or any bundled *.json) stores secrets as plain string
// values, and ripgrep matches on raw text anyway. Reading raw text means a
// malformed / partial / comment-bearing JSON file is still scanned instead of
// being silently dropped on a parse error — matching the "log-and-continue,
// never abort" contract of the plist sweep. A read failure is returned so the
// caller can log-and-continue.
func AppendJSONCorpus(corpusPath, jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("read json %q: %w", jsonPath, err)
	}

	f, err := os.OpenFile(corpusPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open corpus %q: %w", corpusPath, err)
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	for _, line := range strings.Split(string(data), "\n") {
		if _, err := fmt.Fprintf(bw, "[json=%s] %s\n", jsonPath, sanitizeLine(line)); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush corpus %q: %w", corpusPath, err)
	}
	return nil
}

// GoogleServiceInfoName is the fixed file name of the Firebase config plist an
// iOS app bundles when it integrates the Firebase SDK.
const GoogleServiceInfoName = "GoogleService-Info.plist"

// firebaseSDKKeys are the GoogleService-Info.plist keys MORF treats as evidence
// of a specific Firebase capability being provisioned. When present (and
// non-empty) each is folded into the detected-SDK set the SBOM records, so the
// Firebase component names WHICH Firebase products the config enables rather
// than emitting a bare "Firebase present" signal. The keys are the canonical
// GoogleService-Info.plist keys the Firebase iOS SDK reads.
var firebaseSDKKeys = []string{
	"GCM_SENDER_ID",  // Cloud Messaging / push
	"GOOGLE_APP_ID",  // core app identity (FirebaseCore)
	"API_KEY",        // Firebase API key (auth/config)
	"CLIENT_ID",      // OAuth / Google Sign-In
	"DATABASE_URL",   // Realtime Database
	"STORAGE_BUCKET", // Cloud Storage
	"IS_ANALYTICS_ENABLED",
}

// FirebaseConfig is the decoded, best-effort view of a Firebase
// GoogleService-Info.plist. ProjectID is the Firebase project identifier and
// SDKs is the sorted set of firebaseSDKKeys the plist populated (evidence of
// which Firebase products the config provisions).
type FirebaseConfig struct {
	// ProjectID is the Firebase PROJECT_ID (empty when the key is absent).
	ProjectID string
	// SDKs is the sorted set of provisioned Firebase capability keys present in
	// the plist (a subset of firebaseSDKKeys), used as the SBOM SDK evidence.
	SDKs []string
}

// ParseGoogleServiceInfoPlist decodes a Firebase GoogleService-Info.plist
// (binary or XML) and extracts the PROJECT_ID and the set of provisioned
// Firebase capability keys (firebaseSDKKeys that are present and non-empty).
//
// It reuses the existing howett.net/plist decode (same engine as
// DecodeInfoPlist), decoding into a flat string map so heterogeneous scalar
// types (strings, bools) are handled uniformly. It is strictly best-effort: an
// unreadable / undecodable plist yields (nil, error) and the caller
// log-and-continues — a Firebase config that fails to parse must NEVER fail the
// scan.
func ParseGoogleServiceInfoPlist(data []byte) (*FirebaseConfig, error) {
	var raw map[string]interface{}
	if _, err := plist.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode GoogleService-Info.plist: %w", err)
	}

	// Flatten scalars to strings so PROJECT_ID and the capability keys read
	// uniformly regardless of their plist scalar type.
	flat := map[string]string{}
	flattenPlistMap("", raw, flat)

	cfg := &FirebaseConfig{ProjectID: flat["PROJECT_ID"]}
	for _, k := range firebaseSDKKeys {
		if v, ok := flat[k]; ok && v != "" {
			cfg.SDKs = append(cfg.SDKs, k)
		}
	}
	sort.Strings(cfg.SDKs)
	return cfg, nil
}
