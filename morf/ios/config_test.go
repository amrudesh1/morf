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

// Pure-parse tests for the embedded-config (JSON) path and an end-to-end test
// proving that a hardcoded key planted in an embedded GoogleService-Info.plist
// and a bundled *.json both reach the strings corpus consumed by the shared
// detector. Neither test needs a darwin cross-build (pure text + zip), so both
// run unconditionally — same class as the plist tests.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morf/models"
)

// fakeFirebaseAPIKey is a plausible-looking but fake Google API key
// (AIza-prefixed) planted in embedded config fixtures below.
const fakeFirebaseAPIKey = "AIzaSyMORF_FAKE_EMBEDDED_CONFIG_KEY_012345"

// sampleGoogleServiceInfoPlist mirrors a Firebase GoogleService-Info.plist,
// carrying an API_KEY value we expect to be scanned.
const sampleGoogleServiceInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>API_KEY</key>
	<string>` + fakeFirebaseAPIKey + `</string>
	<key>GCM_SENDER_ID</key>
	<string>1234567890</string>
	<key>BUNDLE_ID</key>
	<string>com.example.MorfTestApp</string>
	<key>PROJECT_ID</key>
	<string>morf-test-project</string>
</dict>
</plist>`

// sampleFirebaseJSON mirrors a bundled JSON config (e.g. google-services.json)
// with an api_key value we expect to be scanned.
const sampleFirebaseJSON = `{
  "project_info": {
    "project_id": "morf-test-project"
  },
  "client": [
    {
      "api_key": [
        { "current_key": "` + fakeFirebaseAPIKey + `" }
      ]
    }
  ]
}`

func TestAppendJSONCorpus(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "google-services.json")
	if err := os.WriteFile(jsonPath, []byte(sampleFirebaseJSON), 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}
	corpusPath := filepath.Join(dir, "corpus.txt")

	if err := AppendJSONCorpus(corpusPath, jsonPath); err != nil {
		t.Fatalf("AppendJSONCorpus error: %v", err)
	}
	body, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	corpus := string(body)
	if !strings.Contains(corpus, fakeFirebaseAPIKey) {
		t.Errorf("corpus missing embedded JSON key; corpus=\n%s", corpus)
	}
	// Provenance prefix must be present so a scanner hit is attributable.
	if !strings.Contains(corpus, "[json=") {
		t.Errorf("corpus missing [json=...] provenance prefix; corpus=\n%s", corpus)
	}
}

// TestAppendJSONCorpusMalformed proves the raw-text approach still scans a
// malformed JSON file (a JSON parser would drop it) so secrets in partial /
// comment-bearing config are not silently lost.
func TestAppendJSONCorpusMalformed(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "broken.json")
	malformed := `{ "api_key": "` + fakeFirebaseAPIKey + `", // trailing comment, not valid JSON`
	if err := os.WriteFile(jsonPath, []byte(malformed), 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}
	corpusPath := filepath.Join(dir, "corpus.txt")

	if err := AppendJSONCorpus(corpusPath, jsonPath); err != nil {
		t.Fatalf("AppendJSONCorpus error: %v", err)
	}
	body, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if !strings.Contains(string(body), fakeFirebaseAPIKey) {
		t.Errorf("corpus missing key from malformed JSON; corpus=\n%s", string(body))
	}
}

// TestEmbeddedConfigReachesCorpus builds an .ipa whose app bundle contains a
// GoogleService-Info.plist and a bundled JSON config, each with a planted
// AIza... key, then runs the full StartIOSExtraction pipeline and asserts both
// keys reach the strings corpus (with their provenance prefixes) that the
// shared detector scans. This needs no Mach-O build — the fake main binary
// fails string extraction and the pipeline log-and-continues, exactly as in
// TestStartUnpackLocatesAppAndExecutable.
func TestEmbeddedConfigReachesCorpus(t *testing.T) {
	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.Embedded</string>
<key>CFBundleExecutable</key><string>EmbeddedApp</string>
</dict></plist>`

	entries := []zipEntry{
		{"Payload/EmbeddedApp.app/Info.plist", []byte(infoPlist)},
		{"Payload/EmbeddedApp.app/EmbeddedApp", []byte("\xcf\xfa\xed\xfe not a real macho")},
		{"Payload/EmbeddedApp.app/GoogleService-Info.plist", []byte(sampleGoogleServiceInfoPlist)},
		{"Payload/EmbeddedApp.app/Resources/google-services.json", []byte(sampleFirebaseJSON)},
	}
	ipaPath := buildIPA(t, entries)
	jc := newTestJobCtx(t)

	if _, _, _, err := StartIOSExtraction(context.Background(), ipaPath, jc); err != nil {
		t.Fatalf("StartIOSExtraction error: %v", err)
	}

	corpusPath := filepath.Join(jc.GetIOSBinDir(), "corpus", corpusFileName)
	body, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	corpus := string(body)

	// The GoogleService-Info.plist key must have flowed through the plist sweep.
	if !strings.Contains(corpus, fakeFirebaseAPIKey) {
		t.Errorf("corpus missing planted key from embedded config; corpus=\n%s", corpus)
	}
	if !strings.Contains(corpus, "GoogleService-Info.plist") || !strings.Contains(corpus, "[plist=") {
		t.Errorf("corpus missing GoogleService-Info.plist provenance; corpus=\n%s", corpus)
	}
	// The bundled JSON key must have flowed through the new JSON sweep.
	if !strings.Contains(corpus, "[json=") || !strings.Contains(corpus, "google-services.json") {
		t.Errorf("corpus missing embedded JSON provenance; corpus=\n%s", corpus)
	}
}

// TestParseGoogleServiceInfoPlist proves the Firebase config parser extracts the
// PROJECT_ID and the provisioned-capability key set from a GoogleService-Info.plist.
// sampleGoogleServiceInfoPlist declares PROJECT_ID + GCM_SENDER_ID + API_KEY (and
// BUNDLE_ID, which is not a capability key), so the detected SDK set is exactly
// {API_KEY, GCM_SENDER_ID} (sorted).
func TestParseGoogleServiceInfoPlist(t *testing.T) {
	fc, err := ParseGoogleServiceInfoPlist([]byte(sampleGoogleServiceInfoPlist))
	if err != nil {
		t.Fatalf("ParseGoogleServiceInfoPlist error: %v", err)
	}
	if fc.ProjectID != "morf-test-project" {
		t.Errorf("ProjectID = %q; want morf-test-project", fc.ProjectID)
	}
	// API_KEY + GCM_SENDER_ID are provisioned capability keys; BUNDLE_ID is not.
	want := []string{"API_KEY", "GCM_SENDER_ID"}
	if len(fc.SDKs) != len(want) {
		t.Fatalf("SDKs = %v; want %v", fc.SDKs, want)
	}
	for i, k := range want {
		if fc.SDKs[i] != k {
			t.Errorf("SDKs[%d] = %q; want %q (SDKs=%v)", i, fc.SDKs[i], k, fc.SDKs)
		}
	}
}

// TestBuildSBOMComponentsFirebase proves a GoogleService-Info.plist in the app
// bundle produces ONE Firebase umbrella component (iOS source) carrying the
// project id: the purl is the CocoaPods Firebase pod, the projectID is folded
// into the name and the purl identity's concludedValue, and the plist is its
// occurrence. No frameworks/dylibs/imports are present, so it is the only
// component.
func TestBuildSBOMComponentsFirebase(t *testing.T) {
	root := t.TempDir()
	appBundle := filepath.Join(root, "Payload", "App.app")
	if err := os.MkdirAll(appBundle, 0o700); err != nil {
		t.Fatalf("mkdir app bundle: %v", err)
	}
	plistPath := filepath.Join(appBundle, GoogleServiceInfoName)
	if err := os.WriteFile(plistPath, []byte(sampleGoogleServiceInfoPlist), 0o600); err != nil {
		t.Fatalf("write GoogleService-Info.plist: %v", err)
	}

	up := &UnpackedIPA{AppBundlePath: appBundle}
	components := BuildSBOMComponents("test-job", up, nil)

	if len(components) != 1 {
		t.Fatalf("BuildSBOMComponents returned %d components; want 1 (Firebase only)", len(components))
	}
	c := components[0]

	if c.Type != "library" {
		t.Errorf("Type = %q; want library", c.Type)
	}
	// Firebase on iOS maps to the umbrella CocoaPod, never the Android Maven BOM.
	if c.Purl != models.FirebaseCocoaPodsPurl {
		t.Errorf("Purl = %q; want %q (iOS CocoaPods Firebase)", c.Purl, models.FirebaseCocoaPodsPurl)
	}
	// The projectID must surface in the component name and the bom-ref.
	if !strings.Contains(c.Name, "morf-test-project") {
		t.Errorf("Name = %q; want it to contain the projectID morf-test-project", c.Name)
	}
	if c.BomRef != "firebase:morf-test-project" {
		t.Errorf("BomRef = %q; want firebase:morf-test-project", c.BomRef)
	}
	// The purl identity's concludedValue must carry the projectID as evidence.
	if len(c.Evidence.Identity) != 1 || c.Evidence.Identity[0].Field != "purl" {
		t.Fatalf("Identity = %+v; want a single purl identity", c.Evidence.Identity)
	}
	if !strings.Contains(c.Evidence.Identity[0].ConcludedValue, "morf-test-project") {
		t.Errorf("purl identity concludedValue = %q; want it to carry projectID",
			c.Evidence.Identity[0].ConcludedValue)
	}
	// The plist is the single occurrence.
	if len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != plistPath {
		t.Errorf("Occurrences = %+v; want single occurrence at %q", c.Evidence.Occurrences, plistPath)
	}
}
