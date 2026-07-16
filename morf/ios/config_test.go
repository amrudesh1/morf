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

	if _, _, err := StartIOSExtraction(context.Background(), ipaPath, jc); err != nil {
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
