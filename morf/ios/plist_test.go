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

// Pure-parse unit tests for the plist path. These do NOT require a darwin
// cross-build and therefore always run: they exercise DecodeInfoPlistFull,
// PlistStringValues, AppendPlistCorpus, the ATS flattening, and the corpus
// writers against inline XML plists.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sampleInfoPlist is a minimal but representative Info.plist covering the flat
// identity keys, CFBundleURLTypes/CFBundleURLSchemes, and a nested
// NSAppTransportSecurity subtree with a per-domain exception.
const sampleInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.MorfTestApp</string>
	<key>CFBundleVersion</key>
	<string>42.1</string>
	<key>CFBundleExecutable</key>
	<string>MorfTestApp</string>
	<key>MinimumOSVersion</key>
	<string>15.0</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>morftest</string>
				<string>morftest-alt</string>
			</array>
		</dict>
	</array>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSExceptionDomains</key>
		<dict>
			<key>insecure.example.com</key>
			<dict>
				<key>NSExceptionAllowsInsecureHTTPLoads</key>
				<true/>
			</dict>
		</dict>
	</dict>
	<key>EmbeddedApiKey</key>
	<string>AKIA_MORF_FAKE_INFO_PLIST_SECRET</string>
</dict>
</plist>`

func TestDecodeInfoPlistFull(t *testing.T) {
	pd, err := DecodeInfoPlistFull([]byte(sampleInfoPlist))
	if err != nil {
		t.Fatalf("DecodeInfoPlistFull returned error: %v", err)
	}

	if pd.BundleIdentifier != "com.example.MorfTestApp" {
		t.Errorf("BundleIdentifier = %q, want com.example.MorfTestApp", pd.BundleIdentifier)
	}
	if pd.BundleVersion != "42.1" {
		t.Errorf("BundleVersion = %q, want 42.1", pd.BundleVersion)
	}
	if pd.ExecutableName != "MorfTestApp" {
		t.Errorf("ExecutableName = %q, want MorfTestApp", pd.ExecutableName)
	}
	if pd.MinimumOSVersion != "15.0" {
		t.Errorf("MinimumOSVersion = %q, want 15.0", pd.MinimumOSVersion)
	}

	wantSchemes := []string{"morftest", "morftest-alt"}
	got := append([]string(nil), pd.URLSchemes...)
	sort.Strings(got)
	sort.Strings(wantSchemes)
	if strings.Join(got, ",") != strings.Join(wantSchemes, ",") {
		t.Errorf("URLSchemes = %v, want %v", pd.URLSchemes, wantSchemes)
	}

	// ATS flattening: top-level bool + nested per-domain exception.
	if pd.ATSExceptions["NSAllowsArbitraryLoads"] != "true" {
		t.Errorf("ATS NSAllowsArbitraryLoads = %q, want true", pd.ATSExceptions["NSAllowsArbitraryLoads"])
	}
	nestedKey := "NSExceptionDomains.insecure.example.com.NSExceptionAllowsInsecureHTTPLoads"
	if pd.ATSExceptions[nestedKey] != "true" {
		t.Errorf("ATS nested key %q = %q, want true", nestedKey, pd.ATSExceptions[nestedKey])
	}
}

func TestPlistStringValues(t *testing.T) {
	values, err := PlistStringValues([]byte(sampleInfoPlist))
	if err != nil {
		t.Fatalf("PlistStringValues error: %v", err)
	}
	// The embedded fake secret value must be present so the corpus scan can
	// find it. Keys and values are both collected.
	if !containsString(values, "AKIA_MORF_FAKE_INFO_PLIST_SECRET") {
		t.Errorf("PlistStringValues missing embedded secret value; got %v", values)
	}
	if !containsString(values, "com.example.MorfTestApp") {
		t.Errorf("PlistStringValues missing bundle id; got %v", values)
	}
	if !containsString(values, "morftest") {
		t.Errorf("PlistStringValues missing url scheme; got %v", values)
	}
}

func TestAppendPlistCorpus(t *testing.T) {
	dir := t.TempDir()
	plistPath := filepath.Join(dir, "Info.plist")
	if err := os.WriteFile(plistPath, []byte(sampleInfoPlist), 0o600); err != nil {
		t.Fatalf("write plist: %v", err)
	}
	corpusPath := filepath.Join(dir, "corpus.txt")

	if err := AppendPlistCorpus(corpusPath, plistPath); err != nil {
		t.Fatalf("AppendPlistCorpus error: %v", err)
	}
	body, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	corpus := string(body)
	if !strings.Contains(corpus, "AKIA_MORF_FAKE_INFO_PLIST_SECRET") {
		t.Errorf("corpus missing embedded secret; corpus=\n%s", corpus)
	}
	// Provenance prefix must be present so a scanner hit is attributable.
	if !strings.Contains(corpus, "[plist=") {
		t.Errorf("corpus missing [plist=...] provenance prefix; corpus=\n%s", corpus)
	}
}

// TestDecodeInfoPlistFullMinimal ensures a bare plist without ATS / URL types
// decodes without error and yields empty (non-nil) ATS map.
func TestDecodeInfoPlistFullMinimal(t *testing.T) {
	minimal := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.bare.app</string>
</dict></plist>`
	pd, err := DecodeInfoPlistFull([]byte(minimal))
	if err != nil {
		t.Fatalf("DecodeInfoPlistFull minimal error: %v", err)
	}
	if pd.BundleIdentifier != "com.bare.app" {
		t.Errorf("BundleIdentifier = %q, want com.bare.app", pd.BundleIdentifier)
	}
	if pd.ATSExceptions == nil {
		t.Errorf("ATSExceptions should be non-nil even when absent")
	}
	if len(pd.URLSchemes) != 0 {
		t.Errorf("URLSchemes should be empty, got %v", pd.URLSchemes)
	}
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
