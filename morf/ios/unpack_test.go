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

// Unpack + end-to-end orchestration tests. These build a synthetic .ipa (a zip
// with Payload/<App>.app/{Info.plist, <exe>}) and drive StartUnpack /
// StartIOSExtraction. The app-name and executable resolution paths are
// exercised WITHOUT hardcoding a bundle name. Tests that need a real Mach-O
// build skip when the darwin cross-build is unavailable; a plist-only variant
// covers the zip/unpack path unconditionally.

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morf/utils"
)

// zipEntry is one file to place in the synthetic .ipa.
type zipEntry struct {
	name string // zip-internal path, forward-slash separated
	data []byte
}

// buildIPA writes a zip archive of entries to a temp .ipa path and returns it.
func buildIPA(t *testing.T, entries []zipEntry) string {
	t.Helper()
	dir := t.TempDir()
	ipaPath := filepath.Join(dir, "test.ipa")
	f, err := os.Create(ipaPath)
	if err != nil {
		t.Fatalf("create ipa: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("zip create %q: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("zip write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return ipaPath
}

// newTestJobCtx builds a JobContext rooted under t.TempDir() by pointing its
// workspace at a temp dir. Because JobContext.Workspace is exported we can
// override it so the test does not write into /tmp/morf/jobs.
func newTestJobCtx(t *testing.T) *utils.JobContext {
	t.Helper()
	jc := utils.NewJobContext()
	jc.Workspace = t.TempDir()
	if err := jc.CreateWorkspace(); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	return jc
}

// TestStartUnpackLocatesAppAndExecutable builds an .ipa whose app bundle has a
// non-obvious name and asserts StartUnpack discovers it (not hardcoded) and
// resolves the main binary by CFBundleExecutable NAME.
func TestStartUnpackLocatesAppAndExecutable(t *testing.T) {
	// A deliberately non-default app + executable name to prove nothing is
	// hardcoded.
	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.Weird</string>
<key>CFBundleExecutable</key><string>WeirdExeName</string>
</dict></plist>`

	entries := []zipEntry{
		{"Payload/WeirdApp.app/Info.plist", []byte(infoPlist)},
		{"Payload/WeirdApp.app/WeirdExeName", []byte("\xcf\xfa\xed\xfe not a real macho but a named file")},
		{"Payload/WeirdApp.app/Frameworks/Foo.framework/Foo", []byte("fwbin")},
		{"Payload/WeirdApp.app/PlugIns/Share.appex/ShareBin", []byte("appexbin")},
		{"Payload/WeirdApp.app/some.dylib", []byte("dylibbin")},
		{"Payload/WeirdApp.app/embedded.mobileprovision", []byte("provision")},
	}
	ipaPath := buildIPA(t, entries)
	jc := newTestJobCtx(t)

	up, err := StartUnpack(ipaPath, jc)
	if err != nil {
		t.Fatalf("StartUnpack error: %v", err)
	}

	if !strings.HasSuffix(up.AppBundlePath, "WeirdApp.app") {
		t.Errorf("AppBundlePath = %q, want .../WeirdApp.app", up.AppBundlePath)
	}
	if !strings.HasSuffix(up.MainBinaryPath, "WeirdExeName") {
		t.Errorf("MainBinaryPath = %q, want .../WeirdExeName", up.MainBinaryPath)
	}
	if up.InfoPlistPath == "" {
		t.Errorf("InfoPlistPath not set")
	}
	if len(up.Frameworks) != 1 || !strings.HasSuffix(up.Frameworks[0], "Foo.framework") {
		t.Errorf("Frameworks = %v, want one Foo.framework", up.Frameworks)
	}
	if len(up.AppExtensions) != 1 || !strings.HasSuffix(up.AppExtensions[0], "Share.appex") {
		t.Errorf("AppExtensions = %v, want one Share.appex", up.AppExtensions)
	}
	if len(up.Dylibs) == 0 {
		t.Errorf("Dylibs empty, want at least some.dylib")
	}
	if up.MobileProvisionPath == "" {
		t.Errorf("MobileProvisionPath not set")
	}
}

// TestStartUnpackRejectsNonZip ensures a non-zip input fails the safety gate.
func TestStartUnpackRejectsNonZip(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "not.ipa")
	if err := os.WriteFile(bogus, []byte("this is not a zip"), 0o600); err != nil {
		t.Fatalf("write bogus: %v", err)
	}
	jc := newTestJobCtx(t)
	if _, err := StartUnpack(bogus, jc); err == nil {
		t.Errorf("StartUnpack should reject a non-zip .ipa")
	}
}

// TestStartIOSExtractionEndToEnd builds a real Mach-O main binary (skips if the
// darwin cross-build is unavailable), packs it into an .ipa with an Info.plist,
// and runs the full StartIOSExtraction pipeline, asserting the metadata is
// populated from the plist and the corpus was scanned without error.
func TestStartIOSExtractionEndToEnd(t *testing.T) {
	bin := buildTestMachO(t) // skips if no darwin arm64 cgo build
	binData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read built binary: %v", err)
	}

	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.E2E</string>
<key>CFBundleVersion</key><string>7.7</string>
<key>CFBundleExecutable</key><string>E2EApp</string>
<key>MinimumOSVersion</key><string>16.0</string>
</dict></plist>`

	entries := []zipEntry{
		{"Payload/E2EApp.app/Info.plist", []byte(infoPlist)},
		{"Payload/E2EApp.app/E2EApp", binData},
	}
	ipaPath := buildIPA(t, entries)
	jc := newTestJobCtx(t)

	secrets, meta, _, err := StartIOSExtraction(context.Background(), ipaPath, jc)
	if err != nil {
		t.Fatalf("StartIOSExtraction error: %v", err)
	}
	_ = secrets // may be empty depending on installed patterns; not asserted here.

	if meta.BundleIdentifier != "com.example.E2E" {
		t.Errorf("BundleIdentifier = %q, want com.example.E2E", meta.BundleIdentifier)
	}
	if meta.ExecutableName != "E2EApp" {
		t.Errorf("ExecutableName = %q, want E2EApp", meta.ExecutableName)
	}
	if meta.DeploymentTarget != "16.0" {
		t.Errorf("DeploymentTarget = %q, want 16.0", meta.DeploymentTarget)
	}
	if meta.IsEncrypted {
		t.Errorf("locally built binary should not be encrypted")
	}
	// go-macho's types.CPU.String() renders arm64 as "AARCH64"; match
	// case-insensitively so the assertion is robust to that spelling.
	if !strings.Contains(strings.ToLower(meta.Architectures), "aarch64") &&
		!strings.Contains(strings.ToLower(meta.Architectures), "arm64") {
		t.Errorf("Architectures = %q, want to contain an arm64/aarch64 entry", meta.Architectures)
	}

	// The corpus file must have been created and populated with the fake secret
	// extracted from the __cstring section.
	corpusPath := filepath.Join(jc.GetIOSBinDir(), "corpus", corpusFileName)
	body, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if !strings.Contains(string(body), fakeSecret) {
		t.Errorf("corpus does not contain the fake secret extracted from the binary")
	}
}
