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

// Pure-filesystem tests for the SBOM extractor path: a fake .app bundle laid
// out on disk (no zip, no java/apktool, no darwin cross-build) with an embedded
// Alamofire.framework carrying an Info.plist. These prove EnumerateFrameworks
// captures CFBundleShortVersionString from the framework's own bundle plist and
// that BuildSBOMComponents turns that into a framework component with the parsed
// version, the framework path as its occurrence, and manifest-analysis evidence.

import (
	"os"
	"path/filepath"
	"testing"

	"morf/models"
)

// alamofireFrameworkPlist is a minimal but representative embedded framework
// Info.plist. The only fields the extractor reads are CFBundleShortVersionString
// (the SBOM component version) and CFBundleIdentifier (provenance).
const alamofireFrameworkPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>org.alamofire.Alamofire</string>
	<key>CFBundleName</key>
	<string>Alamofire</string>
	<key>CFBundleShortVersionString</key>
	<string>5.9.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleExecutable</key>
	<string>Alamofire</string>
</dict>
</plist>`

// writeFakeAppWithFramework lays out a fake Payload/App.app/Frameworks/
// Alamofire.framework/Info.plist under a temp dir and returns the absolute path
// to the Alamofire.framework bundle. No zip is involved — the extractor works
// directly off filesystem paths, so this is enough to exercise the framework
// enumeration + SBOM build without any external tooling.
func writeFakeAppWithFramework(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	fwBundle := filepath.Join(root, "Payload", "App.app", "Frameworks", "Alamofire.framework")
	if err := os.MkdirAll(fwBundle, 0o700); err != nil {
		t.Fatalf("mkdir framework bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fwBundle, "Info.plist"), []byte(alamofireFrameworkPlist), 0o600); err != nil {
		t.Fatalf("write framework Info.plist: %v", err)
	}
	return fwBundle
}

// TestEnumerateFrameworksCapturesShortVersion proves EnumerateFrameworks reads
// CFBundleShortVersionString + CFBundleIdentifier from an embedded framework's
// own Info.plist. The framework has no Mach-O binary on disk, which must NOT be
// fatal (best-effort): the plist-derived version/bundle-id still land.
func TestEnumerateFrameworksCapturesShortVersion(t *testing.T) {
	fwBundle := writeFakeAppWithFramework(t)
	up := &UnpackedIPA{Frameworks: []string{fwBundle}}

	fws := EnumerateFrameworks("test-job", up)
	if len(fws) != 1 {
		t.Fatalf("EnumerateFrameworks returned %d frameworks; want 1", len(fws))
	}
	fw := fws[0]
	if fw.Name != "Alamofire.framework" {
		t.Errorf("Name = %q; want Alamofire.framework", fw.Name)
	}
	if fw.Path != fwBundle {
		t.Errorf("Path = %q; want %q", fw.Path, fwBundle)
	}
	if fw.ShortVersion != "5.9.0" {
		t.Errorf("ShortVersion = %q; want 5.9.0 (from CFBundleShortVersionString)", fw.ShortVersion)
	}
	if fw.BundleID != "org.alamofire.Alamofire" {
		t.Errorf("BundleID = %q; want org.alamofire.Alamofire", fw.BundleID)
	}
}

// TestBuildSBOMComponentsFrameworkVersion is the core proof for this stage: the
// framework component is produced with the parsed version, the framework path as
// its occurrence, and manifest-analysis evidence (because a version was parsed
// from the bundle plist) at MEDIUM confidence.
func TestBuildSBOMComponentsFrameworkVersion(t *testing.T) {
	fwBundle := writeFakeAppWithFramework(t)
	up := &UnpackedIPA{Frameworks: []string{fwBundle}}

	fws := EnumerateFrameworks("test-job", up)
	components := BuildSBOMComponents(fws)

	if len(components) != 1 {
		t.Fatalf("BuildSBOMComponents returned %d components; want 1", len(components))
	}
	c := components[0]

	if c.Type != "framework" {
		t.Errorf("Type = %q; want framework", c.Type)
	}
	// The ".framework" suffix must be stripped for a clean name/purl/bom-ref.
	if c.Name != "Alamofire" {
		t.Errorf("Name = %q; want Alamofire (suffix stripped)", c.Name)
	}
	if c.Version != "5.9.0" {
		t.Errorf("Version = %q; want 5.9.0 (parsed CFBundleShortVersionString)", c.Version)
	}
	// PURL RULE: default pkg:generic/<name>@<version>; never pkg:swift.
	if c.Purl != "pkg:generic/Alamofire@5.9.0" {
		t.Errorf("Purl = %q; want pkg:generic/Alamofire@5.9.0", c.Purl)
	}
	if c.BomRef != "framework:Alamofire" {
		t.Errorf("BomRef = %q; want framework:Alamofire", c.BomRef)
	}

	// Occurrence must record the framework bundle path.
	if len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != fwBundle {
		t.Fatalf("Occurrences = %+v; want single occurrence at %q", c.Evidence.Occurrences, fwBundle)
	}

	// Evidence: because a version was parsed, identity is backed by
	// manifest-analysis (structured plist metadata), NOT filename. Assert both
	// the name and version identities carry the manifest-analysis technique.
	if len(c.Evidence.Identity) != 2 {
		t.Fatalf("Identity entries = %d; want 2 (name + version)", len(c.Evidence.Identity))
	}
	for _, id := range c.Evidence.Identity {
		if len(id.Methods) != 1 {
			t.Fatalf("identity %q has %d methods; want 1", id.Field, len(id.Methods))
		}
		m := id.Methods[0]
		if m.Technique != models.TechniqueManifestAnalysis {
			t.Errorf("identity %q technique = %q; want %q (manifest-analysis)",
				id.Field, m.Technique, models.TechniqueManifestAnalysis)
		}
		if m.Confidence != models.ConfidenceMedium {
			t.Errorf("identity %q confidence = %v; want %v (MEDIUM)",
				id.Field, m.Confidence, models.ConfidenceMedium)
		}
	}
}

// TestBuildSBOMComponentsNameOnlyWhenNoPlist proves the best-effort contract:
// an embedded framework whose bundle has NO Info.plist must not fail the scan;
// it yields a name-only component backed by weak filename evidence (LOW).
func TestBuildSBOMComponentsNameOnlyWhenNoPlist(t *testing.T) {
	root := t.TempDir()
	// Framework bundle directory with no Info.plist inside.
	fwBundle := filepath.Join(root, "Payload", "App.app", "Frameworks", "NoPlist.framework")
	if err := os.MkdirAll(fwBundle, 0o700); err != nil {
		t.Fatalf("mkdir framework bundle: %v", err)
	}
	up := &UnpackedIPA{Frameworks: []string{fwBundle}}

	fws := EnumerateFrameworks("test-job", up)
	if len(fws) != 1 || fws[0].ShortVersion != "" {
		t.Fatalf("missing plist should yield empty ShortVersion; got %+v", fws)
	}

	components := BuildSBOMComponents(fws)
	if len(components) != 1 {
		t.Fatalf("BuildSBOMComponents returned %d components; want 1", len(components))
	}
	c := components[0]
	if c.Name != "NoPlist" {
		t.Errorf("Name = %q; want NoPlist", c.Name)
	}
	if c.Version != "" {
		t.Errorf("Version = %q; want empty (no plist)", c.Version)
	}
	if c.Purl != "pkg:generic/NoPlist" {
		t.Errorf("Purl = %q; want pkg:generic/NoPlist (no version)", c.Purl)
	}
	if len(c.Evidence.Identity) != 1 {
		t.Fatalf("Identity entries = %d; want 1 (name-only)", len(c.Evidence.Identity))
	}
	m := c.Evidence.Identity[0].Methods[0]
	if m.Technique != models.TechniqueFilename {
		t.Errorf("technique = %q; want %q (filename)", m.Technique, models.TechniqueFilename)
	}
	if m.Confidence != models.ConfidenceLow {
		t.Errorf("confidence = %v; want %v (LOW)", m.Confidence, models.ConfidenceLow)
	}
}

// TestBuildSBOMComponentsDylib proves embedded *.dylib files map to name-only
// library components via NewDylibComponent (filename evidence, LOW).
func TestBuildSBOMComponentsDylib(t *testing.T) {
	root := t.TempDir()
	dylib := filepath.Join(root, "Payload", "App.app", "Frameworks", "libswiftCore.dylib")
	if err := os.MkdirAll(filepath.Dir(dylib), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A non-Mach-O placeholder file: fillArch logs+swallows the parse failure.
	if err := os.WriteFile(dylib, []byte("not a mach-o"), 0o600); err != nil {
		t.Fatalf("write dylib: %v", err)
	}
	up := &UnpackedIPA{Dylibs: []string{dylib}}

	fws := EnumerateFrameworks("test-job", up)
	components := BuildSBOMComponents(fws)
	if len(components) != 1 {
		t.Fatalf("BuildSBOMComponents returned %d components; want 1", len(components))
	}
	c := components[0]
	if c.Type != "library" {
		t.Errorf("Type = %q; want library", c.Type)
	}
	if c.Name != "libswiftCore.dylib" {
		t.Errorf("Name = %q; want libswiftCore.dylib", c.Name)
	}
	if c.BomRef != "dylib:libswiftCore.dylib" {
		t.Errorf("BomRef = %q; want dylib:libswiftCore.dylib", c.BomRef)
	}
	if len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != dylib {
		t.Errorf("Occurrences = %+v; want single occurrence at %q", c.Evidence.Occurrences, dylib)
	}
}

// TestBuildSBOMComponentsEmpty proves an app with no embedded frameworks/dylibs
// yields nil (no spurious components).
func TestBuildSBOMComponentsEmpty(t *testing.T) {
	if got := BuildSBOMComponents(nil); got != nil {
		t.Errorf("BuildSBOMComponents(nil) = %+v; want nil", got)
	}
	if got := BuildSBOMComponents([]FrameworkInfo{}); got != nil {
		t.Errorf("BuildSBOMComponents(empty) = %+v; want nil", got)
	}
}
