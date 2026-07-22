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

package models

import "testing"

// identityFor returns the identity entry for a given field, or nil.
func identityFor(c SBOMComponent, field string) *SBOMIdentity {
	for i := range c.Evidence.Identity {
		if c.Evidence.Identity[i].Field == field {
			return &c.Evidence.Identity[i]
		}
	}
	return nil
}

// TestNewFrameworkComponentEcosystemPurlFromBundleID proves that a framework
// with an org.cocoapods.* bundleID gets the real pkg:cocoapods purl and a purl
// identity backed by manifest-analysis (the bundleID anchor).
func TestNewFrameworkComponentEcosystemPurlFromBundleID(t *testing.T) {
	c := NewFrameworkComponent("Alamofire", "5.9.0", "org.cocoapods.Alamofire", "Frameworks/Alamofire.framework")

	if want := "pkg:cocoapods/Alamofire@5.9.0"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	if c.Group != "" {
		t.Errorf("Group = %q; want empty for CocoaPods", c.Group)
	}
	pid := identityFor(c, "purl")
	if pid == nil {
		t.Fatalf("no purl identity emitted")
	}
	if pid.ConcludedValue != "pkg:cocoapods/Alamofire@5.9.0" {
		t.Errorf("purl identity concludedValue = %q", pid.ConcludedValue)
	}
	if len(pid.Methods) != 1 || pid.Methods[0].Technique != TechniqueManifestAnalysis {
		t.Errorf("purl identity technique = %+v; want manifest-analysis", pid.Methods)
	}
	if pid.Confidence != ConfidenceMedium {
		t.Errorf("purl identity confidence = %v; want %v", pid.Confidence, ConfidenceMedium)
	}
	// The occurrence and the name/version manifest identities must still be there.
	if len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != "Frameworks/Alamofire.framework" {
		t.Errorf("occurrences = %+v", c.Evidence.Occurrences)
	}
	if identityFor(c, "version") == nil {
		t.Errorf("version identity missing")
	}
}

// TestNewFrameworkComponentAstFingerprintWhenNameOnly proves that when the
// mapping is anchored by the library NAME (no cocoapods bundle hint), the purl
// identity technique is ast-fingerprint and the emitted purl is the SPM host
// form.
func TestNewFrameworkComponentAstFingerprintWhenNameOnly(t *testing.T) {
	c := NewFrameworkComponent("Alamofire", "5.9.0", "", "Frameworks/Alamofire.framework")

	if want := "pkg:swift/github.com/Alamofire/Alamofire@5.9.0"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	pid := identityFor(c, "purl")
	if pid == nil {
		t.Fatalf("no purl identity emitted")
	}
	if len(pid.Methods) != 1 || pid.Methods[0].Technique != TechniqueASTFingerprint {
		t.Errorf("purl identity technique = %+v; want ast-fingerprint", pid.Methods)
	}
}

// TestNewFrameworkComponentMavenSetsGroup proves a Maven-mapped framework sets
// Group to the groupId.
func TestNewFrameworkComponentMavenSetsGroup(t *testing.T) {
	c := NewFrameworkComponent("firebase-analytics", "21.5.0", "", "path")
	if want := "pkg:maven/com.google.firebase/firebase-analytics@21.5.0"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	if c.Group != "com.google.firebase" {
		t.Errorf("Group = %q; want com.google.firebase", c.Group)
	}
}

// TestNewFrameworkComponentGenericWhenUnmapped proves an unknown framework keeps
// the honest pkg:generic purl and emits NO purl identity.
func TestNewFrameworkComponentGenericWhenUnmapped(t *testing.T) {
	c := NewFrameworkComponent("AcmeInternal", "1.2.3", "com.acme.internal", "Frameworks/AcmeInternal.framework")

	if want := "pkg:generic/AcmeInternal@1.2.3"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	if c.Group != "" {
		t.Errorf("Group = %q; want empty", c.Group)
	}
	if identityFor(c, "purl") != nil {
		t.Errorf("unexpected purl identity for unmapped framework")
	}
	// Name+version manifest evidence must remain.
	if identityFor(c, "name") == nil || identityFor(c, "version") == nil {
		t.Errorf("name/version identities missing")
	}
}

// TestNewFrameworkComponentGenericNoVersion proves the name-only (no version)
// generic path still works and keeps filename evidence.
func TestNewFrameworkComponentGenericNoVersion(t *testing.T) {
	c := NewFrameworkComponent("AcmeInternal", "", "", "path")
	if want := "pkg:generic/AcmeInternal"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	name := identityFor(c, "name")
	if name == nil || name.Methods[0].Technique != TechniqueFilename {
		t.Errorf("name identity should be filename evidence; got %+v", name)
	}
}

// TestNewFirebaseComponentAndroid proves the Android Firebase component uses the
// Maven BOM purl, sets the Firebase groupId, records the projectID in the purl
// identity, and carries a manifest-analysis occurrence.
func TestNewFirebaseComponentAndroid(t *testing.T) {
	c := NewFirebaseComponent("my-proj-123", []string{"analytics", "crashlytics"}, FirebaseSourceAndroid, "google-services.json")

	if c.Type != "library" {
		t.Errorf("Type = %q; want library", c.Type)
	}
	if want := "Firebase (my-proj-123)"; c.Name != want {
		t.Errorf("Name = %q; want %q", c.Name, want)
	}
	if c.Purl != FirebaseMavenBOMPurl {
		t.Errorf("Purl = %q; want %q", c.Purl, FirebaseMavenBOMPurl)
	}
	if c.Group != "com.google.firebase" {
		t.Errorf("Group = %q; want com.google.firebase", c.Group)
	}
	pid := identityFor(c, "purl")
	if pid == nil {
		t.Fatalf("no purl identity")
	}
	if pid.Methods[0].Technique != TechniqueManifestAnalysis || pid.Confidence != ConfidenceMedium {
		t.Errorf("identity method/confidence = %+v / %v", pid.Methods, pid.Confidence)
	}
	if len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != "google-services.json" {
		t.Errorf("occurrences = %+v", c.Evidence.Occurrences)
	}
	// No fabricated version.
	if c.Version != "" {
		t.Errorf("Version = %q; want empty (no version fabrication)", c.Version)
	}
}

// TestNewFirebaseComponentIOS proves the iOS Firebase component uses the
// CocoaPods umbrella purl and records the detected SDK set in Group (since there
// is no Maven groupId occupying it).
func TestNewFirebaseComponentIOS(t *testing.T) {
	c := NewFirebaseComponent("ios-proj", []string{"analytics"}, FirebaseSourceIOS, "GoogleService-Info.plist")

	if c.Purl != FirebaseCocoaPodsPurl {
		t.Errorf("Purl = %q; want %q", c.Purl, FirebaseCocoaPodsPurl)
	}
	if c.Group == "" {
		t.Errorf("Group should record the SDK set; got empty")
	}
	if identityFor(c, "purl") == nil {
		t.Errorf("purl identity missing")
	}
}

// TestNewFirebaseComponentNoProjectID proves the umbrella name is used when no
// projectID is known, and the bom-ref is stable.
func TestNewFirebaseComponentNoProjectID(t *testing.T) {
	c := NewFirebaseComponent("", nil, FirebaseSourceIOS, "GoogleService-Info.plist")
	if c.Name != "Firebase" {
		t.Errorf("Name = %q; want Firebase", c.Name)
	}
	if c.BomRef != "firebase:Firebase" {
		t.Errorf("BomRef = %q; want firebase:Firebase", c.BomRef)
	}
}

// TestNewImportedLibraryComponentMapped proves a Mach-O import that maps to a
// curated coordinate gets the ecosystem purl but keeps LOW-confidence
// binary-analysis name evidence (imports carry no version/bytes).
func TestNewImportedLibraryComponentMapped(t *testing.T) {
	c := NewImportedLibraryComponent("Alamofire", "@rpath/Alamofire.framework/Alamofire")

	if c.Type != "library" {
		t.Errorf("Type = %q; want library", c.Type)
	}
	if c.BomRef != "import:Alamofire" {
		t.Errorf("BomRef = %q; want import:Alamofire", c.BomRef)
	}
	// No bundleID + no version -> SPM host form (name-only match).
	if want := "pkg:swift/github.com/Alamofire/Alamofire"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	name := identityFor(c, "name")
	if name == nil {
		t.Fatalf("name identity missing")
	}
	if name.Confidence != ConfidenceLow || name.Methods[0].Technique != TechniqueBinaryAnalysis {
		t.Errorf("name identity = %+v; want LOW binary-analysis", name)
	}
	if len(c.Evidence.Occurrences) != 1 {
		t.Errorf("occurrences = %+v; want 1", c.Evidence.Occurrences)
	}
}

// TestNewImportedLibraryComponentUnmapped proves an unknown import keeps the
// pkg:generic fallback.
func TestNewImportedLibraryComponentUnmapped(t *testing.T) {
	c := NewImportedLibraryComponent("libProprietary", "@rpath/libProprietary.dylib")
	if want := "pkg:generic/libProprietary"; c.Purl != want {
		t.Errorf("Purl = %q; want %q", c.Purl, want)
	}
	if c.Group != "" {
		t.Errorf("Group = %q; want empty", c.Group)
	}
}
