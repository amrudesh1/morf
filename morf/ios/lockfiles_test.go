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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morf/models"
	"morf/utils"
)

// iosJobCtxForDir builds a JobContext whose workspace is a temporary directory.
func iosJobCtxForDir(t *testing.T, id string) *utils.JobContext {
	t.Helper()
	jc := utils.NewJobContextForID(id)
	jc.Workspace = t.TempDir()
	return jc
}

// ---- ParsePodfileLock tests ----

const podfileLockFixture = `PODS:
  - Alamofire (5.6.4)
  - Firebase/Core (10.1.0):
    - Firebase/CoreOnly (= 10.1.0)
    - FirebaseCore (~> 10.3)
  - Firebase/Crashlytics (10.1.0):
    - Firebase/CoreOnly (= 10.1.0)
  - FirebaseCore (10.3.8):
    - FirebaseCoreInternal (~> 10.3.8)
    - GoogleUtilities/Environment (~> 7.8)
  - FirebaseCrashlytics (10.3.0):
    - FirebaseCore (~> 10.3)
    - FirebaseSessions (~> 10.3)
    - GoogleDataTransport (~> 9.2)
    - Promises (~> 2.1)
  - GoogleUtilities/Environment (7.12.1):
    - FBLPromises (~> 2.0)
  - Kingfisher (7.6.2)
  - SDWebImage (5.18.0)

DEPENDENCIES:
  - Alamofire (~> 5.6)
  - Firebase/Core
  - Kingfisher (~> 7.6)

SPEC REPOS:
  trunk:
    - Alamofire
    - Firebase

SPEC CHECKSUMS:
  Alamofire: abc123def456

PODFILE CHECKSUM: deadbeef

COCOAPODS: 1.14.3
`

func TestParsePodfileLock_ParsesVersions(t *testing.T) {
	got := ParsePodfileLock([]byte(podfileLockFixture))

	cases := map[string]string{
		"Alamofire":                   "5.6.4",
		"Firebase/Core":               "10.1.0",
		"Firebase/Crashlytics":        "10.1.0",
		"FirebaseCore":                "10.3.8",
		"FirebaseCrashlytics":         "10.3.0",
		"GoogleUtilities/Environment": "7.12.1",
		"Kingfisher":                  "7.6.2",
		"SDWebImage":                  "5.18.0",
	}
	for name, want := range cases {
		if got[name] != want {
			t.Errorf("Podfile.lock: %q version = %q, want %q", name, got[name], want)
		}
	}
}

func TestParsePodfileLock_DoesNotIncludeDependenciesSection(t *testing.T) {
	got := ParsePodfileLock([]byte(podfileLockFixture))

	// "DEPENDENCIES:" section entries like "  - Alamofire (~> 5.6)" should NOT
	// appear in the output — they use a version constraint, not a resolved version.
	// The versions should come from the PODS: block only.
	// We check there are no entries with "~>" in the version field (a constraint
	// marker, not a resolved version).
	for name, ver := range got {
		if strings.Contains(ver, "~>") || strings.Contains(ver, ">=") || strings.Contains(ver, "=") {
			t.Errorf("Podfile.lock: %q has a constraint version %q (should be resolved)", name, ver)
		}
	}
}

func TestParsePodfileLock_Empty(t *testing.T) {
	got := ParsePodfileLock([]byte(""))
	if len(got) != 0 {
		t.Errorf("empty input: expected no pods, got %v", got)
	}
}

func TestParsePodfileLock_SubspecName(t *testing.T) {
	got := ParsePodfileLock([]byte(podfileLockFixture))

	// Subspecs must be stored as full subspec keys.
	if _, ok := got["Firebase/Core"]; !ok {
		t.Error("Firebase/Core subspec should be present")
	}
	if _, ok := got["GoogleUtilities/Environment"]; !ok {
		t.Error("GoogleUtilities/Environment subspec should be present")
	}
}

// ---- ParsePackageResolved tests ----

const packageResolvedV2Fixture = `{
  "originHash" : "abc123",
  "pins" : [
    {
      "identity" : "alamofire",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/Alamofire/Alamofire.git",
      "state" : {
        "revision" : "f455c2975872ccd2d9c81594c658af65716e9b9a",
        "version" : "5.8.1"
      }
    },
    {
      "identity" : "sdwebimage",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/SDWebImage/SDWebImage.git",
      "state" : {
        "revision" : "deadbeef",
        "version" : "5.18.0"
      }
    },
    {
      "identity" : "sentry-cocoa",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/getsentry/sentry-cocoa.git",
      "state" : {
        "revision" : "cafe1234",
        "version" : "8.18.0"
      }
    },
    {
      "identity" : "commit-only-dep",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/example/dep.git",
      "state" : {
        "revision" : "abc123"
      }
    }
  ],
  "version" : 2
}`

const packageResolvedV1Fixture = `{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": {
          "branch": null,
          "revision": "f455c29",
          "version": "5.6.4"
        }
      },
      {
        "package": "SwiftyJSON",
        "repositoryURL": "https://github.com/SwiftyJSON/SwiftyJSON.git",
        "state": {
          "branch": null,
          "revision": "cafecafe",
          "version": "5.0.1"
        }
      }
    ]
  },
  "version": 1
}`

func TestParsePackageResolved_V2(t *testing.T) {
	got := ParsePackageResolved([]byte(packageResolvedV2Fixture))

	cases := map[string]string{
		"alamofire":    "5.8.1",
		"sdwebimage":   "5.18.0",
		"sentry-cocoa": "8.18.0",
	}
	for name, want := range cases {
		if got[name] != want {
			t.Errorf("Package.resolved v2: %q version = %q, want %q", name, got[name], want)
		}
	}

	// commit-only-dep has no version field → must be excluded.
	if _, ok := got["commit-only-dep"]; ok {
		t.Error("commit-only-dep (no version) should be excluded from Package.resolved output")
	}
}

func TestParsePackageResolved_V1(t *testing.T) {
	got := ParsePackageResolved([]byte(packageResolvedV1Fixture))

	cases := map[string]string{
		"Alamofire":  "5.6.4",
		"SwiftyJSON": "5.0.1",
	}
	for name, want := range cases {
		if got[name] != want {
			t.Errorf("Package.resolved v1: %q version = %q, want %q", name, got[name], want)
		}
	}
}

func TestParsePackageResolved_Empty(t *testing.T) {
	got := ParsePackageResolved([]byte(""))
	if len(got) != 0 {
		t.Errorf("empty input: expected no packages, got %v", got)
	}
}

func TestParsePackageResolved_InvalidJSON(t *testing.T) {
	got := ParsePackageResolved([]byte("{invalid json"))
	if len(got) != 0 {
		t.Errorf("invalid JSON: expected empty map, got %v", got)
	}
}

// ---- podPurlName tests ----

func TestPodPurlName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Alamofire", "Alamofire"},
		{"Firebase/Core", "Firebase"},
		{"Firebase/Crashlytics", "Firebase"},
		{"GoogleUtilities/Environment", "GoogleUtilities"},
		{"", ""},
	}
	for _, c := range cases {
		got := podPurlName(c.in)
		if got != c.want {
			t.Errorf("podPurlName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---- EnrichFromIOSLockfiles integration tests ----

// TestEnrichFromIOSLockfiles_PodfileLock verifies that Podfile.lock enrichment
// upgrades an existing component's version and purl.
func TestEnrichFromIOSLockfiles_PodfileLock(t *testing.T) {
	jc := iosJobCtxForDir(t, "ios-enrich-pod")

	podfileLock := `PODS:
  - Alamofire (5.8.0)
  - Kingfisher (7.10.0)
  - UnknownPod (1.0.0)

DEPENDENCIES:
  - Alamofire (~> 5.8)

PODFILE CHECKSUM: abc

COCOAPODS: 1.14.3
`
	if err := os.WriteFile(filepath.Join(jc.Workspace, "Podfile.lock"), []byte(podfileLock), 0o600); err != nil {
		t.Fatalf("write Podfile.lock: %v", err)
	}

	// Simulate an Alamofire framework detected without a version (no Info.plist).
	initial := []models.SBOMComponent{
		models.NewFrameworkComponent("Alamofire", "", "org.cocoapods.Alamofire", "Frameworks/Alamofire.framework"),
	}

	enriched := EnrichFromIOSLockfiles(jc, initial)

	byName := iosIndexByName(enriched)

	// Alamofire should have its version upgraded from "" to "5.8.0".
	alamofire, ok := byName["Alamofire"]
	if !ok {
		t.Fatal("Alamofire component missing")
	}
	if alamofire.Version != "5.8.0" {
		t.Errorf("Alamofire.Version = %q, want 5.8.0", alamofire.Version)
	}
	// purl should be upgraded to pkg:cocoapods.
	if !strings.HasPrefix(alamofire.Purl, "pkg:cocoapods/Alamofire@") {
		t.Errorf("Alamofire.Purl = %q, want pkg:cocoapods/Alamofire@...", alamofire.Purl)
	}

	// Kingfisher was not in initial — should be added as a new component.
	kf, ok := byName["Kingfisher"]
	if !ok {
		t.Fatal("Kingfisher component missing; should have been added from Podfile.lock")
	}
	if kf.Version != "7.10.0" {
		t.Errorf("Kingfisher.Version = %q, want 7.10.0", kf.Version)
	}

	// UnknownPod should also have been added.
	if _, ok := byName["UnknownPod"]; !ok {
		t.Error("UnknownPod should have been added from Podfile.lock")
	}
}

// TestEnrichFromIOSLockfiles_PackageResolved verifies Package.resolved enrichment.
func TestEnrichFromIOSLockfiles_PackageResolved(t *testing.T) {
	jc := iosJobCtxForDir(t, "ios-enrich-spm")

	packageResolved := `{
  "pins": [
    {
      "identity": "alamofire",
      "kind": "remoteSourceControl",
      "location": "https://github.com/Alamofire/Alamofire.git",
      "state": { "revision": "abc", "version": "5.9.0" }
    },
    {
      "identity": "rxswift",
      "kind": "remoteSourceControl",
      "location": "https://github.com/ReactiveX/RxSwift.git",
      "state": { "revision": "def", "version": "6.6.0" }
    }
  ],
  "version": 2
}`
	if err := os.WriteFile(filepath.Join(jc.Workspace, "Package.resolved"), []byte(packageResolved), 0o600); err != nil {
		t.Fatalf("write Package.resolved: %v", err)
	}

	// Simulate a framework detected without version.
	initial := []models.SBOMComponent{
		models.NewFrameworkComponent("Alamofire", "", "", "Frameworks/Alamofire.framework"),
	}

	enriched := EnrichFromIOSLockfiles(jc, initial)
	byName := iosIndexByName(enriched)

	// Case-insensitive match: "alamofire" in Package.resolved should match "Alamofire" component.
	alamofire, ok := byName["Alamofire"]
	if !ok {
		t.Fatal("Alamofire component missing after Package.resolved enrichment")
	}
	if alamofire.Version != "5.9.0" {
		t.Errorf("Alamofire.Version = %q, want 5.9.0", alamofire.Version)
	}

	// RxSwift was not in initial — should be added.
	if _, ok := byName["rxswift"]; !ok {
		// Also try original key from order (we may use the identity key "rxswift").
		found := false
		for _, c := range enriched {
			if strings.EqualFold(c.Name, "rxswift") {
				found = true
				if c.Version != "6.6.0" {
					t.Errorf("rxswift.Version = %q, want 6.6.0", c.Version)
				}
				break
			}
		}
		if !found {
			t.Error("rxswift component missing; should have been added from Package.resolved")
		}
	}
}

// TestEnrichFromIOSLockfiles_NoLockfile asserts no-op when no lockfile exists.
func TestEnrichFromIOSLockfiles_NoLockfile(t *testing.T) {
	jc := iosJobCtxForDir(t, "ios-enrich-none")

	initial := []models.SBOMComponent{
		models.NewFrameworkComponent("Alamofire", "5.0.0", "", "Frameworks/Alamofire.framework"),
	}
	enriched := EnrichFromIOSLockfiles(jc, initial)
	if len(enriched) != 1 {
		t.Errorf("expected 1 component (unchanged), got %d", len(enriched))
	}
	if enriched[0].Version != "5.0.0" {
		t.Errorf("version unexpectedly changed to %q", enriched[0].Version)
	}
}

// TestEnrichFromIOSLockfiles_ExistingVersionNotOverwritten asserts that an
// existing version (from Info.plist parsing) is NOT overwritten by the lockfile.
func TestEnrichFromIOSLockfiles_ExistingVersionNotOverwritten(t *testing.T) {
	jc := iosJobCtxForDir(t, "ios-enrich-nooverwrite")

	podfileLock := `PODS:
  - Alamofire (5.8.0)

PODFILE CHECKSUM: abc

COCOAPODS: 1.14.3
`
	if err := os.WriteFile(filepath.Join(jc.Workspace, "Podfile.lock"), []byte(podfileLock), 0o600); err != nil {
		t.Fatalf("write Podfile.lock: %v", err)
	}

	// Alamofire already has a version from Info.plist.
	initial := []models.SBOMComponent{
		models.NewFrameworkComponent("Alamofire", "5.7.0", "org.cocoapods.Alamofire", "Frameworks/Alamofire.framework"),
	}

	enriched := EnrichFromIOSLockfiles(jc, initial)
	byName := iosIndexByName(enriched)

	alamofire := byName["Alamofire"]
	// The existing version (5.7.0 from Info.plist) must be preserved.
	if alamofire.Version != "5.7.0" {
		t.Errorf("Alamofire.Version = %q, want 5.7.0 (must not be overwritten by Podfile.lock)", alamofire.Version)
	}
	// But the purl should still be upgraded to include the lockfile evidence.
	hasPodPurl := false
	for _, id := range alamofire.Evidence.Identity {
		if id.Field == "purl" && strings.HasPrefix(id.ConcludedValue, "pkg:cocoapods/") {
			hasPodPurl = true
			break
		}
	}
	if !hasPodPurl {
		t.Error("Alamofire should have a pkg:cocoapods purl identity from Podfile.lock enrichment")
	}
}

// TestEnrichFromIOSLockfiles_SubspecHandling verifies that a "Firebase/Core"
// subspec entry produces a component with the correct purl (root pod name used).
func TestEnrichFromIOSLockfiles_SubspecHandling(t *testing.T) {
	jc := iosJobCtxForDir(t, "ios-enrich-subspec")

	podfileLock := `PODS:
  - Firebase/Core (10.2.0):
    - Firebase/CoreOnly (= 10.2.0)
  - Firebase/Analytics (10.2.0):
    - Firebase/Core (= 10.2.0)

PODFILE CHECKSUM: abc

COCOAPODS: 1.14.3
`
	if err := os.WriteFile(filepath.Join(jc.Workspace, "Podfile.lock"), []byte(podfileLock), 0o600); err != nil {
		t.Fatalf("write Podfile.lock: %v", err)
	}

	enriched := EnrichFromIOSLockfiles(jc, nil)
	byName := iosIndexByName(enriched)

	// Firebase/Core subspec should be present with purl using root pod "Firebase".
	fc, ok := byName["Firebase/Core"]
	if !ok {
		t.Fatal("Firebase/Core subspec component missing")
	}
	if fc.Version != "10.2.0" {
		t.Errorf("Firebase/Core.Version = %q, want 10.2.0", fc.Version)
	}
	// purl root pod name is "Firebase", not "Firebase/Core".
	if !strings.Contains(fc.Purl, "pkg:cocoapods/Firebase@") {
		t.Errorf("Firebase/Core.Purl = %q, want pkg:cocoapods/Firebase@...", fc.Purl)
	}
}

// iosIndexByName builds a name→component map for assertions in iOS tests.
func iosIndexByName(cs []models.SBOMComponent) map[string]models.SBOMComponent {
	m := make(map[string]models.SBOMComponent, len(cs))
	for _, c := range cs {
		m[c.Name] = c
	}
	return m
}
