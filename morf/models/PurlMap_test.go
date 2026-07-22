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

// TestPurlForCocoaPodsByBundleID proves the org.cocoapods.* CFBundleIdentifier
// anchor forces the pkg:cocoapods emit path with the spec-correct NO-namespace
// shape and an appended version.
func TestPurlForCocoaPodsByBundleID(t *testing.T) {
	purl, group, matched := PurlFor("Alamofire", "org.cocoapods.Alamofire", "5.9.0")
	if !matched {
		t.Fatalf("PurlFor(Alamofire, org.cocoapods.Alamofire) matched=false; want true")
	}
	if want := "pkg:cocoapods/Alamofire@5.9.0"; purl != want {
		t.Errorf("purl = %q; want %q", purl, want)
	}
	if group != "" {
		t.Errorf("group = %q; want empty (CocoaPods has no namespace/group)", group)
	}
}

// TestPurlForCocoaPodsNoVersion proves the CocoaPods form omits the version
// segment when the version is unknown.
func TestPurlForCocoaPodsNoVersion(t *testing.T) {
	purl, _, matched := PurlFor("SnapKit", "org.cocoapods.SnapKit", "")
	if !matched {
		t.Fatalf("matched=false; want true")
	}
	if want := "pkg:cocoapods/SnapKit"; purl != want {
		t.Errorf("purl = %q; want %q", purl, want)
	}
}

// TestPurlForMavenSetsGroup proves an Android/Java library resolves to
// pkg:maven/<groupId>/<artifact>@<ver> and that group=<groupId> is set. There
// is no pkg:gradle.
func TestPurlForMavenSetsGroup(t *testing.T) {
	purl, group, matched := PurlFor("firebase-analytics", "", "21.5.0")
	if !matched {
		t.Fatalf("PurlFor(firebase-analytics) matched=false; want true")
	}
	if want := "pkg:maven/com.google.firebase/firebase-analytics@21.5.0"; purl != want {
		t.Errorf("purl = %q; want %q", purl, want)
	}
	if want := "com.google.firebase"; group != want {
		t.Errorf("group = %q; want %q", group, want)
	}
}

// TestPurlForMavenTakesPrecedenceOverBundleHint proves a Maven-only entry emits
// pkg:maven even if a (nonsensical) cocoapods bundle hint is passed — Maven
// coordinates are unambiguous and never downgrade to a Swift/CocoaPods guess.
func TestPurlForMavenIgnoresBundleHint(t *testing.T) {
	purl, group, matched := PurlFor("okhttp", "org.cocoapods.whatever", "4.12.0")
	if !matched {
		t.Fatalf("matched=false; want true")
	}
	if want := "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"; purl != want {
		t.Errorf("purl = %q; want %q", purl, want)
	}
	if group != "com.squareup.okhttp3" {
		t.Errorf("group = %q; want com.squareup.okhttp3", group)
	}
}

// TestPurlForSwiftHostForm proves that, absent a CocoaPods signal, an iOS
// library with a confident SPM coordinate emits the host-namespaced pkg:swift
// form (pkg:swift REQUIRES a source host).
func TestPurlForSwiftHostForm(t *testing.T) {
	// No cocoapods bundle hint (bundleID empty) -> prefer the SPM host form.
	purl, group, matched := PurlFor("Alamofire", "", "5.9.0")
	if !matched {
		t.Fatalf("matched=false; want true")
	}
	if want := "pkg:swift/github.com/Alamofire/Alamofire@5.9.0"; purl != want {
		t.Errorf("purl = %q; want %q", purl, want)
	}
	if group != "" {
		t.Errorf("group = %q; want empty for pkg:swift", group)
	}
}

// TestPurlForCocoaPodsBeatsSwiftWhenHinted proves the CocoaPods bundle hint
// wins even when the entry also has an SPM host: a pod on device was, by
// construction, delivered by CocoaPods.
func TestPurlForCocoaPodsBeatsSwiftWhenHinted(t *testing.T) {
	purl, _, matched := PurlFor("Kingfisher", "org.cocoapods.Kingfisher", "7.0.0")
	if !matched {
		t.Fatalf("matched=false; want true")
	}
	if want := "pkg:cocoapods/Kingfisher@7.0.0"; purl != want {
		t.Errorf("purl = %q; want %q (CocoaPods hint must beat SPM host)", purl, want)
	}
}

// TestPurlForCocoaPodsOnlyEntry proves a pod-only entry (no SPM host, e.g.
// Bolts) emits pkg:cocoapods even without a bundle hint, because there is no
// SPM coordinate to fall back to.
func TestPurlForCocoaPodsOnlyEntry(t *testing.T) {
	purl, _, matched := PurlFor("Bolts", "", "")
	if !matched {
		t.Fatalf("matched=false; want true")
	}
	if want := "pkg:cocoapods/Bolts"; purl != want {
		t.Errorf("purl = %q; want %q", purl, want)
	}
}

// TestPurlForPodNameAliasing proves libraries whose on-device framework name
// differs from the pod name (Lottie -> lottie-ios, Flurry_iOS_SDK ->
// Flurry-iOS-SDK) map to the real pod coordinate.
func TestPurlForPodNameAliasing(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"Lottie", "pkg:cocoapods/lottie-ios"},
		{"Flurry_iOS_SDK", "pkg:cocoapods/Flurry-iOS-SDK"},
	}
	for _, tc := range cases {
		purl, _, matched := PurlFor(tc.name, "org.cocoapods."+tc.name, "")
		if !matched {
			t.Errorf("PurlFor(%s) matched=false; want true", tc.name)
			continue
		}
		if purl != tc.want {
			t.Errorf("PurlFor(%s) = %q; want %q", tc.name, purl, tc.want)
		}
	}
}

// TestPurlForUnknownFallsBackGeneric proves an unmapped library returns
// matched=false with empty purl/group, so the CALLER keeps its pkg:generic
// fallback and MORF never fabricates a coordinate.
func TestPurlForUnknownFallsBackGeneric(t *testing.T) {
	purl, group, matched := PurlFor("TotallyProprietaryInternalSDK", "com.acme.internal", "1.0")
	if matched {
		t.Errorf("matched=true for unknown library; want false")
	}
	if purl != "" || group != "" {
		t.Errorf("purl=%q group=%q; want both empty for unmatched", purl, group)
	}
}

// TestPurlForEmptyName proves an empty name never matches.
func TestPurlForEmptyName(t *testing.T) {
	if _, _, matched := PurlFor("", "org.cocoapods.Alamofire", "1.0"); matched {
		t.Errorf("matched=true for empty name; want false")
	}
}
