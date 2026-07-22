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

import (
	"fmt"
	"strings"
)

// PurlMap is the curated, sourced mapping from an observed mobile third-party
// library to its REAL Package-URL (purl) coordinate.
//
// Why a curated table rather than string-munging?  A purl is a claim about a
// package in a specific registry, and every ecosystem has different, spec-
// mandated shape rules (see https://github.com/package-url/purl-spec):
//
//   - pkg:cocoapods  — has NO namespace. The pod name is the whole "name"
//     component: pkg:cocoapods/<Pod>@<ver>. (purl-spec cocoapods definition.)
//   - pkg:swift      — REQUIRES a source-host namespace (Swift Package Manager
//     resolves by repo URL, not a central registry):
//     pkg:swift/github.com/<org>/<repo>@<ver>. (purl-spec swift definition.)
//   - pkg:maven      — namespace is the Maven groupId, name is the artifactId:
//     pkg:maven/<groupId>/<artifact>@<ver>. There is NO pkg:gradle — Gradle is a
//     build tool, its dependencies ARE Maven coordinates. (purl-spec maven
//     definition.)
//
// Getting these wrong (e.g. emitting pkg:cocoapods/org.alamofire/Alamofire, or
// a bare pkg:swift/Alamofire with no host) produces a purl that no scanner can
// resolve — worse than the honest pkg:generic fallback. So MORF only emits an
// ecosystem purl for a library it can map to a coordinate it is CONFIDENT is
// real; everything else falls through to pkg:generic (matched=false).
//
// The reverse-DNS iOS CFBundleIdentifier is a strong ecosystem anchor: a bundle
// id beginning "org.cocoapods." was, by construction, packaged by CocoaPods, so
// we can safely emit a pkg:cocoapods purl for it. For a swift-only distribution
// (SPM), we emit the host form.

// purlEntry is one curated mapping. Exactly one of the ecosystem coordinate
// fields is authoritative per emit path; unused fields stay empty.
type purlEntry struct {
	// cocoapods is the CocoaPods pod name (the whole purl name; no namespace).
	// Empty when the library is not distributed as a Pod.
	cocoapods string
	// swiftHost is the Swift Package Manager source coordinate WITHOUT the
	// leading "pkg:swift/" and WITHOUT a version, e.g.
	// "github.com/Alamofire/Alamofire". Empty when there is no confident SPM
	// coordinate.
	swiftHost string
	// mavenGroup / mavenArtifact are the Maven groupId / artifactId used for
	// the Android emit path. Both empty when there is no confident Maven
	// coordinate.
	mavenGroup    string
	mavenArtifact string
}

// purlTable maps a canonical library name (as observed on-device: the
// framework bundle base name, the Mach-O LC_LOAD_DYLIB import name, or a
// declared dependency name) to its curated coordinate(s).
//
// CONSERVATIVE BY DESIGN: only entries whose coordinate has been verified
// against the pod's podspec / the SPM repo / the Maven artifact appear here.
// If a library is not in this table, PurlFor returns matched=false and the
// caller keeps pkg:generic. Do not add speculative rows.
//
// Sources are cited inline: CP=CocoaPods trunk pod name, SPM=Swift Package
// Manager repo, MVN=Maven groupId:artifactId. NOTE the registry differs by
// group: Square/Google-code/Bumptech artifacts resolve from Maven Central
// (repo1.maven.org), but com.google.firebase:* resolves from GOOGLE'S Maven
// (maven.google.com / dl.google.com/dl/android/maven2), NOT Maven Central. The
// PURL coordinate (pkg:maven/<group>/<artifact>) is registry-agnostic and
// correct either way; only the resolution host differs.
var purlTable = map[string]purlEntry{
	// Alamofire — Swift HTTP networking. CP: Alamofire. SPM: github.com/Alamofire/Alamofire.
	"Alamofire": {cocoapods: "Alamofire", swiftHost: "github.com/Alamofire/Alamofire"},
	// AFNetworking — Obj-C HTTP networking. CP: AFNetworking. SPM: github.com/AFNetworking/AFNetworking.
	"AFNetworking": {cocoapods: "AFNetworking", swiftHost: "github.com/AFNetworking/AFNetworking"},
	// SDWebImage — async image loader/cache. CP: SDWebImage. SPM: github.com/SDWebImage/SDWebImage.
	"SDWebImage": {cocoapods: "SDWebImage", swiftHost: "github.com/SDWebImage/SDWebImage"},
	// Kingfisher — Swift image loader/cache. CP: Kingfisher. SPM: github.com/onevcat/Kingfisher.
	"Kingfisher": {cocoapods: "Kingfisher", swiftHost: "github.com/onevcat/Kingfisher"},
	// RxSwift — reactive extensions. CP: RxSwift. SPM: github.com/ReactiveX/RxSwift.
	"RxSwift": {cocoapods: "RxSwift", swiftHost: "github.com/ReactiveX/RxSwift"},
	// RxCocoa — RxSwift Cocoa bindings; ships from the SAME ReactiveX/RxSwift repo. CP: RxCocoa.
	"RxCocoa": {cocoapods: "RxCocoa", swiftHost: "github.com/ReactiveX/RxSwift"},
	// SnapKit — Auto Layout DSL. CP: SnapKit. SPM: github.com/SnapKit/SnapKit.
	"SnapKit": {cocoapods: "SnapKit", swiftHost: "github.com/SnapKit/SnapKit"},
	// Lottie — Airbnb animation renderer. CP pod is "lottie-ios". SPM: github.com/airbnb/lottie-ios.
	"Lottie": {cocoapods: "lottie-ios", swiftHost: "github.com/airbnb/lottie-ios"},
	// The framework binary Lottie ships under is "Lottie"; the pod/SPM name is "lottie-ios".
	"lottie-ios": {cocoapods: "lottie-ios", swiftHost: "github.com/airbnb/lottie-ios"},
	// Realm — Obj-C/Swift mobile database. CP: Realm. SPM: github.com/realm/realm-swift.
	"Realm": {cocoapods: "Realm", swiftHost: "github.com/realm/realm-swift"},
	// RealmSwift — Swift API over Realm; same realm/realm-swift repo. CP: RealmSwift.
	"RealmSwift": {cocoapods: "RealmSwift", swiftHost: "github.com/realm/realm-swift"},
	// Firebase core/analytics/crashlytics — CP pod names as published by the
	// firebase-ios-sdk. SPM: github.com/firebase/firebase-ios-sdk (one repo, many products).
	"FirebaseCore":        {cocoapods: "FirebaseCore", swiftHost: "github.com/firebase/firebase-ios-sdk"},
	"FirebaseAnalytics":   {cocoapods: "FirebaseAnalytics", swiftHost: "github.com/firebase/firebase-ios-sdk"},
	"FirebaseCrashlytics": {cocoapods: "FirebaseCrashlytics", swiftHost: "github.com/firebase/firebase-ios-sdk"},
	// GoogleUtilities — Firebase shared utils. CP: GoogleUtilities. SPM: github.com/google/GoogleUtilities.
	"GoogleUtilities": {cocoapods: "GoogleUtilities", swiftHost: "github.com/google/GoogleUtilities"},
	// GTMSessionFetcher — Google HTTP session fetcher. CP: GTMSessionFetcher. SPM: github.com/google/gtm-session-fetcher.
	"GTMSessionFetcher": {cocoapods: "GTMSessionFetcher", swiftHost: "github.com/google/gtm-session-fetcher"},
	// FBSDKCoreKit — Facebook SDK core. CP: FBSDKCoreKit. SPM: github.com/facebook/facebook-ios-sdk.
	"FBSDKCoreKit": {cocoapods: "FBSDKCoreKit", swiftHost: "github.com/facebook/facebook-ios-sdk"},
	// Crashlytics — legacy standalone Fabric Crashlytics pod (pre-Firebase). CP: Crashlytics.
	"Crashlytics": {cocoapods: "Crashlytics"},
	// Parse — Parse mobile backend SDK. CP: Parse. SPM: github.com/parse-community/Parse-SDK-iOS-OSX.
	"Parse": {cocoapods: "Parse", swiftHost: "github.com/parse-community/Parse-SDK-iOS-OSX"},
	// Bolts — Parse/Facebook task framework. CP: Bolts.
	"Bolts": {cocoapods: "Bolts"},
	// Flurry analytics — CP pod is "Flurry-iOS-SDK". The framework/import name is Flurry_iOS_SDK.
	"Flurry_iOS_SDK": {cocoapods: "Flurry-iOS-SDK"},
	"Flurry-iOS-SDK": {cocoapods: "Flurry-iOS-SDK"},
	// Sentry — crash/error monitoring. CP: Sentry. SPM: github.com/getsentry/sentry-cocoa.
	"Sentry": {cocoapods: "Sentry", swiftHost: "github.com/getsentry/sentry-cocoa"},
	// Nimble — matcher/assertion framework. CP: Nimble. SPM: github.com/Quick/Nimble.
	"Nimble": {cocoapods: "Nimble", swiftHost: "github.com/Quick/Nimble"},
	// Quick — BDD test framework. CP: Quick. SPM: github.com/Quick/Quick.
	"Quick": {cocoapods: "Quick", swiftHost: "github.com/Quick/Quick"},
	// Moya — network abstraction over Alamofire. CP: Moya. SPM: github.com/Moya/Moya.
	"Moya": {cocoapods: "Moya", swiftHost: "github.com/Moya/Moya"},
	// SwiftyJSON — JSON handling. CP: SwiftyJSON. SPM: github.com/SwiftyJSON/SwiftyJSON.
	"SwiftyJSON": {cocoapods: "SwiftyJSON", swiftHost: "github.com/SwiftyJSON/SwiftyJSON"},
	// Charts — Danielgindi/DGCharts charting. CP pod is "Charts". SPM: github.com/danielgindi/Charts.
	"Charts": {cocoapods: "Charts", swiftHost: "github.com/danielgindi/Charts"},

	// --- Android / Java Maven coordinates (Firebase + common known set) ---
	// group=<groupId>, name=<artifactId>. Firebase Android core/analytics/
	// crashlytics resolve from GOOGLE'S Maven (maven.google.com), not Maven
	// Central; the coordinate below is the real, canonical one build tools use.
	"firebase-core":        {mavenGroup: "com.google.firebase", mavenArtifact: "firebase-core"},
	"firebase-analytics":   {mavenGroup: "com.google.firebase", mavenArtifact: "firebase-analytics"},
	"firebase-crashlytics": {mavenGroup: "com.google.firebase", mavenArtifact: "firebase-crashlytics"},
	"firebase-messaging":   {mavenGroup: "com.google.firebase", mavenArtifact: "firebase-messaging"},
	// Firebase BOM (bill of materials) — the pinning artifact for the Firebase Android SDK set.
	"firebase-bom": {mavenGroup: "com.google.firebase", mavenArtifact: "firebase-bom"},
	// OkHttp — Square HTTP client. MVN com.squareup.okhttp3:okhttp.
	"okhttp": {mavenGroup: "com.squareup.okhttp3", mavenArtifact: "okhttp"},
	// Retrofit — Square type-safe HTTP client. MVN com.squareup.retrofit2:retrofit.
	"retrofit": {mavenGroup: "com.squareup.retrofit2", mavenArtifact: "retrofit"},
	// Gson — Google JSON (de)serialization. MVN com.google.code.gson:gson.
	"gson": {mavenGroup: "com.google.code.gson", mavenArtifact: "gson"},
	// Glide — Bumptech image loading. MVN com.github.bumptech.glide:glide.
	"glide": {mavenGroup: "com.github.bumptech.glide", mavenArtifact: "glide"},
}

// FirebaseCocoaPodsPurl is the purl for the aggregate Firebase pod on iOS
// (the "Firebase" umbrella CocoaPod). Sourced from CP pod name "Firebase".
const FirebaseCocoaPodsPurl = "pkg:cocoapods/Firebase"

// FirebaseMavenBOMPurl is the purl for the Firebase Android BOM, the canonical
// pinning artifact for the Firebase Android SDK. MVN com.google.firebase:firebase-bom.
const FirebaseMavenBOMPurl = "pkg:maven/com.google.firebase/firebase-bom"

// bundleIDIsCocoaPods reports whether a reverse-DNS iOS CFBundleIdentifier was
// produced by CocoaPods. CocoaPods stamps embedded pod frameworks with a bundle
// id under the "org.cocoapods." prefix (e.g. "org.cocoapods.Alamofire"), so
// this prefix is a reliable, self-declaring CocoaPods ecosystem anchor.
func bundleIDIsCocoaPods(bundleID string) bool {
	return strings.HasPrefix(bundleID, "org.cocoapods.")
}

// PurlFor resolves the real Package-URL for an observed library.
//
// Inputs:
//   - name:     the on-device library name (framework bundle base name, dylib
//     import name, or declared dependency). This is the primary table key.
//   - bundleID: the iOS CFBundleIdentifier, when known. Used only as an
//     ecosystem HINT: an "org.cocoapods." prefix forces the CocoaPods emit path.
//     Pass "" for Android / Mach-O imports.
//   - version:  the resolved version, when known. Appended as @<ver> only for
//     ecosystems whose spec version segment we can populate confidently.
//
// Returns (purl, group, matched):
//   - matched=false when name is empty or not in the curated table. purl/group
//     are "" and the CALLER must keep its pkg:generic fallback. PurlFor never
//     fabricates a coordinate.
//   - matched=true with a spec-correct purl otherwise. group is the Maven
//     groupId for a Maven match and "" for CocoaPods/Swift (those ecosystems
//     have no separate group in MORF's model).
//
// Emit-path selection:
//   - A Maven-only entry (Android) always emits pkg:maven and sets group.
//   - An iOS entry emits pkg:cocoapods when the bundleID says CocoaPods OR when
//     the entry has a pod name but no SPM host. It emits the pkg:swift host form
//     only when there is a confident SPM coordinate AND no CocoaPods signal.
//     This keeps the honest default (a pod on device came via CocoaPods) while
//     still using the host-namespaced Swift form when that is the real source.
func PurlFor(name, bundleID, version string) (purl string, group string, matched bool) {
	if name == "" {
		return "", "", false
	}
	entry, ok := purlTable[name]
	if !ok {
		return "", "", false
	}

	// Maven (Android/Java): namespace=groupId, name=artifactId. Always sets group.
	if entry.mavenArtifact != "" && entry.mavenGroup != "" {
		return mavenPurl(entry.mavenGroup, entry.mavenArtifact, version), entry.mavenGroup, true
	}

	cocoaPodsHinted := bundleIDIsCocoaPods(bundleID)

	// CocoaPods: emit when the bundleID declares CocoaPods, or when we have a pod
	// name but no SPM host to fall back to.
	if entry.cocoapods != "" && (cocoaPodsHinted || entry.swiftHost == "") {
		return cocoaPodsPurl(entry.cocoapods, version), "", true
	}

	// Swift Package Manager: host-namespaced form. Preferred when we have a
	// confident SPM coordinate and no CocoaPods signal.
	if entry.swiftHost != "" {
		return swiftPurl(entry.swiftHost, version), "", true
	}

	// Entry present but no usable coordinate (should not happen given the table
	// invariants) — keep the generic fallback rather than emit a malformed purl.
	return "", "", false
}

// cocoaPodsPurl builds pkg:cocoapods/<Pod>[@<ver>]. CocoaPods purls have NO
// namespace — the pod name is the entire name segment (purl-spec cocoapods).
func cocoaPodsPurl(pod, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:cocoapods/%s@%s", pod, version)
	}
	return fmt.Sprintf("pkg:cocoapods/%s", pod)
}

// swiftPurl builds pkg:swift/<host>/<org>/<repo>[@<ver>]. Swift purls REQUIRE a
// source-host namespace (purl-spec swift); host already carries "host/org/repo".
func swiftPurl(host, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:swift/%s@%s", host, version)
	}
	return fmt.Sprintf("pkg:swift/%s", host)
}

// mavenPurl builds pkg:maven/<groupId>/<artifact>[@<ver>] (purl-spec maven).
// There is intentionally no pkg:gradle — Gradle dependencies ARE Maven coords.
func mavenPurl(group, artifact, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:maven/%s/%s@%s", group, artifact, version)
	}
	return fmt.Sprintf("pkg:maven/%s/%s", group, artifact)
}
