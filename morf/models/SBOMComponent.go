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

// SBOMComponent models a single CycloneDX 1.6 component together with the
// EVIDENCE that justifies its identity. This is the contract type that the
// platform extractors (iOS frameworks/dylibs, Android native libs, runtimes)
// populate and that utils.exportCycloneDX consumes.
//
// The evidence graph is deliberately explicit: every identity conclusion
// (name/version/purl/hash) records the analysis techniques that produced it
// and a per-technique confidence, so downstream supply-chain tooling can
// reason about how strongly each component was identified rather than trusting
// a bare component list. MORF only ever emits an evidence-based lower bound —
// it never fabricates identities it cannot substantiate.
//
// JSON field names are chosen to map 1:1 onto the CycloneDX 1.6 component
// object, so the exporter can serialize evidence with minimal reshaping.
type SBOMComponent struct {
	// Type is the CycloneDX component classification: "library",
	// "framework", or "application".
	Type string `json:"type"`
	// Name is the component name (e.g. "Alamofire", "libflutter.so").
	Name string `json:"name"`
	// Version is the resolved component version, when known.
	Version string `json:"version,omitempty"`
	// BomRef is the document-local unique reference for this component,
	// used by compositions and dependency edges.
	BomRef string `json:"bom-ref"`
	// Purl is the package URL. MORF emits pkg:generic/<name>[@<version>]
	// by default and never fabricates an ecosystem-specific host.
	Purl string `json:"purl,omitempty"`
	// Hashes carries content hashes (typically SHA-256) proving byte
	// identity of the underlying artifact.
	Hashes []SBOMHash `json:"hashes,omitempty"`
	// Group is the optional namespace/vendor grouping.
	Group string `json:"group,omitempty"`
	// Scope is the optional CycloneDX scope ("required"/"optional"/"excluded").
	Scope string `json:"scope,omitempty"`
	// Evidence is the identity + occurrence evidence graph.
	Evidence SBOMEvidence `json:"evidence"`
}

// SBOMHash is a single CycloneDX hash entry.
type SBOMHash struct {
	// Alg is the hash algorithm identifier (e.g. "SHA-256").
	Alg string `json:"alg"`
	// Content is the hex-encoded digest.
	Content string `json:"content"`
}

// SBOMEvidence is the CycloneDX 1.6 evidence object: the identity conclusions
// plus the physical occurrences where the component was observed.
type SBOMEvidence struct {
	// Identity holds one entry per identified field (name/version/purl/hash).
	Identity []SBOMIdentity `json:"identity,omitempty"`
	// Occurrences lists the physical locations the component was found at.
	Occurrences []SBOMOccurrence `json:"occurrences,omitempty"`
}

// SBOMIdentity is a CycloneDX identity evidence entry: a single field, the
// overall confidence in that conclusion, the concluded value, and the set of
// analysis methods that support it.
type SBOMIdentity struct {
	// Field is the identified attribute: "name", "version", "purl", or "hash".
	Field string `json:"field"`
	// Confidence is the aggregate confidence for this identity in [0,1].
	Confidence float64 `json:"confidence"`
	// ConcludedValue is the value MORF concluded for this field.
	ConcludedValue string `json:"concludedValue,omitempty"`
	// Methods are the individual analysis techniques backing the conclusion.
	Methods []SBOMMethod `json:"methods"`
}

// SBOMMethod is a single analysis technique that contributed to an identity
// conclusion.
type SBOMMethod struct {
	// Technique is the analysis technique: "binary-analysis",
	// "manifest-analysis", "ast-fingerprint", "hash-comparison", or "filename".
	Technique string `json:"technique"`
	// Confidence is this technique's confidence in [0,1].
	Confidence float64 `json:"confidence"`
	// Value is the technique-specific evidence value (e.g. the filename or
	// the digest that was compared).
	Value string `json:"value"`
}

// SBOMOccurrence is a physical location where the component was observed.
type SBOMOccurrence struct {
	// Location is the in-artifact path (e.g. "Frameworks/Alamofire.framework").
	Location string `json:"location"`
}

// Confidence bands used across the constructors. Extractors should prefer
// these named constants over bare literals so evidence stays consistent.
const (
	// ConfidenceHigh is used for byte-exact evidence such as a SHA-256
	// hash comparison.
	ConfidenceHigh = 0.9
	// ConfidenceMedium is used for structured metadata evidence such as a
	// manifest / Info.plist version field.
	ConfidenceMedium = 0.6
	// ConfidenceLow is used for weak, name-only evidence such as a bare
	// filename with no corroborating metadata.
	ConfidenceLow = 0.35
)

// Analysis technique identifiers (CycloneDX 1.6 evidence.identity.methods.technique).
const (
	TechniqueBinaryAnalysis   = "binary-analysis"
	TechniqueManifestAnalysis = "manifest-analysis"
	TechniqueASTFingerprint   = "ast-fingerprint"
	TechniqueHashComparison   = "hash-comparison"
	TechniqueFilename         = "filename"
)

// genericPurl builds the default package URL. MORF deliberately emits the
// ecosystem-agnostic pkg:generic namespace: it observes an artifact on disk,
// not a resolved package from a known registry, so inventing a pkg:swift /
// pkg:maven host would overstate identity. Version is appended only when known.
func genericPurl(name, version string) string {
	if name == "" {
		return ""
	}
	if version != "" {
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:generic/%s", name)
}

// NewFrameworkComponent builds a "framework" component for an iOS/embedded
// framework observed at path.
//
// The bundleID is the framework's CFBundleIdentifier (e.g.
// "org.cocoapods.Alamofire", "io.realm.Realm"), used purely as an ecosystem
// anchor for purl mapping — it is NOT recorded as a field, only fed to PurlFor.
//
// Purl + group:
//   - When PurlFor(name, bundleID, version) matches, the component carries the
//     real ecosystem purl (pkg:cocoapods / pkg:swift / pkg:maven), Group is set
//     for a Maven match, and an ADDITIONAL "purl" identity is recorded. Its
//     technique is manifest-analysis when the mapping was anchored by the
//     bundleID (an org.cocoapods.* CFBundleIdentifier we parsed from a plist),
//     or ast-fingerprint when the mapping was name-only (we recognized the
//     library from its binary/framework name alone). Either way at MEDIUM
//     confidence — a curated coordinate is a strong-but-not-byte-exact claim.
//   - When there is no confident mapping, the component keeps the honest
//     pkg:generic purl and only the name/version evidence below.
//
// Name/version evidence (always present):
//   - When version is present, the name+version identity is backed by
//     manifest-analysis (an Info.plist / manifest field) at MEDIUM confidence.
//   - When version is absent, only the name is concluded, backed by filename
//     evidence at LOW confidence.
//
// A single occurrence records the framework's path.
func NewFrameworkComponent(name, version, bundleID, path string) SBOMComponent {
	c := SBOMComponent{
		Type:    "framework",
		Name:    name,
		Version: version,
		BomRef:  "framework:" + name,
		Purl:    genericPurl(name, version),
	}
	if path != "" {
		c.Evidence.Occurrences = []SBOMOccurrence{{Location: path}}
	}

	if version != "" {
		c.Evidence.Identity = []SBOMIdentity{
			{
				Field:          "name",
				Confidence:     ConfidenceMedium,
				ConcludedValue: name,
				Methods: []SBOMMethod{
					{Technique: TechniqueManifestAnalysis, Confidence: ConfidenceMedium, Value: name},
				},
			},
			{
				Field:          "version",
				Confidence:     ConfidenceMedium,
				ConcludedValue: version,
				Methods: []SBOMMethod{
					{Technique: TechniqueManifestAnalysis, Confidence: ConfidenceMedium, Value: version},
				},
			},
		}
	} else {
		c.Evidence.Identity = []SBOMIdentity{
			{
				Field:          "name",
				Confidence:     ConfidenceLow,
				ConcludedValue: name,
				Methods: []SBOMMethod{
					{Technique: TechniqueFilename, Confidence: ConfidenceLow, Value: name},
				},
			},
		}
	}

	// Upgrade the ecosystem-agnostic pkg:generic purl to a curated, real
	// coordinate when we are confident of one. bundleID anchoring (an
	// org.cocoapods.* CFBundleIdentifier) is manifest-analysis; recognizing the
	// library from its name alone is ast-fingerprint.
	if purl, group, matched := PurlFor(name, bundleID, version); matched {
		c.Purl = purl
		if group != "" {
			c.Group = group
		}
		technique := TechniqueASTFingerprint
		if bundleIDIsCocoaPods(bundleID) {
			technique = TechniqueManifestAnalysis
		}
		c.Evidence.Identity = append(c.Evidence.Identity, SBOMIdentity{
			Field:          "purl",
			Confidence:     ConfidenceMedium,
			ConcludedValue: purl,
			Methods: []SBOMMethod{
				{Technique: technique, Confidence: ConfidenceMedium, Value: purl},
			},
		})
	}
	return c
}

// NewDylibComponent builds a "library" component for a Mach-O dynamic library
// (dylib) observed at path. Identity is name-only via filename evidence at LOW
// confidence — a bare dylib name without a version string or hash is weak
// evidence.
func NewDylibComponent(name, path string) SBOMComponent {
	c := SBOMComponent{
		Type:   "library",
		Name:   name,
		BomRef: "dylib:" + name,
		Purl:   genericPurl(name, ""),
		Evidence: SBOMEvidence{
			Identity: []SBOMIdentity{
				{
					Field:          "name",
					Confidence:     ConfidenceLow,
					ConcludedValue: name,
					Methods: []SBOMMethod{
						{Technique: TechniqueFilename, Confidence: ConfidenceLow, Value: name},
					},
				},
			},
		},
	}
	if path != "" {
		c.Evidence.Occurrences = []SBOMOccurrence{{Location: path}}
	}
	return c
}

// NewNativeLibComponent builds a "library" component for an Android native
// library (e.g. libflutter.so) that may be shipped for multiple ABIs.
//
// Evidence:
//   - name via filename at MEDIUM confidence (a versioned .so soname or a
//     recognizable native library name is stronger than a bare framework
//     folder name).
//   - when sha256 is provided, an additional hash identity backed by
//     hash-comparison at HIGH confidence, plus a SHA-256 hash entry proving
//     byte identity.
//
// One occurrence is recorded per ABI (e.g. lib/arm64-v8a/<name>,
// lib/armeabi-v7a/<name>), so the same logical component reports every place
// it physically appears.
func NewNativeLibComponent(name string, abis []string, sha256 string) SBOMComponent {
	c := SBOMComponent{
		Type:   "library",
		Name:   name,
		BomRef: "native:" + name,
		Purl:   genericPurl(name, ""),
	}

	c.Evidence.Identity = []SBOMIdentity{
		{
			Field:          "name",
			Confidence:     ConfidenceMedium,
			ConcludedValue: name,
			Methods: []SBOMMethod{
				{Technique: TechniqueFilename, Confidence: ConfidenceMedium, Value: name},
			},
		},
	}

	if sha256 != "" {
		c.Hashes = []SBOMHash{{Alg: "SHA-256", Content: sha256}}
		c.Evidence.Identity = append(c.Evidence.Identity, SBOMIdentity{
			Field:          "hash",
			Confidence:     ConfidenceHigh,
			ConcludedValue: sha256,
			Methods: []SBOMMethod{
				{Technique: TechniqueHashComparison, Confidence: ConfidenceHigh, Value: sha256},
			},
		})
	}

	for _, abi := range abis {
		if abi == "" {
			continue
		}
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, SBOMOccurrence{
			Location: fmt.Sprintf("lib/%s/%s", abi, name),
		})
	}
	return c
}

// NewRuntimeComponent builds a "framework" component for a detected runtime
// (e.g. Flutter, React Native). Identity is name-only via binary-analysis at
// MEDIUM confidence — the runtime is inferred from binary signatures rather
// than a declared manifest entry. Every path that evidenced the runtime is
// recorded as an occurrence.
func NewRuntimeComponent(name string, evidencePaths []string) SBOMComponent {
	c := SBOMComponent{
		Type:   "framework",
		Name:   name,
		BomRef: "runtime:" + name,
		Purl:   genericPurl(name, ""),
		Evidence: SBOMEvidence{
			Identity: []SBOMIdentity{
				{
					Field: "name",
					// Runtime detection is inference from the PRESENCE of marker
					// files (libflutter.so, libhermes.so, …) — no bytes are
					// analyzed — so the technique is filename at LOW confidence,
					// not binary-analysis.
					Confidence:     ConfidenceLow,
					ConcludedValue: name,
					Methods: []SBOMMethod{
						{Technique: TechniqueFilename, Confidence: ConfidenceLow, Value: name},
					},
				},
			},
		},
	}
	for _, p := range evidencePaths {
		if p == "" {
			continue
		}
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, SBOMOccurrence{Location: p})
	}
	return c
}

// Firebase source hints for NewFirebaseComponent. Callers pass the platform
// they detected Firebase on so the constructor can emit the correct ecosystem
// purl (Firebase ships as a Maven BOM on Android and an umbrella CocoaPod on
// iOS).
const (
	// FirebaseSourceAndroid selects the Firebase Android BOM (pkg:maven) purl.
	FirebaseSourceAndroid = "android"
	// FirebaseSourceIOS selects the Firebase umbrella CocoaPod (pkg:cocoapods) purl.
	FirebaseSourceIOS = "ios"
)

// NewFirebaseComponent builds a "library" component for a detected Firebase
// integration.
//
// Firebase is special-cased (rather than emitted as N separate framework/native
// components) because on-device it presents as a Google-services config
// (GoogleService-Info.plist on iOS, google-services.json on Android) that names
// a projectID and enables a set of SDKs, plus the individual Firebase product
// frameworks/libs. This constructor produces ONE umbrella component that records
// the projectID and the detected SDK set, so the SBOM has a single, coherent
// Firebase entry.
//
// Purl:
//   - source == FirebaseSourceAndroid -> pkg:maven/com.google.firebase/firebase-bom
//     (the Android BOM, MORF's canonical Firebase-Android coordinate), Group set
//     to the com.google.firebase groupId.
//   - otherwise (iOS / unknown) -> pkg:cocoapods/Firebase (the umbrella pod).
//
// No version is invented — a Firebase config declares a projectID and SDKs, not
// a resolved SDK version. The projectID is recorded as the purl identity's
// concludedValue and the detected SDK set is folded into the Group so it is not
// lost. Evidence is a single manifest-analysis purl identity at MEDIUM
// confidence (we parsed a structured Google-services manifest), with one
// occurrence at evidencePath.
func NewFirebaseComponent(projectID string, sdks []string, source, evidencePath string) SBOMComponent {
	name := "Firebase"
	if projectID != "" {
		name = fmt.Sprintf("Firebase (%s)", projectID)
	}

	c := SBOMComponent{
		Type:   "library",
		Name:   name,
		BomRef: "firebase:" + firebaseRef(projectID),
	}

	if source == FirebaseSourceAndroid {
		c.Purl = FirebaseMavenBOMPurl
		c.Group = "com.google.firebase"
	} else {
		c.Purl = FirebaseCocoaPodsPurl
	}

	// Record the detected SDK set without fabricating a version. When there is
	// no Maven groupId occupying Group, we surface the SDK list there so the
	// signal survives into the SBOM; the concludedValue carries the projectID.
	if len(sdks) > 0 && c.Group == "" {
		c.Group = "sdks: " + strings.Join(sdks, ", ")
	}

	concluded := c.Purl
	if projectID != "" {
		concluded = fmt.Sprintf("%s (projectID=%s)", c.Purl, projectID)
	}
	c.Evidence.Identity = []SBOMIdentity{
		{
			Field:          "purl",
			Confidence:     ConfidenceMedium,
			ConcludedValue: concluded,
			Methods: []SBOMMethod{
				{Technique: TechniqueManifestAnalysis, Confidence: ConfidenceMedium, Value: c.Purl},
			},
		},
	}
	if evidencePath != "" {
		c.Evidence.Occurrences = []SBOMOccurrence{{Location: evidencePath}}
	}
	return c
}

// firebaseRef derives a stable bom-ref suffix for a Firebase component: the
// projectID when present, else the literal "Firebase".
func firebaseRef(projectID string) string {
	if projectID != "" {
		return projectID
	}
	return "Firebase"
}

// NewImportedLibraryComponent builds a "library" component for a third-party
// Mach-O dynamic-library import (an LC_LOAD_DYLIB entry pointing at a bundled
// framework/dylib) observed at path.
//
// This is the WEAKEST identity source MORF emits: a load command names a
// library but carries no version and no bytes we hashed, so identity is
// name-only via binary-analysis at LOW confidence. When the import name maps to
// a curated coordinate we still upgrade the purl (PurlFor with no bundleID —
// name-only matching), and set Group for a Maven coordinate; otherwise the
// component keeps the honest pkg:generic fallback.
func NewImportedLibraryComponent(name, path string) SBOMComponent {
	c := SBOMComponent{
		Type:   "library",
		Name:   name,
		BomRef: "import:" + name,
		Purl:   genericPurl(name, ""),
		Evidence: SBOMEvidence{
			Identity: []SBOMIdentity{
				{
					Field:          "name",
					Confidence:     ConfidenceLow,
					ConcludedValue: name,
					Methods: []SBOMMethod{
						{Technique: TechniqueBinaryAnalysis, Confidence: ConfidenceLow, Value: name},
					},
				},
			},
		},
	}
	if purl, group, matched := PurlFor(name, "", ""); matched {
		c.Purl = purl
		if group != "" {
			c.Group = group
		}
	}
	if path != "" {
		c.Evidence.Occurrences = []SBOMOccurrence{{Location: path}}
	}
	return c
}
