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

// Package ios — opportunistic lockfile-based SBOM enrichment for iOS artifacts.
//
// IMPORTANT: A compiled release IPA almost never contains lockfiles (Podfile.lock,
// Package.resolved). CocoaPods resolves Podfile.lock at `pod install` time; SPM
// resolves Package.resolved at build time. Neither file is bundled into the final
// Payload/*.app. These parsers are therefore OPPORTUNISTIC: they enrich the SBOM
// when MORF is pointed at a source/build tree (e.g. a Xcode project directory
// checked into CI) and are silently skipped when the lockfile is absent. This is
// the correct behaviour: a missing lockfile in a release IPA is expected, not an
// error.
package ios

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"morf/models"
	"morf/utils"

	log "github.com/sirupsen/logrus"
)

// ---- Pure parsers (bytes → map[name]version) --------------------------------

// ParsePodfileLock parses a CocoaPods Podfile.lock and returns a map of pod
// name → resolved version (including subspec pods like "Firebase/Core").
//
// Podfile.lock format (excerpt):
//
//	PODS:
//	  - Alamofire (5.6.4)
//	  - Firebase/Core (10.1.0):
//	    - Firebase/CoreOnly (= 10.1.0)
//	    - FirebaseCore (~> 10.3)
//	  - FirebaseCore (10.3.8):
//	    - FirebaseCoreInternal (~> 10.3.8)
//	    - GoogleUtilities/Environment (~> 7.8)
//
// Rules:
//   - Only the "PODS:" block is parsed; other blocks (DEPENDENCIES, SPEC REPOS,
//     SPEC CHECKSUMS, PODFILE CHECKSUM, COCOAPODS) are skipped.
//   - An entry at the two-space indent is a top-level pod declaration:
//     "  - PodName (version)" or "  - PodName/SubSpec (version):"
//   - Deeper-indented lines are sub-dependency declarations; we skip them because
//     they will appear as their own top-level entries when CocoaPods resolves the
//     full graph (or as a subspec of the parent pod).
//   - Subspecs ("Firebase/Core") are kept as distinct map entries because they
//     can carry distinct versions and are independently addressable purls.
func ParsePodfileLock(data []byte) map[string]string {
	out := make(map[string]string)

	inPods := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		// Section headers are non-indented lines followed by ":".
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inPods = strings.TrimSuffix(strings.TrimSpace(line), ":") == "PODS"
			continue
		}

		if !inPods {
			continue
		}

		// Top-level pod entries are indented with exactly two spaces and start with
		// "- ". Deeper indentation means a sub-dependency (skip).
		if !strings.HasPrefix(line, "  - ") {
			continue
		}

		rest := strings.TrimPrefix(line, "  - ")
		// Strip a trailing ":" that marks a pod with sub-dependencies.
		rest = strings.TrimSuffix(rest, ":")

		// rest is now: "PodName (version)" or "PodName/SubSpec (version)"
		// Parse the version from the parentheses.
		name, version, ok := parsePodEntry(rest)
		if ok {
			out[name] = version
		}
	}
	return out
}

// podEntryRe matches a Podfile.lock PODS: entry of the form:
//
//	PodName (version)
//	PodName/SubSpec (version)
//
// The first capture group is the pod name (including any subspec path), and the
// second capture group is the version string.
var podEntryRe = regexp.MustCompile(`^([A-Za-z0-9_./-]+)\s+\(([^)]+)\)$`)

// parsePodEntry extracts the pod name and version from a PODS: entry line that
// has already had the leading "  - " and optional trailing ":" removed. Returns
// (name, version, true) on success.
func parsePodEntry(rest string) (string, string, bool) {
	m := podEntryRe.FindStringSubmatch(strings.TrimSpace(rest))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// packageResolvedV1 is the JSON structure for a Package.resolved v1 file
// (Xcode 12 and earlier). Pins are nested under "object.pins".
type packageResolvedV1 struct {
	Object struct {
		Pins []struct {
			Package string `json:"package"`
			State   struct {
				Version string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	} `json:"object"`
}

// packageResolvedV2 is the JSON structure for a Package.resolved v2 file
// (Xcode 13+). Pins are a top-level "pins" array.
type packageResolvedV2 struct {
	Pins []struct {
		Identity string `json:"identity"`
		State    struct {
			Version string `json:"version"`
		} `json:"state"`
	} `json:"pins"`
}

// ParsePackageResolved parses a Swift Package Manager Package.resolved file
// (both v1 and v2 schema) and returns a map of package identity → resolved
// version. Only pinned-to-version entries are included (revision-only pins
// that have no "version" field are skipped, as they carry no semver version).
//
// Package.resolved v2 example:
//
//	{
//	  "originHash": "abc123",
//	  "pins": [
//	    {
//	      "identity": "alamofire",
//	      "kind": "remoteSourceControl",
//	      "location": "https://github.com/Alamofire/Alamofire.git",
//	      "state": { "revision": "…", "version": "5.8.1" }
//	    }
//	  ],
//	  "version": 2
//	}
//
// Package.resolved v1 example:
//
//	{
//	  "object": {
//	    "pins": [
//	      {
//	        "package": "Alamofire",
//	        "repositoryURL": "…",
//	        "state": { "branch": null, "revision": "…", "version": "5.6.4" }
//	      }
//	    ]
//	  },
//	  "version": 1
//	}
func ParsePackageResolved(data []byte) map[string]string {
	out := make(map[string]string)

	// Detect the schema version first.
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return out
	}

	switch probe.Version {
	case 1:
		var v1 packageResolvedV1
		if err := json.Unmarshal(data, &v1); err != nil {
			return out
		}
		for _, pin := range v1.Object.Pins {
			if pin.Package != "" && pin.State.Version != "" {
				out[pin.Package] = pin.State.Version
			}
		}

	case 2:
		var v2 packageResolvedV2
		if err := json.Unmarshal(data, &v2); err != nil {
			return out
		}
		for _, pin := range v2.Pins {
			if pin.Identity != "" && pin.State.Version != "" {
				out[pin.Identity] = pin.State.Version
			}
		}

	default:
		// Unknown schema version — try v2 first, then v1 as fallback.
		var v2 packageResolvedV2
		if err := json.Unmarshal(data, &v2); err == nil && len(v2.Pins) > 0 {
			for _, pin := range v2.Pins {
				if pin.Identity != "" && pin.State.Version != "" {
					out[pin.Identity] = pin.State.Version
				}
			}
		} else {
			var v1 packageResolvedV1
			if err := json.Unmarshal(data, &v1); err == nil {
				for _, pin := range v1.Object.Pins {
					if pin.Package != "" && pin.State.Version != "" {
						out[pin.Package] = pin.State.Version
					}
				}
			}
		}
	}
	return out
}

// ---- Lockfile candidate paths -----------------------------------------------

// iosLockfileCandidates returns, in priority order, the candidate paths where a
// lockfile might appear under an extracted iOS job tree. Unlike Android, an IPA
// has no standard source-code root — the app bundle (Payload/*.app) does not
// ship source files. We search:
//
//  1. The job workspace root (when MORF is run from a project directory or a
//     CI workspace that has the lockfile alongside the IPA).
//  2. The parent of the workspace root (one level up in case the workspace is a
//     subdirectory of the project root).
//  3. The iOS output directory (unlikely, but covers unpack tools that mirror
//     source structure).
func iosLockfileCandidates(jobCtx *utils.JobContext, filename string) []string {
	ws := jobCtx.Workspace
	return []string{
		filepath.Join(ws, filename),
		filepath.Join(filepath.Dir(ws), filename),
		filepath.Join(jobCtx.GetIOSDir(), filename),
	}
}

// readFirstExistingIOS is the iOS analogue of the APK readFirstExisting helper.
// It tries each candidate path and returns (data, path) for the first readable
// file, or (nil, "") when none exist.
func readFirstExistingIOS(candidates []string) ([]byte, string) {
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			return data, p
		}
	}
	return nil, ""
}

// ---- SBOM construction helpers ----------------------------------------------

// newIOSLockfileComponent builds a "library" SBOM component for a package
// discovered exclusively via iOS lockfile manifest analysis. Evidence is
// manifest-analysis at MEDIUM confidence (a lockfile is a structured,
// machine-generated manifest).
func newIOSLockfileComponent(name, version, lockfilePath string) models.SBOMComponent {
	c := models.SBOMComponent{
		Type:    "library",
		Name:    name,
		Version: version,
		BomRef:  "lockfile:" + name,
		Purl:    fmt.Sprintf("pkg:generic/%s@%s", name, version),
	}
	if version == "" {
		c.Purl = fmt.Sprintf("pkg:generic/%s", name)
		c.BomRef = "lockfile:" + name
	}

	identities := []models.SBOMIdentity{
		{
			Field:          "name",
			Confidence:     models.ConfidenceMedium,
			ConcludedValue: name,
			Methods: []models.SBOMMethod{
				{Technique: models.TechniqueManifestAnalysis, Confidence: models.ConfidenceMedium, Value: lockfilePath},
			},
		},
	}
	if version != "" {
		identities = append(identities, models.SBOMIdentity{
			Field:          "version",
			Confidence:     models.ConfidenceMedium,
			ConcludedValue: version,
			Methods: []models.SBOMMethod{
				{Technique: models.TechniqueManifestAnalysis, Confidence: models.ConfidenceMedium, Value: fmt.Sprintf("%s@%s (lockfile)", name, version)},
			},
		})
	}
	c.Evidence.Identity = identities
	if lockfilePath != "" {
		c.Evidence.Occurrences = []models.SBOMOccurrence{{Location: lockfilePath}}
	}
	return c
}

// upgradeIOSPurl replaces a component's purl with a more precise coordinate and
// appends a manifest-analysis purl identity backed by it.
func upgradeIOSPurl(c *models.SBOMComponent, purl, lockfilePath string) {
	c.Purl = purl
	c.Evidence.Identity = append(c.Evidence.Identity, models.SBOMIdentity{
		Field:          "purl",
		Confidence:     models.ConfidenceMedium,
		ConcludedValue: purl,
		Methods: []models.SBOMMethod{
			{Technique: models.TechniqueManifestAnalysis, Confidence: models.ConfidenceMedium, Value: lockfilePath},
		},
	})
}

// ---- Enrichment integration -------------------------------------------------

// EnrichFromIOSLockfiles scans the extracted job tree for supported iOS
// lockfiles and enriches the given SBOM component list:
//
//   - Podfile.lock (CocoaPods): resolves pod versions. Matched components get
//     their Version set and purl upgraded to pkg:cocoapods/<pod>@<ver>. New
//     components are added for pods not otherwise detected. Subspecs
//     ("Firebase/Core") are kept as distinct entries.
//
//   - Package.resolved (Swift Package Manager, v1 and v2): resolves SPM package
//     versions. Matched components get Version + pkg:swift upgrade. The identity
//     key in v2 is the lowercase package identity (e.g. "alamofire"); the
//     Package name in v1 may be mixed-case. Matching is case-insensitive.
//
// HONEST NOTE: A compiled release IPA almost never ships these lockfiles — they
// are consumed at build time and not bundled into the final Payload/*.app. This
// enrichment is primarily useful when MORF is pointed at a source/build tree
// (e.g. a Xcode project or CI workspace) where the lockfile sits alongside the
// IPA. When no lockfile is found this function returns the input slice unchanged.
//
// This is the function the OSV vulnerability scan unit (P4b) should call after
// BuildSBOMComponents to obtain the enriched []models.SBOMComponent before
// querying OSV for CVEs:
//
//	sbom := ios.BuildSBOMComponents(jobID, up, fws)
//	sbom = ios.EnrichFromIOSLockfiles(jobCtx, sbom)
func EnrichFromIOSLockfiles(jobCtx *utils.JobContext, components []models.SBOMComponent) []models.SBOMComponent {
	// Build a name-indexed mutable working copy (case-insensitive matching to
	// handle Package.resolved v2 lowercased identities vs mixed-case framework
	// names like "Alamofire" vs "alamofire").
	byName := make(map[string]*models.SBOMComponent, len(components)) // lowercase key
	byOrig := make(map[string]*models.SBOMComponent, len(components)) // original-case key
	order := make([]string, 0, len(components))
	for i := range components {
		c := &components[i]
		key := strings.ToLower(c.Name)
		if _, seen := byName[key]; !seen {
			byName[key] = c
			byOrig[c.Name] = c
			order = append(order, c.Name)
		}
	}

	// Lookup helper: find a component by name (case-insensitive).
	lookup := func(name string) (*models.SBOMComponent, bool) {
		if c, ok := byOrig[name]; ok {
			return c, true
		}
		c, ok := byName[strings.ToLower(name)]
		return c, ok
	}

	// --- Podfile.lock (CocoaPods) ---
	if podData, podPath := readFirstExistingIOS(iosLockfileCandidates(jobCtx, "Podfile.lock")); podData != nil {
		versions := ParsePodfileLock(podData)
		if len(versions) > 0 {
			log.WithFields(log.Fields{
				"job_id":   jobCtx.JobID,
				"lockfile": podPath,
				"pods":     len(versions),
			}).Debug("Enriching SBOM from Podfile.lock")
		}
		for name, ver := range versions {
			// Derive the purl name: for a subspec "Firebase/Core" the pod name is
			// the full subspec string but the CocoaPods purl uses the root pod name
			// ("Firebase"). For non-subspec pods the purl name equals the pod name.
			purlName := podPurlName(name)
			purl := fmt.Sprintf("pkg:cocoapods/%s@%s", purlName, ver)

			if c, ok := lookup(name); ok {
				if c.Version == "" {
					c.Version = ver
				}
				upgradeIOSPurl(c, purl, podPath)
			} else {
				nc := newIOSLockfileComponent(name, ver, podPath)
				nc.Purl = purl
				nc.BomRef = "pod:" + name
				key := strings.ToLower(name)
				byName[key] = &nc
				byOrig[name] = &nc
				order = append(order, name)
			}
		}
	}

	// --- Package.resolved (Swift Package Manager) ---
	if spmData, spmPath := readFirstExistingIOS(iosLockfileCandidates(jobCtx, "Package.resolved")); spmData != nil {
		versions := ParsePackageResolved(spmData)
		if len(versions) > 0 {
			log.WithFields(log.Fields{
				"job_id":   jobCtx.JobID,
				"lockfile": spmPath,
				"packages": len(versions),
			}).Debug("Enriching SBOM from Package.resolved")
		}
		for name, ver := range versions {
			// PurlFor does a name-only lookup in the curated table; the SPM identity
			// may be lowercase ("alamofire") but the table uses mixed-case. We try
			// the direct name first, then a title-cased variant.
			purl, _, matched := models.PurlFor(name, "", ver)
			if !matched {
				titled := titleCase(name)
				if p, _, ok := models.PurlFor(titled, "", ver); ok {
					purl = p
					matched = true
				}
			}
			if !matched {
				// Fall back to pkg:swift with a generic host placeholder — we don't
				// know the SPM repo URL from the identity alone.
				purl = fmt.Sprintf("pkg:swift/unknown/%s@%s", name, ver)
			}

			if c, ok := lookup(name); ok {
				if c.Version == "" {
					c.Version = ver
				}
				upgradeIOSPurl(c, purl, spmPath)
			} else {
				nc := newIOSLockfileComponent(name, ver, spmPath)
				nc.Purl = purl
				nc.BomRef = "spm:" + name
				key := strings.ToLower(name)
				byName[key] = &nc
				byOrig[name] = &nc
				order = append(order, name)
			}
		}
	}

	// Reconstruct the slice in original + new-appended order.
	out := make([]models.SBOMComponent, 0, len(order))
	for _, name := range order {
		if c, ok := byOrig[name]; ok {
			out = append(out, *c)
		} else if c, ok := byName[strings.ToLower(name)]; ok {
			out = append(out, *c)
		}
	}
	return out
}

// podPurlName returns the root pod name for a CocoaPods purl. A subspec like
// "Firebase/Core" maps to the root pod "Firebase" in the purl because the
// purl-spec CocoaPods definition uses the pod name (not the subspec path).
func podPurlName(name string) string {
	if idx := strings.IndexByte(name, '/'); idx >= 0 {
		return name[:idx]
	}
	return name
}

// titleCase capitalises the first letter of s and lowercases the rest, a
// simple approximation of Go's strings.Title without the unicode overhead. Used
// to attempt a curated-purl lookup for SPM identities that are all-lowercase
// (e.g. "alamofire" → "Alamofire").
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
