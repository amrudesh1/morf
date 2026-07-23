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

// Package apk — opportunistic lockfile-based SBOM enrichment for Android artifacts.
//
// IMPORTANT: Release APK artifacts (the output of `gradle assemble…`) almost
// never contain lockfiles — build tooling consumes pubspec.lock / package-lock.json
// at compile time and does NOT bundle them into the final .apk. These parsers are
// therefore OPPORTUNISTIC: they enrich the SBOM when MORF is pointed at a
// source/build tree (e.g. a CI workspace that still has the lockfile next to the
// compiled output), and are silently skipped when the lockfile is absent. This is
// the correct behaviour: failing or warning when a lockfile is missing would be
// noisy for the common case (a release artifact).
package apk

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
// Each parser accepts raw file bytes so it can be unit-tested without touching
// the filesystem. All parsers are best-effort: malformed input is silently
// skipped at the entry level so a corrupt lockfile never fails a scan.

// ParsePubspecLock parses a Flutter pubspec.lock YAML file and returns a map
// of package name → resolved version.
//
// pubspec.lock format (YAML):
//
//	packages:
//	  http:
//	    version: "1.2.3"
//	  flutter:
//	    version: "0.0.0"
//
// We deliberately avoid pulling in a full YAML library and instead parse with
// a simple line-scanner: the format is stable and machine-generated, so the
// structure is consistent enough for a targeted scanner. This keeps the parser
// dependency-free and trivially auditable.
func ParsePubspecLock(data []byte) map[string]string {
	out := make(map[string]string)

	// State machine: track the current top-level key and whether we are inside
	// the "packages:" block.
	inPackages := false
	var currentPkg string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		// Detect the top-level "packages:" key (no leading whitespace, ends with ":").
		if line == "packages:" {
			inPackages = true
			currentPkg = ""
			continue
		}
		// Any other non-indented key ends the packages block.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			inPackages = false
			currentPkg = ""
			continue
		}

		if !inPackages {
			continue
		}

		// A two-space-indented word followed by ":" is a package name.
		// e.g. "  http:" or "  flutter_local_notifications:"
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, ":") {
				currentPkg = strings.TrimSuffix(trimmed, ":")
			}
			continue
		}

		// A deeper-indented "version: ..." line carries the resolved version.
		if currentPkg != "" && strings.Contains(line, "version:") {
			// Strip leading whitespace, the "version:" key, and surrounding quotes.
			rest := strings.TrimSpace(line)
			rest = strings.TrimPrefix(rest, "version:")
			rest = strings.TrimSpace(rest)
			rest = strings.Trim(rest, `"'`)
			if rest != "" {
				out[currentPkg] = rest
			}
		}
	}
	return out
}

// ParsePackageLockJSON parses an npm package-lock.json (v2 or v3 format) and
// returns a map of package name → resolved version.
//
// npm v2/v3 package-lock.json uses a flat "packages" object whose keys are
// node_modules/<name> (or node_modules/<scope>/<name> for scoped packages).
// Each entry has a "version" field. The root package "" (no name) is skipped.
//
// We only parse the top-level "packages" map. The older v1 "dependencies" map
// is NOT parsed — v1 package-locks are rare in modern React Native projects and
// the nested format would require full recursive traversal. Projects still on v1
// will simply produce no lockfile enrichment (the best-effort contract).
func ParsePackageLockJSON(data []byte) map[string]string {
	out := make(map[string]string)

	// We parse only the "packages" key to keep memory bounded and avoid
	// deserializing the full (potentially multi-MB) lockfile into a nested map.
	// Use json.RawMessage to extract just the packages object.
	var root struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return out
	}

	for key, entry := range root.Packages {
		if key == "" || entry.Version == "" {
			continue
		}
		// Strip the leading "node_modules/" prefix to get the plain package name.
		// Scoped packages: "node_modules/@scope/pkg" → "@scope/pkg".
		name := strings.TrimPrefix(key, "node_modules/")
		// Remove any nested path — "node_modules/a/node_modules/b" → "b" (the
		// hoisted entry for that dependency); we keep only the top-level hoisting
		// by checking for a second "node_modules/" segment.
		if idx := strings.Index(name, "/node_modules/"); idx >= 0 {
			name = name[idx+len("/node_modules/"):]
		}
		if name != "" {
			out[name] = entry.Version
		}
	}
	return out
}

// yarnEntryRe matches a yarn.lock entry header of the form:
//
//	"package@version", "package@^version":
//	package@version:
//	"@scope/package@version":
//
// The first capture group is the unquoted package name (possibly scoped).
var yarnEntryRe = regexp.MustCompile(`^"?(@?[^@"]+)@`)

// ParseYarnLock parses a yarn.lock (v1 "classic" format) and returns a map of
// package name → resolved version. This is a best-effort parser: the yarn.lock
// format is not formally specified and has changed across yarn versions, so we
// parse on a best-effort basis and silently skip entries that do not match.
//
// yarn.lock v1 format (excerpt):
//
//	"react@^18.0.0":
//	  version "18.2.0"
//	  resolved "…"
//
// Yarn Berry (v2/v3/v4) uses a different YAML-like syntax; we detect it by
// the "__metadata:" sentinel and skip it entirely rather than emit wrong data.
func ParseYarnLock(data []byte) map[string]string {
	out := make(map[string]string)

	lines := bufio.NewScanner(bytes.NewReader(data))
	var currentPkg string
	for lines.Scan() {
		line := lines.Text()

		// Detect yarn berry — skip entirely rather than misparse.
		if strings.TrimSpace(line) == "__metadata:" {
			return out
		}

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			currentPkg = ""
			continue
		}

		// An entry header is a non-indented line ending with ":" that names a
		// package. Multiple comma-separated specifiers may share one block:
		//   "react@^18.0.0", "react@^18.2.0":
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// Extract the canonical package name from the first specifier.
			// Strip surrounding quotes.
			first := strings.Split(line, ",")[0]
			first = strings.TrimSpace(first)
			first = strings.Trim(first, `"`)
			m := yarnEntryRe.FindStringSubmatch(first)
			if m != nil {
				currentPkg = m[1]
			} else {
				currentPkg = ""
			}
			continue
		}

		// The "  version" line inside a block carries the resolved version.
		if currentPkg != "" && strings.HasPrefix(line, "  version") {
			// Formats: `  version "1.2.3"` or `  version: 1.2.3`
			rest := strings.TrimPrefix(strings.TrimSpace(line), "version")
			rest = strings.TrimSpace(rest)
			rest = strings.TrimPrefix(rest, ":")
			rest = strings.TrimSpace(rest)
			rest = strings.Trim(rest, `"`)
			if rest != "" {
				// Only record the first resolved version for a given package name; later
				// duplicate entries (different version specifiers for the same package)
				// may resolve to a different version, but the first is the canonical one
				// npm/yarn selects for the top-level requirement.
				if _, already := out[currentPkg]; !already {
					out[currentPkg] = rest
				}
			}
		}
	}
	return out
}

// ---- Lockfile candidate paths -----------------------------------------------

// lockfileCandidates returns the candidate paths, in priority order, where each
// supported lockfile might appear under the extracted job tree. The list covers:
//   - the apktool source tree root (rare but possible when MORF is pointed at a
//     build workspace that has the lockfile alongside the decompiled output);
//   - the job workspace root (the directory above the apktool output, where the
//     original APK was placed before decompilation);
//   - the workspace parent (one level up, in case MORF is run from the project
//     root and the job workspace is a subdirectory).
//
// All paths are absolute. callers stat each path and use the first one found.
func lockfileCandidates(jobCtx *utils.JobContext, filename string) []string {
	src := jobCtx.GetSourceDir()
	ws := jobCtx.Workspace
	return []string{
		filepath.Join(src, filename),
		filepath.Join(ws, filename),
		filepath.Join(filepath.Dir(ws), filename),
	}
}

// readFirstExisting tries each candidate path in order and returns (data, path)
// for the first path that can be read. Returns (nil, "") when none exist.
func readFirstExisting(candidates []string) ([]byte, string) {
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			return data, p
		}
	}
	return nil, ""
}

// ---- Enrichment integration -------------------------------------------------

// newLockfileComponent builds a "library" SBOM component for a package that
// was discovered exclusively via lockfile manifest analysis (i.e. it was NOT
// already detected as a native lib or runtime marker). Evidence is
// manifest-analysis at MEDIUM confidence — a lockfile is a structured,
// machine-generated manifest, so it is a strong identity signal even though it
// is not a binary artifact we hashed.
func newLockfileComponent(name, version, lockfilePath string) models.SBOMComponent {
	c := models.SBOMComponent{
		Type:    "library",
		Name:    name,
		Version: version,
		BomRef:  "lockfile:" + name,
		Purl:    lockfilePurl(name, version),
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

	// Attempt a curated purl upgrade via PurlFor (name-only match, no bundleID).
	if purl, group, matched := models.PurlFor(name, "", version); matched {
		c.Purl = purl
		if group != "" {
			c.Group = group
		}
		identities = append(identities, models.SBOMIdentity{
			Field:          "purl",
			Confidence:     models.ConfidenceMedium,
			ConcludedValue: purl,
			Methods: []models.SBOMMethod{
				{Technique: models.TechniqueManifestAnalysis, Confidence: models.ConfidenceMedium, Value: purl},
			},
		})
	}

	c.Evidence.Identity = identities
	if lockfilePath != "" {
		c.Evidence.Occurrences = []models.SBOMOccurrence{{Location: lockfilePath}}
	}
	return c
}

// lockfilePurl returns a purl for a lockfile-sourced package. For npm/yarn
// packages (React Native) we emit pkg:npm; for Dart/Flutter packages we emit
// pkg:pub. Both ecosystems have well-defined purl specs. When the ecosystem
// cannot be inferred (e.g. the function is called from a generic context) we
// fall back to pkg:generic.
//
// NOTE: This function is called from the APK-side enrichment (pubspec.lock is
// Flutter/Dart → pkg:pub; package-lock.json / yarn.lock is npm → pkg:npm).
// The caller passes the resolved version (may be empty).
func lockfilePurl(name, version string) string {
	// Callers of newLockfileComponent from the APK side are either npm (React
	// Native) or pub (Flutter). We cannot infer which from name alone without
	// context, so we defer to pkg:generic here. The upgrade to pkg:npm/pkg:pub
	// happens in the ecosystem-specific enrichment helpers below, which know which
	// lockfile they parsed.
	if version != "" {
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:generic/%s", name)
}

// upgradePurl replaces a component's purl with the given ecosystem purl and
// adds a manifest-analysis purl identity backed by that purl. This is called
// after parsing a lockfile that provides a more precise ecosystem coordinate
// than the initial pkg:generic fallback.
func upgradePurl(c *models.SBOMComponent, purl, lockfilePath string) {
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

// EnrichFromAndroidLockfiles scans the extracted job tree for supported
// Android/cross-platform lockfiles and enriches the given SBOM component list:
//
//   - pubspec.lock (Flutter): resolves Dart/pub package versions. Matched
//     components get their Version set and purl upgraded to pkg:pub/<name>@<ver>.
//     New components are added for packages not otherwise detected.
//
//   - package-lock.json (npm v2/v3): resolves npm package versions for React
//     Native projects. Matched components get Version + pkg:npm upgrade.
//
//   - yarn.lock (yarn v1 classic): same as package-lock.json but from yarn.
//     When both package-lock.json and yarn.lock are present, package-lock.json
//     takes precedence (it carries authoritative resolved hashes).
//
// HONEST NOTE: A compiled release APK almost never ships these lockfiles — they
// are consumed at build time and stripped from the final artifact. This
// enrichment is primarily useful when MORF is pointed at a source/build tree
// (e.g. a CI workspace) where the lockfile sits alongside the compiled output.
// When no lockfile is found this function returns the input slice unchanged.
//
// This is the function the OSV vulnerability scan unit (P4b) should call to
// obtain the enriched []models.SBOMComponent before querying OSV for CVEs.
func EnrichFromAndroidLockfiles(jobCtx *utils.JobContext, components []models.SBOMComponent) []models.SBOMComponent {
	// Build a name-indexed mutable working copy so we can update components
	// in place and append new ones efficiently.
	byName := make(map[string]*models.SBOMComponent, len(components))
	order := make([]string, 0, len(components)) // preserve original ordering
	for i := range components {
		c := &components[i]
		if _, seen := byName[c.Name]; !seen {
			byName[c.Name] = c
			order = append(order, c.Name)
		}
	}

	// --- pubspec.lock (Flutter / Dart / pub) ---
	if pubData, pubPath := readFirstExisting(lockfileCandidates(jobCtx, "pubspec.lock")); pubData != nil {
		versions := ParsePubspecLock(pubData)
		if len(versions) > 0 {
			log.WithFields(log.Fields{
				"job_id":   jobCtx.JobID,
				"lockfile": pubPath,
				"packages": len(versions),
			}).Debug("Enriching SBOM from pubspec.lock")
		}
		for name, ver := range versions {
			purl := fmt.Sprintf("pkg:pub/%s@%s", name, ver)
			if c, ok := byName[name]; ok {
				// Upgrade existing component: set version if unset, upgrade purl.
				if c.Version == "" {
					c.Version = ver
				}
				upgradePurl(c, purl, pubPath)
			} else {
				// New component from lockfile only (not otherwise detected).
				nc := newLockfileComponent(name, ver, pubPath)
				nc.Purl = purl
				nc.BomRef = "pub:" + name
				byName[name] = &nc
				order = append(order, name)
			}
		}
	}

	// --- package-lock.json (npm / React Native) ---
	//
	// package-lock.json takes precedence over yarn.lock when both are present:
	// npm's lockfile carries SHA-512 integrity hashes that pin exact byte
	// identity, making it the more authoritative source for resolved versions.
	npmHandled := false
	if pkgData, pkgPath := readFirstExisting(lockfileCandidates(jobCtx, "package-lock.json")); pkgData != nil {
		versions := ParsePackageLockJSON(pkgData)
		if len(versions) > 0 {
			log.WithFields(log.Fields{
				"job_id":   jobCtx.JobID,
				"lockfile": pkgPath,
				"packages": len(versions),
			}).Debug("Enriching SBOM from package-lock.json")
			npmHandled = true
		}
		applyNPMVersions(versions, pkgPath, byName, &order)
	}

	// --- yarn.lock (yarn v1, React Native fallback) ---
	if !npmHandled {
		if yarnData, yarnPath := readFirstExisting(lockfileCandidates(jobCtx, "yarn.lock")); yarnData != nil {
			versions := ParseYarnLock(yarnData)
			if len(versions) > 0 {
				log.WithFields(log.Fields{
					"job_id":   jobCtx.JobID,
					"lockfile": yarnPath,
					"packages": len(versions),
				}).Debug("Enriching SBOM from yarn.lock")
			}
			applyNPMVersions(versions, yarnPath, byName, &order)
		}
	}

	// Reconstruct the slice in original + new-appended order.
	out := make([]models.SBOMComponent, 0, len(order))
	for _, name := range order {
		if c, ok := byName[name]; ok {
			out = append(out, *c)
		}
	}
	return out
}

// applyNPMVersions applies a name→version map (from package-lock.json or
// yarn.lock) to the working component index. Existing components get their
// Version upgraded and a pkg:npm purl added; new packages produce a fresh
// lockfile component with a pkg:npm purl.
func applyNPMVersions(versions map[string]string, lockfilePath string, byName map[string]*models.SBOMComponent, order *[]string) {
	for name, ver := range versions {
		purl := fmt.Sprintf("pkg:npm/%s@%s", name, ver)
		if c, ok := byName[name]; ok {
			if c.Version == "" {
				c.Version = ver
			}
			upgradePurl(c, purl, lockfilePath)
		} else {
			nc := newLockfileComponent(name, ver, lockfilePath)
			nc.Purl = purl
			nc.BomRef = "npm:" + name
			byName[name] = &nc
			*order = append(*order, name)
		}
	}
}
