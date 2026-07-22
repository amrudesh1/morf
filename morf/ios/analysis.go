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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"morf/detect"
	"morf/models"
	"morf/utils"

	log "github.com/sirupsen/logrus"
)

// corpusFileName is the name of the strings corpus written under the corpus
// directory. It is the only file the detect.ScanCorpus pass reads for an iOS
// job (the corpus dir contains just this file, so ripgrep scans exactly it).
const corpusFileName = "ios_strings.corpus"

// StartIOSExtraction is the top-level iOS pipeline entry point. It orchestrates:
//
//  1. unpack  — safety-gate + unzip the .ipa and locate Payload/*.app, the main
//     binary (by CFBundleExecutable name), embedded frameworks/dylibs/appex and
//     embedded.mobileprovision.
//  2. macho   — extract literal strings from the main binary and every embedded
//     binary (handling FAT/universal and FairPlay cryptid), writing them with
//     {arch,section} provenance to a strings corpus.
//  3. plist   — parse Info.plist (+ embedded plists) into IOSMetadata and append
//     their string values to the corpus.
//  4. frameworks — enumerate embedded frameworks/dylibs + architectures and, if
//     present, best-effort entitlements from embedded.mobileprovision.
//  5. detect  — run the shared detect.ScanCorpus over the corpus dir and
//     detect.SanitizeSecrets over the result.
//
// It returns the sanitized secrets, the assembled IOSMetadata, and an error.
// Only genuinely fatal problems (unusable .ipa, unwritable corpus, scan
// failure) produce an error; per-binary / per-plist parse failures are logged
// and the scan continues.
// The 4th return value is the per-app SBOM component inventory (embedded
// frameworks + dylibs with evidence); the worker threads it into the scan
// result payload under the "sbomComponents" key that the CycloneDX exporter
// reads. It is nil on any error path.
func StartIOSExtraction(ctx context.Context, ipaPath string, jobCtx *utils.JobContext) ([]models.SecretModel, models.IOSMetadata, []models.SBOMComponent, error) {
	var meta models.IOSMetadata

	// 1. Unpack.
	up, err := StartUnpack(ipaPath, jobCtx)
	if err != nil {
		return nil, meta, nil, fmt.Errorf("ipa unpack failed: %w", err)
	}

	// Prepare an isolated corpus directory so ripgrep scans exactly our corpus
	// file and nothing else in the workspace.
	corpusDir := filepath.Join(jobCtx.GetIOSBinDir(), "corpus")
	if err := os.MkdirAll(corpusDir, 0o700); err != nil {
		return nil, meta, nil, fmt.Errorf("create corpus dir %q: %w", corpusDir, err)
	}
	corpusPath := filepath.Join(corpusDir, corpusFileName)
	// Truncate/create the corpus up front so appenders only ever append.
	if f, cErr := os.OpenFile(corpusPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); cErr == nil {
		f.Close()
	} else {
		return nil, meta, nil, fmt.Errorf("create corpus file %q: %w", corpusPath, cErr)
	}

	// 2. Mach-O strings for the main binary.
	var mainStrings *BinaryStrings
	if up.MainBinaryPath != "" {
		if bs, mErr := ExtractBinaryStrings(up.MainBinaryPath); mErr == nil {
			mainStrings = bs
			logBinaryStrings(jobCtx.JobID, bs)
			if wErr := AppendBinaryCorpus(corpusPath, bs); wErr != nil {
				log.WithFields(log.Fields{"job_id": jobCtx.JobID, "error": wErr.Error()}).Warn("Failed to append main binary corpus")
			}
		} else {
			log.WithFields(log.Fields{"job_id": jobCtx.JobID, "error": mErr.Error()}).Warn("Failed to extract main binary strings")
		}
	} else {
		log.WithFields(log.Fields{"job_id": jobCtx.JobID}).Warn("No main binary resolved; skipping main Mach-O string extraction")
	}

	// 3. Info.plist metadata + corpus.
	if up.InfoPlistPath != "" {
		if data, rErr := os.ReadFile(up.InfoPlistPath); rErr == nil {
			if pd, pErr := DecodeInfoPlistFull(data); pErr == nil {
				meta.BundleIdentifier = pd.BundleIdentifier
				meta.BundleVersion = pd.BundleVersion
				meta.DeploymentTarget = pd.MinimumOSVersion
				meta.ExecutableName = pd.ExecutableName
				meta.URLSchemes = marshalJSON(pd.URLSchemes)
				meta.ATSExceptions = marshalJSON(pd.ATSExceptions)
			} else {
				log.WithFields(log.Fields{"job_id": jobCtx.JobID, "error": pErr.Error()}).Warn("Failed to decode Info.plist metadata")
			}
		}
		if aErr := AppendPlistCorpus(corpusPath, up.InfoPlistPath); aErr != nil {
			log.WithFields(log.Fields{"job_id": jobCtx.JobID, "error": aErr.Error()}).Warn("Failed to append Info.plist corpus")
		}
	}

	// Append any additional embedded plists (e.g. bundled config .plist files)
	// discovered under the app bundle, so secrets in them are scanned too. The
	// Info.plist is skipped to avoid double-counting.
	for _, p := range collectFilesWithSuffix(up.AppBundlePath, ".plist") {
		if p == up.InfoPlistPath {
			continue
		}
		if aErr := AppendPlistCorpus(corpusPath, p); aErr != nil {
			log.WithFields(log.Fields{"job_id": jobCtx.JobID, "plist": p, "error": aErr.Error()}).Debug("Skipping unparseable embedded plist")
		}
	}

	// Append any embedded JSON config discovered under the app bundle (e.g.
	// Firebase's GoogleService-Info.json / google-services.json, or any bundled
	// *.json), so hardcoded keys in embedded JSON config are scanned too.
	// collectFilesWithSuffix recurses the whole bundle, so nested JSON inside
	// .appex / .framework / resource bundles is picked up for free.
	for _, p := range collectFilesWithSuffix(up.AppBundlePath, ".json") {
		if aErr := AppendJSONCorpus(corpusPath, p); aErr != nil {
			log.WithFields(log.Fields{"job_id": jobCtx.JobID, "json": p, "error": aErr.Error()}).Debug("Skipping unreadable embedded JSON")
		}
	}

	// 4. Frameworks / dylibs + architectures + entitlements.
	fws := EnumerateFrameworks(jobCtx.JobID, up)
	meta.Frameworks = marshalJSON(FrameworkNames(fws))

	// SBOM: build the evidence-bearing CycloneDX component inventory. It contains
	// one component per EMBEDDED framework/dylib, plus THIRD-PARTY Mach-O
	// LC_LOAD_DYLIB imports not already covered by an embedded component, plus a
	// single Firebase umbrella component when a GoogleService-Info.plist is
	// present. This is the value the worker places under the scan result payload
	// contract key "sbomComponents" (scanResultData.SBOMComponents). Apple OS
	// system frameworks (UIKit/Foundation/… reached via LC_LOAD_DYLIB imports)
	// are deliberately excluded by the import filter.
	sbom := BuildSBOMComponents(jobCtx.JobID, up, fws)

	// Extract strings from each embedded binary into the corpus as well.
	for _, fw := range fws {
		if fw.BinaryPath == "" {
			continue
		}
		if bs, eErr := ExtractBinaryStrings(fw.BinaryPath); eErr == nil {
			if wErr := AppendBinaryCorpus(corpusPath, bs); wErr != nil {
				log.WithFields(log.Fields{"job_id": jobCtx.JobID, "binary": fw.BinaryPath, "error": wErr.Error()}).Debug("Failed to append framework corpus")
			}
		}
	}

	// Aggregate architectures + encryption for metadata: prefer the main binary,
	// falling back to the union across frameworks if the main binary is absent.
	arches, encrypted := aggregateArch(mainStrings, fws)
	meta.Architectures = marshalJSON(arches)
	meta.IsEncrypted = encrypted

	// Best-effort entitlements from embedded.mobileprovision.
	if ent, entErr := ParseEntitlements(up.MobileProvisionPath); entErr == nil && len(ent) > 0 {
		meta.Entitlements = marshalJSON(ent)
		log.WithFields(log.Fields{"job_id": jobCtx.JobID, "entitlement_keys": EntitlementKeys(ent)}).Info("Parsed entitlements")
	}

	log.WithFields(log.Fields{
		"job_id":          jobCtx.JobID,
		"bundle_id":       meta.BundleIdentifier,
		"architectures":   arches,
		"encrypted":       encrypted,
		"frameworks":      summarizeFrameworks(fws),
		"sbom_components": len(sbom),
	}).Info("iOS metadata assembled")

	// 5. Scan the corpus dir with the shared detector, then sanitize.
	// PLATFORM-SCOPE: iOS scan → "ios"/"any" patterns run (Android-only rules excluded).
	rawSecrets, scanErr := detect.ScanCorpus(ctx, jobCtx.JobID, []string{corpusDir}, "ios")
	if scanErr != nil {
		return nil, meta, nil, fmt.Errorf("ios corpus scan failed: %w", scanErr)
	}
	secrets := detect.SanitizeSecrets(rawSecrets)

	return secrets, meta, sbom, nil
}

// aggregateArch derives the architecture list and encryption flag for the
// metadata row. It prefers the main binary's values; if the main binary is
// missing it unions the architectures observed across embedded frameworks and
// ORs their encryption flags.
func aggregateArch(main *BinaryStrings, fws []FrameworkInfo) ([]string, bool) {
	if main != nil && len(main.Architectures) > 0 {
		return main.Architectures, main.IsEncrypted
	}
	seen := map[string]bool{}
	var arches []string
	encrypted := false
	for _, fw := range fws {
		if fw.IsEncrypted {
			encrypted = true
		}
		for _, a := range fw.Architectures {
			if !seen[a] {
				seen[a] = true
				arches = append(arches, a)
			}
		}
	}
	return arches, encrypted
}

// BuildSBOMComponents assembles the evidence-bearing CycloneDX 1.6 component
// inventory for an unpacked app via the foundation constructors. It is the value
// the worker places under the scan result payload contract key "sbomComponents"
// (scanResultData.SBOMComponents). It layers three sources, in order:
//
//  1. EMBEDDED frameworks/dylibs (from fws):
//     - each *.framework bundle -> models.NewFrameworkComponent(name, version,
//     bundleID, path). The name is the bundle base name without ".framework"
//     (clean purl/bom-ref, e.g. "Alamofire"), version is
//     CFBundleShortVersionString from the framework's own Info.plist (empty ->
//     name-only filename evidence), bundleID is its CFBundleIdentifier (fed to
//     PurlFor for ecosystem-purl mapping), and path is the framework bundle
//     (its single occurrence).
//     - each *.dylib -> models.NewDylibComponent(name, path): name-only filename
//     evidence.
//
//  2. THIRD-PARTY Mach-O LC_LOAD_DYLIB imports (from the main binary + every
//     framework binary): OS/system and Swift-runtime imports are filtered out by
//     ExtractImportedDylibs; each surviving import whose base name is NOT already
//     covered by an embedded component (step 1) is emitted via
//     models.NewImportedLibraryComponent(name, "LC_LOAD_DYLIB:"+installName).
//     This is the weakest identity source (a load command names a library but
//     carries no version/bytes), deduped by name so a dependency embedded AND
//     linked is reported once (as the stronger embedded component).
//
//  3. FIREBASE: when a GoogleService-Info.plist exists in the app bundle it is
//     parsed (best-effort) and a single umbrella models.NewFirebaseComponent(
//     projectID, sdks, FirebaseSourceIOS, plistPath) is emitted.
//
// Every step is best-effort: a binary that will not parse or a Firebase plist
// that will not decode is logged and skipped, never fatal.
func BuildSBOMComponents(jobID string, up *UnpackedIPA, fws []FrameworkInfo) []models.SBOMComponent {
	var components []models.SBOMComponent

	// covered tracks the base names already represented by an embedded component
	// so a linked-AND-embedded dependency is not double-counted as a weaker
	// imported-library component.
	covered := map[string]bool{}

	// 1. Embedded frameworks / dylibs.
	for _, fw := range fws {
		if strings.HasSuffix(fw.Name, ".framework") {
			name := strings.TrimSuffix(fw.Name, ".framework")
			components = append(components,
				models.NewFrameworkComponent(name, fw.ShortVersion, fw.BundleID, fw.Path))
			covered[name] = true
			continue
		}
		if strings.HasSuffix(fw.Name, ".dylib") {
			components = append(components, models.NewDylibComponent(fw.Name, fw.Path))
			covered[fw.Name] = true
			continue
		}
		// Any other embedded artifact shape (should not occur given unpack only
		// collects *.framework bundles and *.dylib files) is treated as a dylib
		// so it is still surfaced with weak filename evidence rather than dropped.
		components = append(components, models.NewDylibComponent(fw.Name, fw.Path))
		covered[fw.Name] = true
	}

	if up == nil {
		return components
	}

	// 2. Third-party Mach-O imports, deduped against embedded components and
	// against each other (ExtractImportedDylibs already dedups within one binary;
	// importSeen dedups across binaries).
	components = append(components, importedLibraryComponents(jobID, up, covered)...)

	// 3. Firebase umbrella component from GoogleService-Info.plist.
	if fc := firebaseComponent(jobID, up.AppBundlePath); fc != nil {
		components = append(components, *fc)
	}

	return components
}

// importedLibraryComponents enumerates third-party LC_LOAD_DYLIB imports across
// the main binary and every framework binary, filters OS/system + Swift-runtime
// imports (done inside ExtractImportedDylibs), drops any import already covered
// by an embedded component, and returns one weak imported-library component per
// remaining unique import. It is best-effort per binary: a binary that will not
// parse is logged at Debug and skipped.
func importedLibraryComponents(jobID string, up *UnpackedIPA, covered map[string]bool) []models.SBOMComponent {
	var out []models.SBOMComponent
	importSeen := map[string]bool{}

	binaries := []string{up.MainBinaryPath}
	for _, fw := range up.Frameworks {
		base := strings.TrimSuffix(filepath.Base(fw), ".framework")
		if bin := filepath.Join(fw, base); fileExists(bin) {
			binaries = append(binaries, bin)
		}
	}

	for _, bin := range binaries {
		if bin == "" {
			continue
		}
		imports, err := ExtractImportedDylibs(bin)
		if err != nil {
			log.WithFields(log.Fields{"job_id": jobID, "binary": bin, "error": err.Error()}).
				Debug("Skipping unparseable binary for import enumeration")
			continue
		}
		for _, imp := range imports {
			if covered[imp.Name] || importSeen[imp.Name] {
				continue
			}
			importSeen[imp.Name] = true
			out = append(out, models.NewImportedLibraryComponent(imp.Name, "LC_LOAD_DYLIB:"+imp.InstallName))
		}
	}
	return out
}

// firebaseComponent looks for a GoogleService-Info.plist in the app bundle root,
// parses it best-effort, and returns a single Firebase umbrella component (iOS
// source). It returns nil when there is no bundle path, no config file, or the
// config cannot be decoded — Firebase detection NEVER fails the scan.
func firebaseComponent(jobID, appBundlePath string) *models.SBOMComponent {
	if appBundlePath == "" {
		return nil
	}
	plistPath := filepath.Join(appBundlePath, GoogleServiceInfoName)
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return nil // no Firebase config: not an error.
	}
	fc, err := ParseGoogleServiceInfoPlist(data)
	if err != nil {
		log.WithFields(log.Fields{"job_id": jobID, "plist": plistPath, "error": err.Error()}).
			Debug("Skipping undecodable GoogleService-Info.plist")
		return nil
	}
	c := models.NewFirebaseComponent(fc.ProjectID, fc.SDKs, models.FirebaseSourceIOS, plistPath)
	log.WithFields(log.Fields{"job_id": jobID, "project_id": fc.ProjectID, "sdks": fc.SDKs}).
		Info("Detected Firebase (GoogleService-Info.plist)")
	return &c
}

// marshalJSON marshals v to a JSON string for storage in an IOSMetadata JSON
// column. On error (which should not happen for the simple slice/map inputs
// here) it returns an empty JSON value so the column is never left with invalid
// JSON.
func marshalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}
