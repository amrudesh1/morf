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

package apk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"morf/models"
	"morf/utils"

	log "github.com/sirupsen/logrus"
)

// androidBinaryRoots returns the extra search roots that require a binary-safe
// (ripgrep --text) pass over the apktool "-r" output tree (GetSourceDir):
// native libraries (lib/**/*.so), bundled assets (assets/** — Flutter
// flutter_assets/ kernel blobs and React-Native index.android.bundle), the
// apktool "unknown/" bucket (where google-services.json and other unrecognized
// config JSON land), and the tree root itself (which carries resources.arsc and
// any top-level google-services.json).
//
// The root is included so resources.arsc and top-level config are covered by a
// single dir pass; androidBinaryExcludes keeps that root pass from re-scanning
// the smali/res/original trees already covered by the text pass. Existence
// filtering is deliberately deferred to detect.ScanCorpusText (it stat-filters
// roots to existing directories), so this helper stays a pure path computation
// that is unit-testable without an apktool run.
func androidBinaryRoots(jobCtx *utils.JobContext) []string {
	src := jobCtx.GetSourceDir()
	return []string{src}
}

// androidBinaryExcludes are the extra ripgrep "-g","!glob" pairs for the
// binary-safe pass. They exclude the trees already scanned (as text) by the
// primary ScanCorpus pass so the --text pass does not re-scan smali sources,
// decoded resources or apktool's "original/" copies in binary mode (which would
// double the work and duplicate smali findings). What remains under the source
// root for the --text pass: lib/**/*.so, assets/**, unknown/**, resources.arsc
// and any top-level google-services.json.
func androidBinaryExcludes() []string {
	return []string{
		"-g", "!**/smali*/**",
		"-g", "!**/res/**",
		"-g", "!**/original/**",
	}
}

// maxNativeLibHashBytes bounds the SHA-256 hashing pass over a single .so so a
// pathological (multi-hundred-MB) native library cannot make SBOM extraction
// dominate the scan. We hash the whole file when it is smaller than this cap;
// larger files are hashed over their first maxNativeLibHashBytes only, which is
// still a stable, reproducible content digest for the same artifact.
const maxNativeLibHashBytes = 64 * 1024 * 1024

// nativeLib is the per-basename grouping of a native library across the ABI
// directories it ships in. ABIs is the sorted set of ABI folder names that
// contain a file with this basename; SHA256 is the hex digest of a single
// representative file (the first ABI in sorted order); ABIsDiffer reports
// whether the per-ABI files were NOT byte-identical (their individual digests
// disagreed), so a consumer knows the single recorded SHA256 is representative
// rather than universal.
type nativeLib struct {
	Name       string
	ABIs       []string
	SHA256     string
	ABIsDiffer bool
}

// EnumerateNativeLibs walks <GetSourceDir>/lib/<abi>/*.so, groups the .so files
// by basename across every ABI directory, and returns one SBOMComponent per
// distinct library built via the foundation models.NewNativeLibComponent
// constructor.
//
// For each distinct basename it records:
//   - the ABIs it appears in (as occurrences lib/<abi>/<name> inside the
//     constructor),
//   - a SHA-256 over one representative file (the lexicographically-first ABI);
//     when the per-ABI files are not byte-identical a diagnostic is logged so
//     the single recorded hash is understood to be representative, not universal.
//
// It is best-effort and bounded: a missing lib/ tree yields no components; an
// unreadable individual file is skipped (logged at debug), never fatal. The walk
// is confined to the lib/ subtree (one os.ReadDir per ABI dir) so it stays fast
// regardless of the size of the rest of the decompiled output.
func EnumerateNativeLibs(jobCtx *utils.JobContext) []models.SBOMComponent {
	libRoot := filepath.Join(jobCtx.GetSourceDir(), "lib")

	// abiDirs are the immediate children of lib/ — the ABI folders
	// (arm64-v8a, armeabi-v7a, x86, x86_64, ...). A missing lib/ tree (no native
	// code) is not an error: we simply have no native-lib components to report.
	abiEntries, err := os.ReadDir(libRoot)
	if err != nil {
		return nil
	}

	// byName groups <abi>-relative .so files by basename. abiOf preserves, per
	// (basename, abi), the absolute path of the representative file so we can hash
	// it and compare digests across ABIs without re-walking.
	byName := map[string]*nativeLib{}
	pathOf := map[string]map[string]string{} // basename -> abi -> abs path

	for _, abiEntry := range abiEntries {
		if !abiEntry.IsDir() {
			continue
		}
		abi := abiEntry.Name()
		abiDir := filepath.Join(libRoot, abi)
		soEntries, readErr := os.ReadDir(abiDir)
		if readErr != nil {
			continue
		}
		for _, so := range soEntries {
			if so.IsDir() || !strings.HasSuffix(so.Name(), ".so") {
				continue
			}
			name := so.Name()
			lib, ok := byName[name]
			if !ok {
				lib = &nativeLib{Name: name}
				byName[name] = lib
				pathOf[name] = map[string]string{}
			}
			lib.ABIs = append(lib.ABIs, abi)
			pathOf[name][abi] = filepath.Join(abiDir, so.Name())
		}
	}

	if len(byName) == 0 {
		return nil
	}

	// Deterministic ordering: sort the library names and, per library, its ABIs.
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	components := make([]models.SBOMComponent, 0, len(names))
	for _, name := range names {
		lib := byName[name]
		sort.Strings(lib.ABIs)

		// Hash the representative (first ABI) file, then compare against the other
		// ABIs' digests so ABIsDiffer is accurate. All hashing is best-effort.
		var repDigest string
		digests := make([]string, 0, len(lib.ABIs))
		for _, abi := range lib.ABIs {
			d, hErr := hashFileSHA256(pathOf[name][abi])
			if hErr != nil {
				log.WithFields(log.Fields{
					"job_id": jobCtx.JobID,
					"lib":    name,
					"abi":    abi,
					"error":  hErr.Error(),
				}).Debug("Skipping unhashable native library file")
				continue
			}
			if repDigest == "" {
				repDigest = d
			}
			digests = append(digests, d)
		}
		lib.SHA256 = repDigest
		for _, d := range digests {
			if d != repDigest {
				lib.ABIsDiffer = true
				break
			}
		}
		if lib.ABIsDiffer {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"lib":    name,
				"abis":   strings.Join(lib.ABIs, ","),
			}).Debug("Native library differs across ABIs; recorded SHA-256 is representative of the first ABI")
		}

		components = append(components, models.NewNativeLibComponent(lib.Name, lib.ABIs, lib.SHA256))
	}
	return components
}

// hashFileSHA256 returns the lowercase-hex SHA-256 of at most
// maxNativeLibHashBytes of the file at path. Bounding the read keeps a
// pathologically large native library from dominating the scan while still
// producing a stable digest for the same bytes.
func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxNativeLibHashBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// classifyRuntime inspects the set of native-library basenames (plus the
// presence of a React-Native JS bundle asset) and returns the runtime framework
// components the .so signatures imply, built via models.NewRuntimeComponent.
//
// Signatures (any single match classifies the runtime):
//   - Flutter:      libflutter.so or libapp.so
//   - React Native: libhermes.so, libjscexecutor.so, libreactnativejni.so, or an
//     assets/index.android.bundle JS bundle
//   - Xamarin/.NET: libmonodroid.so or any libmonosgen* soname
//
// Each detected runtime records, as occurrences, the lib/<abi>/<name> paths (or
// the bundle asset path) that evidenced it. libNames is the map produced from
// the same lib/ walk EnumerateNativeLibs uses (basename -> sorted ABIs);
// hasRNBundle reports whether assets/index.android.bundle exists.
func classifyRuntime(libNames map[string][]string, hasRNBundle bool) []models.SBOMComponent {
	// occurrencesFor builds lib/<abi>/<name> occurrence paths for a matched .so.
	occurrencesFor := func(name string) []string {
		abis := libNames[name]
		out := make([]string, 0, len(abis))
		for _, abi := range abis {
			out = append(out, filepath.Join("lib", abi, name))
		}
		return out
	}

	var out []models.SBOMComponent

	// Flutter: libflutter.so (engine) or libapp.so (AOT-compiled Dart).
	var flutterEvidence []string
	for _, n := range []string{"libflutter.so", "libapp.so"} {
		if _, ok := libNames[n]; ok {
			flutterEvidence = append(flutterEvidence, occurrencesFor(n)...)
		}
	}
	if len(flutterEvidence) > 0 {
		out = append(out, models.NewRuntimeComponent("Flutter", flutterEvidence))
	}

	// React Native: the JS engine / bridge sonames, or the packaged JS bundle.
	var rnEvidence []string
	for _, n := range []string{"libhermes.so", "libjscexecutor.so", "libreactnativejni.so"} {
		if _, ok := libNames[n]; ok {
			rnEvidence = append(rnEvidence, occurrencesFor(n)...)
		}
	}
	if hasRNBundle {
		rnEvidence = append(rnEvidence, filepath.Join("assets", "index.android.bundle"))
	}
	if len(rnEvidence) > 0 {
		out = append(out, models.NewRuntimeComponent("React Native", rnEvidence))
	}

	// Xamarin / .NET: the Mono runtime sonames (libmonodroid.so, libmonosgen*).
	var xamarinEvidence []string
	for name, abis := range libNames {
		if name == "libmonodroid.so" || strings.HasPrefix(name, "libmonosgen") {
			for _, abi := range abis {
				xamarinEvidence = append(xamarinEvidence, filepath.Join("lib", abi, name))
			}
		}
	}
	if len(xamarinEvidence) > 0 {
		// Deterministic occurrence ordering (map iteration is random).
		sort.Strings(xamarinEvidence)
		out = append(out, models.NewRuntimeComponent("Xamarin/.NET", xamarinEvidence))
	}

	return out
}

// nativeLibNames re-walks lib/<abi> exactly as EnumerateNativeLibs does and
// returns basename -> sorted ABIs, without hashing. classifyRuntime consumes
// this cheap view so runtime detection does not pay the SHA-256 cost.
func nativeLibNames(jobCtx *utils.JobContext) map[string][]string {
	libRoot := filepath.Join(jobCtx.GetSourceDir(), "lib")
	abiEntries, err := os.ReadDir(libRoot)
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, abiEntry := range abiEntries {
		if !abiEntry.IsDir() {
			continue
		}
		abi := abiEntry.Name()
		soEntries, readErr := os.ReadDir(filepath.Join(libRoot, abi))
		if readErr != nil {
			continue
		}
		for _, so := range soEntries {
			if so.IsDir() || !strings.HasSuffix(so.Name(), ".so") {
				continue
			}
			out[so.Name()] = append(out[so.Name()], abi)
		}
	}
	for name := range out {
		sort.Strings(out[name])
	}
	return out
}

// hasReactNativeBundle reports whether assets/index.android.bundle exists under
// the decompiled tree (the packaged JS bundle a React-Native app ships).
func hasReactNativeBundle(jobCtx *utils.JobContext) bool {
	p := filepath.Join(jobCtx.GetSourceDir(), "assets", "index.android.bundle")
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// googleServicesConfig is the subset of a google-services.json we parse for
// SBOM Firebase detection. The file is the Google-services Gradle plugin's
// config that a Firebase-enabled Android app ships; it names the Firebase
// project and the client apps/services registered against it.
//
// Only the fields MORF concludes evidence from are modeled; unknown fields are
// ignored by encoding/json. project_info.project_id is the project identity;
// each client[].services.<name> is a per-client service block whose presence
// (with an enabled status) evidences an enabled Firebase SDK.
type googleServicesConfig struct {
	ProjectInfo struct {
		ProjectID     string `json:"project_id"`
		ProjectNumber string `json:"project_number"`
	} `json:"project_info"`
	Client []struct {
		ClientInfo struct {
			MobileSDKAppID    string `json:"mobilesdk_app_id"`
			AndroidClientInfo struct {
				PackageName string `json:"package_name"`
			} `json:"android_client_info"`
		} `json:"client_info"`
		// Services is the per-client service map. Real keys include
		// appinvite_service, ads_service, analytics_service, etc. We only look at
		// whether the block is present with a non-disabled status; the exact shape
		// varies, so it is decoded as a permissive map.
		Services map[string]struct {
			Status              int  `json:"status"`
			AnalyticsEnabled    bool `json:"analytics_enabled"`
			GA4AutoLoggingRules any  `json:"ga4_auto_logging_rules"`
		} `json:"services"`
	} `json:"client"`
}

// googleServicesSearchPaths returns, in priority order, the candidate locations
// of a google-services.json inside the apktool "-r" output tree. apktool routes
// unrecognized top-level config into unknown/, but a google-services.json can
// also survive as a raw resource (res/raw/) or sit at the decompiled tree root.
func googleServicesSearchPaths(jobCtx *utils.JobContext) []string {
	src := jobCtx.GetSourceDir()
	return []string{
		filepath.Join(src, "unknown", "google-services.json"),
		filepath.Join(src, "res", "raw", "google-services.json"),
		filepath.Join(src, "google-services.json"),
	}
}

// detectFirebaseSDKs derives the sorted, de-duplicated set of enabled Firebase
// services from the parsed config. A service is counted when at least one client
// registers it with a non-disabled status (google-services uses status==2 for
// enabled, status==1 for absent/disabled; analytics_enabled corroborates
// Analytics). The "_service" suffix is trimmed so the SBOM records "analytics",
// "ads", … rather than the raw JSON keys.
func detectFirebaseSDKs(cfg *googleServicesConfig) []string {
	set := map[string]struct{}{}
	for _, client := range cfg.Client {
		for name, svc := range client.Services {
			enabled := svc.Status >= 2 || svc.AnalyticsEnabled
			if !enabled {
				continue
			}
			set[strings.TrimSuffix(name, "_service")] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// detectFirebase looks for a google-services.json in the decompiled tree, parses
// it, and returns a single umbrella Firebase SBOM component built via
// models.NewFirebaseComponent (source="android" -> pkg:maven firebase-bom).
//
// It is strictly best-effort: no file found, an unreadable file, or a file that
// does not parse as the expected JSON is logged at debug and yields (nil,false),
// never an error — a missing Firebase config must never fail a scan. The
// returned evidencePath is the tree-relative path of the config so the SBOM
// occurrence points at the artifact that evidenced the component.
func detectFirebase(jobCtx *utils.JobContext) (models.SBOMComponent, bool) {
	src := jobCtx.GetSourceDir()
	for _, path := range googleServicesSearchPaths(jobCtx) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // not at this location; try the next candidate
		}

		var cfg googleServicesConfig
		if jErr := json.Unmarshal(data, &cfg); jErr != nil {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"path":   path,
				"error":  jErr.Error(),
			}).Debug("Skipping unparseable google-services.json for Firebase SBOM detection")
			continue
		}
		if cfg.ProjectInfo.ProjectID == "" {
			log.WithFields(log.Fields{
				"job_id": jobCtx.JobID,
				"path":   path,
			}).Debug("google-services.json has no project_info.project_id; skipping Firebase SBOM component")
			continue
		}

		sdks := detectFirebaseSDKs(&cfg)
		// Record the occurrence as a tree-relative path so it reads the same way
		// as the native-lib lib/<abi>/<name> occurrences.
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			rel = path
		}

		log.WithFields(log.Fields{
			"job_id":     jobCtx.JobID,
			"project_id": cfg.ProjectInfo.ProjectID,
			"sdks":       strings.Join(sdks, ","),
			"path":       rel,
		}).Debug("Detected Firebase integration from google-services.json")

		return models.NewFirebaseComponent(
			cfg.ProjectInfo.ProjectID,
			sdks,
			models.FirebaseSourceAndroid,
			rel,
		), true
	}
	return models.SBOMComponent{}, false
}

// CollectSBOMComponents assembles the full Android SBOM component set for a
// scanned APK: every distinct native library (EnumerateNativeLibs), any detected
// runtime framework (classifyRuntime), and a structured Firebase component when a
// google-services.json is present (detectFirebase). This is the single entry
// point the scan pipeline wires into the result payload under the contract key
// "sbomComponents". It is best-effort and never fails a scan.
func CollectSBOMComponents(jobCtx *utils.JobContext) []models.SBOMComponent {
	libs := EnumerateNativeLibs(jobCtx)
	runtimes := classifyRuntime(nativeLibNames(jobCtx), hasReactNativeBundle(jobCtx))
	firebase, hasFirebase := detectFirebase(jobCtx)

	if len(libs) == 0 && len(runtimes) == 0 && !hasFirebase {
		return nil
	}
	out := make([]models.SBOMComponent, 0, len(libs)+len(runtimes)+1)
	out = append(out, libs...)
	out = append(out, runtimes...)
	if hasFirebase {
		out = append(out, firebase)
	}
	return out
}
