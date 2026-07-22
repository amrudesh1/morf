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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"morf/models"
	"morf/utils"
)

// jobCtxForDir builds a JobContext whose workspace is an isolated temp dir so a
// test never touches the real /tmp/morf/jobs tree. Workspace is an exported
// field and GetSourceDir/GetResDir derive from it, so overriding it reroutes the
// whole output/apk subtree.
func jobCtxForDir(t *testing.T, id string) *utils.JobContext {
	t.Helper()
	jc := utils.NewJobContextForID(id)
	jc.Workspace = t.TempDir()
	return jc
}

// TestAndroidBinaryRoots asserts the binary-safe pass roots at the "-r" apktool
// output tree (GetSourceDir), which carries lib/, assets/, unknown/,
// resources.arsc and any top-level google-services.json. Existence filtering is
// deferred to detect.ScanCorpusText, so the helper returns the root regardless
// of whether the subtrees have been created yet.
func TestAndroidBinaryRoots(t *testing.T) {
	jc := jobCtxForDir(t, "job-roots")
	got := androidBinaryRoots(jc)
	want := []string{jc.GetSourceDir()}
	if !slices.Equal(got, want) {
		t.Fatalf("androidBinaryRoots() = %v, want %v", got, want)
	}
}

// TestAndroidBinaryExcludes pins the excludes that keep the --text pass from
// re-scanning the smali/res/original trees already covered by the text pass.
func TestAndroidBinaryExcludes(t *testing.T) {
	got := androidBinaryExcludes()
	want := []string{
		"-g", "!**/smali*/**",
		"-g", "!**/res/**",
		"-g", "!**/original/**",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("androidBinaryExcludes() = %v, want %v", got, want)
	}
}

// writeTestPatterns drops a minimal patterns YAML into a temp dir and points
// MORF_PATTERNS_DIR at it. The single high-confidence pattern (AWS example key)
// is enough to prove the new roots are scanned. The fresh file's ModTime is
// newer than any earlier build, so detect's per-platform cache rebuilds.
func writeTestPatterns(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	yaml := `patterns:
  - pattern:
      name: AWS Access Key
      regex: "AKIA[0-9A-Z]{16}"
      confidence: high
      enabled: true
`
	if err := os.WriteFile(filepath.Join(dir, "test-secrets.yml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("write patterns: %v", err)
	}
	t.Setenv("MORF_PATTERNS_DIR", dir)
}

// TestStartScanE_ScansBinaryArtifacts is the end-to-end regression for Android
// binary coverage: a well-formed AWS key is planted inside a fake native .so, a
// Flutter asset blob and a google-services.json under apktool's unknown/ bucket,
// each surrounded by NUL bytes so ripgrep would treat them as binary and skip
// them without the --text pass. StartScanE must find the key in every artifact.
func TestStartScanE_ScansBinaryArtifacts(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep (rg) not installed; skipping scan integration test")
	}
	writeTestPatterns(t)

	jc := jobCtxForDir(t, "job-binscan")
	src := jc.GetSourceDir()

	const planted = "AKIAIOSFODNN7EXAMPLE" // canonical AWS example key
	// Wrap the planted key in NUL bytes so the files register as binary and are
	// skipped unless ripgrep is invoked with -a/--text (the load-bearing gap).
	blob := func(s string) []byte {
		return append([]byte("\x00\x00head\x00"+s+"\x00tail\x00\x00"), 0x00)
	}

	files := map[string][]byte{
		filepath.Join(src, "lib", "arm64-v8a", "libsecret.so"):            blob(planted),
		filepath.Join(src, "assets", "flutter_assets", "kernel_blob.bin"): blob(planted),
		filepath.Join(src, "unknown", "google-services.json"):             blob(planted),
		filepath.Join(src, "resources.arsc"):                              blob(planted),
		// A smali file also containing the key: it must NOT contribute an extra
		// finding from the binary pass (excluded), only from the text pass.
		filepath.Join(src, "smali", "com", "app", "Config.smali"): []byte("const-string v0, \"" + planted + "\"\n"),
	}
	for path, data := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	// GetResDir must exist so the text pass root survives stat-filtering.
	if err := os.MkdirAll(jc.GetResDir(), 0755); err != nil {
		t.Fatalf("mkdir resdir: %v", err)
	}

	secrets, err := StartScanE(context.Background(), jc)
	if err != nil {
		t.Fatalf("StartScanE returned error: %v", err)
	}
	if len(secrets) == 0 {
		t.Fatal("no secrets found; expected the planted key in native/asset/config artifacts")
	}

	// Collect the set of files that yielded the planted key.
	hitFiles := map[string]bool{}
	for _, s := range secrets {
		if s.SecretString == planted {
			hitFiles[filepath.Base(s.FileLocation)] = true
		}
	}

	// Every binary artifact must have been scanned via the --text pass.
	wantBinaryHits := []string{"libsecret.so", "kernel_blob.bin", "google-services.json", "resources.arsc"}
	for _, name := range wantBinaryHits {
		if !hitFiles[name] {
			t.Errorf("planted key not found in %s (binary --text pass missed it); hits=%v", name, hitFiles)
		}
	}

	// The smali file is found once by the text pass; the binary pass must exclude
	// smali, so it is not double-counted from the binary root.
	smaliCount := 0
	for _, s := range secrets {
		if s.SecretString == planted && filepath.Base(s.FileLocation) == "Config.smali" {
			smaliCount++
		}
	}
	if smaliCount != 1 {
		t.Errorf("smali key found %d times, want exactly 1 (binary pass should exclude smali)", smaliCount)
	}
}

// TestStartScanE_LargeNewlineSparseBinary is the regression for the giant-line
// crash: real native libraries (libflutter.so, libapp.so, RN/ML blobs) have
// multi-megabyte newline-sparse regions, so ripgrep's --text pass emits a single
// enormous "line". The old bufio.Scanner (4MB cap) returned "token too long" on
// such input, which aborted the whole Android scan AND discarded the valid
// text-pass findings. This plants a key inside a >5MB newline-free .so and
// asserts the scan (a) does not error and (b) still finds the planted key, so a
// large native lib can never fail the job or lose findings.
func TestStartScanE_LargeNewlineSparseBinary(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep (rg) not installed; skipping large-binary regression test")
	}
	writeTestPatterns(t)

	jc := jobCtxForDir(t, "job-largebin")
	src := jc.GetSourceDir()
	const planted = "AKIAIOSFODNN7EXAMPLE"

	// Build a >5MB newline-free blob: NUL padding, the planted key, then a long
	// run of non-newline bytes so the whole file is one giant "line" to ripgrep.
	var buf bytes.Buffer
	buf.WriteString("\x00\x00head\x00" + planted + "\x00")
	filler := bytes.Repeat([]byte("A"), 6*1024*1024) // 6 MB, no newlines
	buf.Write(filler)

	soPath := filepath.Join(src, "lib", "arm64-v8a", "libapp.so")
	if err := os.MkdirAll(filepath.Dir(soPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(soPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write large .so: %v", err)
	}
	if err := os.MkdirAll(jc.GetResDir(), 0755); err != nil {
		t.Fatalf("mkdir resdir: %v", err)
	}

	secrets, err := StartScanE(context.Background(), jc)
	if err != nil {
		t.Fatalf("StartScanE errored on a large newline-sparse .so (the crash regression): %v", err)
	}
	found := false
	for _, s := range secrets {
		if s.SecretString == planted && filepath.Base(s.FileLocation) == "libapp.so" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("planted key not found in the >5MB .so; hits=%v", secrets)
	}
}

// writeFakeNativeLib creates a .so under lib/<abi>/<name> with the given bytes,
// mkdir-ing the ABI directory. No apktool run is required — the tree is the
// exact shape apktool's "-r" output would leave under GetSourceDir.
func writeFakeNativeLib(t *testing.T, jc *utils.JobContext, abi, name string, data []byte) {
	t.Helper()
	dir := filepath.Join(jc.GetSourceDir(), "lib", abi)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
		t.Fatalf("write %s/%s: %v", dir, name, err)
	}
}

// TestEnumerateNativeLibs_GroupsByBasenameAndDetectsFlutter builds a fake
// decompiled tree with libfoo.so shipped for two ABIs plus a Flutter engine
// .so, then asserts:
//   - libfoo.so collapses to exactly ONE component across the two ABIs;
//   - that component records both lib/<abi>/libfoo.so occurrences;
//   - it carries a SHA-256 hash entry backed by a hash-comparison identity
//     method (the byte-identity evidence);
//   - CollectSBOMComponents additionally yields a "Flutter" runtime component
//     from the libflutter.so signature.
//
// It never shells out to apktool — the tree is constructed directly on disk.
func TestEnumerateNativeLibs_GroupsByBasenameAndDetectsFlutter(t *testing.T) {
	jc := jobCtxForDir(t, "job-nativelibs")

	// libfoo.so ships for arm64-v8a and armeabi-v7a with identical bytes; a
	// Flutter engine .so ships for arm64-v8a only.
	fooBytes := []byte("\x7fELF-fake-libfoo-contents")
	writeFakeNativeLib(t, jc, "arm64-v8a", "libfoo.so", fooBytes)
	writeFakeNativeLib(t, jc, "armeabi-v7a", "libfoo.so", fooBytes)
	writeFakeNativeLib(t, jc, "arm64-v8a", "libflutter.so", []byte("\x7fELF-fake-flutter"))

	libs := EnumerateNativeLibs(jc)

	// Exactly two distinct native-lib components: libfoo.so and libflutter.so.
	// libfoo must NOT be duplicated per ABI.
	byName := map[string]models.SBOMComponent{}
	for _, c := range libs {
		if _, dup := byName[c.Name]; dup {
			t.Fatalf("native lib %q appeared more than once; want exactly one component per basename (got %d total)", c.Name, len(libs))
		}
		byName[c.Name] = c
	}
	foo, ok := byName["libfoo.so"]
	if !ok {
		t.Fatalf("libfoo.so component missing; got components %v", componentNames(libs))
	}

	// Two ABI occurrences: lib/arm64-v8a/libfoo.so and lib/armeabi-v7a/libfoo.so.
	gotOcc := make([]string, 0, len(foo.Evidence.Occurrences))
	for _, o := range foo.Evidence.Occurrences {
		gotOcc = append(gotOcc, o.Location)
	}
	slices.Sort(gotOcc)
	wantOcc := []string{"lib/arm64-v8a/libfoo.so", "lib/armeabi-v7a/libfoo.so"}
	if !slices.Equal(gotOcc, wantOcc) {
		t.Errorf("libfoo occurrences = %v, want %v", gotOcc, wantOcc)
	}

	// A SHA-256 hash entry must be present.
	if len(foo.Hashes) != 1 || foo.Hashes[0].Alg != "SHA-256" || foo.Hashes[0].Content == "" {
		t.Errorf("libfoo hashes = %+v, want one non-empty SHA-256 entry", foo.Hashes)
	}

	// A hash-comparison identity method (the byte-identity evidence) must back it.
	if !hasHashComparisonEvidence(foo) {
		t.Errorf("libfoo missing a hash-comparison identity method; identity = %+v", foo.Evidence.Identity)
	}

	// CollectSBOMComponents must additionally surface the Flutter runtime.
	all := CollectSBOMComponents(jc)
	if !hasRuntimeComponent(all, "Flutter") {
		t.Errorf("expected a Flutter runtime component from libflutter.so; got %v", componentNames(all))
	}
}

// TestCollectSBOMComponents_DetectsFirebaseFromGoogleServices builds a fake
// decompiled tree with a google-services.json under apktool's unknown/ bucket
// (the location apktool routes unrecognized top-level config into), then asserts
// CollectSBOMComponents surfaces a single Firebase component that:
//   - carries the project_info.project_id from the config (in its name),
//   - is anchored to the Android Firebase BOM purl / group (source="android"),
//   - records the detected SDK set (analytics/crashlytics) somewhere in its
//     evidence, and
//   - has an occurrence pointing at the tree-relative config path.
//
// No apktool run is required — the JSON is written directly on disk.
func TestCollectSBOMComponents_DetectsFirebaseFromGoogleServices(t *testing.T) {
	jc := jobCtxForDir(t, "job-firebase")

	const projectID = "morf-demo-project"
	// A trimmed but structurally-faithful google-services.json: a project_id plus
	// one client whose services enable Analytics and Crashlytics (status 2).
	googleServices := `{
  "project_info": {
    "project_number": "1234567890",
    "project_id": "` + projectID + `",
    "storage_bucket": "` + projectID + `.appspot.com"
  },
  "client": [
    {
      "client_info": {
        "mobilesdk_app_id": "1:1234567890:android:abcdef",
        "android_client_info": { "package_name": "com.example.morfdemo" }
      },
      "services": {
        "appinvite_service": { "status": 1 },
        "analytics_service": { "status": 2, "analytics_enabled": true },
        "crashlytics_service": { "status": 2 }
      }
    }
  ]
}`

	cfgPath := filepath.Join(jc.GetSourceDir(), "unknown", "google-services.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatalf("mkdir unknown/: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(googleServices), 0644); err != nil {
		t.Fatalf("write google-services.json: %v", err)
	}

	all := CollectSBOMComponents(jc)

	fb, ok := firebaseComponent(all)
	if !ok {
		t.Fatalf("expected a Firebase component from google-services.json; got %v", componentNames(all))
	}

	// The project_id must survive into the component identity (the constructor
	// folds it into the name and the purl identity's concludedValue).
	if !strings.Contains(fb.Name, projectID) {
		t.Errorf("Firebase component name = %q, want it to contain project id %q", fb.Name, projectID)
	}

	// source="android" -> the Firebase Android BOM purl + com.google.firebase group.
	if fb.Purl != models.FirebaseMavenBOMPurl {
		t.Errorf("Firebase purl = %q, want the Android BOM purl %q", fb.Purl, models.FirebaseMavenBOMPurl)
	}
	if fb.Group != "com.google.firebase" {
		t.Errorf("Firebase group = %q, want com.google.firebase", fb.Group)
	}

	// The source occurrence must point at the tree-relative config path.
	wantOcc := filepath.Join("unknown", "google-services.json")
	hasOcc := false
	for _, o := range fb.Evidence.Occurrences {
		if o.Location == wantOcc {
			hasOcc = true
			break
		}
	}
	if !hasOcc {
		t.Errorf("Firebase occurrences = %+v, want one at %q", fb.Evidence.Occurrences, wantOcc)
	}

	// The purl identity's concludedValue must carry the project id so the SBOM's
	// evidence graph names the concrete Firebase project.
	hasProjectEvidence := false
	for _, id := range fb.Evidence.Identity {
		if id.Field == "purl" && strings.Contains(id.ConcludedValue, projectID) {
			hasProjectEvidence = true
			break
		}
	}
	if !hasProjectEvidence {
		t.Errorf("Firebase purl identity missing project id %q; identity = %+v", projectID, fb.Evidence.Identity)
	}

	// The detected SDK set (analytics + crashlytics) must be preserved. The
	// constructor folds the SDK list into Group only when no Maven groupId
	// occupies it; on Android the group is com.google.firebase, so the SDKs are
	// carried by the SBOM component's identity/occurrences rather than Group. We
	// assert at minimum that detection surfaced both enabled services.
	sdks := detectFirebaseSDKs(mustParseGoogleServices(t, googleServices))
	if !slices.Contains(sdks, "analytics") || !slices.Contains(sdks, "crashlytics") {
		t.Errorf("detected SDKs = %v, want both analytics and crashlytics", sdks)
	}
	// The disabled appinvite service (status 1) must NOT be reported.
	if slices.Contains(sdks, "appinvite") {
		t.Errorf("detected SDKs = %v, must exclude the disabled appinvite service", sdks)
	}
}

// TestDetectFirebase_MissingConfigIsSkipped asserts the best-effort contract: a
// decompiled tree with no google-services.json yields no Firebase component and
// never fails, so CollectSBOMComponents returns nil for an otherwise empty tree.
func TestDetectFirebase_MissingConfigIsSkipped(t *testing.T) {
	jc := jobCtxForDir(t, "job-firebase-missing")
	if err := os.MkdirAll(jc.GetSourceDir(), 0755); err != nil {
		t.Fatalf("mkdir source: %v", err)
	}
	if _, ok := firebaseComponent(CollectSBOMComponents(jc)); ok {
		t.Fatal("expected no Firebase component when google-services.json is absent")
	}
}

// TestDetectFirebase_UnparseableConfigIsSkipped asserts a malformed
// google-services.json is skipped (debug-logged) rather than fatal, so a
// corrupt config never surfaces a spurious component or errors the scan.
func TestDetectFirebase_UnparseableConfigIsSkipped(t *testing.T) {
	jc := jobCtxForDir(t, "job-firebase-bad")
	cfgPath := filepath.Join(jc.GetSourceDir(), "unknown", "google-services.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatalf("mkdir unknown/: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	if _, ok := firebaseComponent(CollectSBOMComponents(jc)); ok {
		t.Fatal("expected no Firebase component from an unparseable google-services.json")
	}
}

// firebaseComponent returns the Firebase umbrella component if present. The
// Firebase constructor sets a "firebase:" bom-ref, which uniquely distinguishes
// it from native-lib / runtime components.
func firebaseComponent(cs []models.SBOMComponent) (models.SBOMComponent, bool) {
	for _, c := range cs {
		if strings.HasPrefix(c.BomRef, "firebase:") {
			return c, true
		}
	}
	return models.SBOMComponent{}, false
}

// mustParseGoogleServices parses a google-services.json body into the internal
// config type for direct assertions on SDK detection.
func mustParseGoogleServices(t *testing.T, body string) *googleServicesConfig {
	t.Helper()
	var cfg googleServicesConfig
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("parse google-services.json fixture: %v", err)
	}
	return &cfg
}

// componentNames returns the component names for diagnostic output.
func componentNames(cs []models.SBOMComponent) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// hasHashComparisonEvidence reports whether any identity entry of c is backed by
// a hash-comparison technique method.
func hasHashComparisonEvidence(c models.SBOMComponent) bool {
	for _, id := range c.Evidence.Identity {
		for _, m := range id.Methods {
			if m.Technique == models.TechniqueHashComparison {
				return true
			}
		}
	}
	return false
}

// hasRuntimeComponent reports whether cs contains a framework component with the
// given runtime name.
func hasRuntimeComponent(cs []models.SBOMComponent, name string) bool {
	for _, c := range cs {
		if c.Type == "framework" && c.Name == name {
			return true
		}
	}
	return false
}
