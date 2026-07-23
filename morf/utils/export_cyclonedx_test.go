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

package utils

import (
	"bytes"
	"encoding/json"
	"morf/models"
	"morf/version"
	"testing"
	"time"
)

// buildCycloneDXFixture returns a job + payload carrying a representative set of
// evidence-bearing SBOM components: a framework with a version
// (manifest-analysis), a native library shipped for two ABIs with a SHA-256
// (filename + hash-comparison), and a runtime (binary-analysis).
func buildCycloneDXFixture() (*models.ScanJob, *scanResultPayload) {
	job := &models.ScanJob{
		ID:               "cyclonedx-job-001",
		Status:           models.JobStatusCompleted,
		OriginalFilename: "example.ipa",
		CreatedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	result := &scanResultPayload{
		Message: "Success",
		Data: scanResultData{
			FileName:    "example.ipa",
			PackageName: "com.example.app",
			Version:     "3.2.1",
			SBOMComponents: []models.SBOMComponent{
				models.NewFrameworkComponent("Alamofire", "5.9.0", "", "Frameworks/Alamofire.framework"),
				models.NewNativeLibComponent("libflutter.so", []string{"arm64-v8a", "armeabi-v7a"}, sha),
				models.NewRuntimeComponent("Flutter", []string{"Frameworks/Flutter.framework/Flutter"}),
			},
		},
	}
	return job, result
}

// TestExportCycloneDX16Structure verifies exportCycloneDX emits well-formed
// CycloneDX 1.6 with the app root, MORF tool component, evidence
// techniques/confidence, occurrences, hashes, purl, and an "incomplete"
// composition aggregate.
func TestExportCycloneDX16Structure(t *testing.T) {
	job, result := buildCycloneDXFixture()

	data, ct, err := exportCycloneDX(job, result, nil)
	if err != nil {
		t.Fatalf("exportCycloneDX returned error: %v", err)
	}
	if ct != "application/vnd.cyclonedx+json" {
		t.Errorf("content type = %q; want application/vnd.cyclonedx+json", ct)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Top-level spec version.
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v; want CycloneDX", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v; want 1.6", bom["specVersion"])
	}

	metadata, ok := bom["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata missing or wrong type")
	}
	if _, ok := metadata["timestamp"].(string); !ok {
		t.Error("metadata.timestamp missing")
	}

	// App root component.
	appRoot, ok := metadata["component"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata.component missing")
	}
	if appRoot["type"] != "application" {
		t.Errorf("app root type = %v; want application", appRoot["type"])
	}
	if appRoot["bom-ref"] != "app" {
		t.Errorf("app root bom-ref = %v; want app", appRoot["bom-ref"])
	}
	if appRoot["name"] != "com.example.app" {
		t.Errorf("app root name = %v; want com.example.app", appRoot["name"])
	}
	if appRoot["version"] != "3.2.1" {
		t.Errorf("app root version = %v; want 3.2.1", appRoot["version"])
	}

	// MORF tool component with the real version and mandated publisher.
	tools, ok := metadata["tools"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata.tools missing or wrong type")
	}
	toolComps, ok := tools["components"].([]interface{})
	if !ok || len(toolComps) == 0 {
		t.Fatal("metadata.tools.components missing")
	}
	tool := toolComps[0].(map[string]interface{})
	if tool["name"] != "morf" {
		t.Errorf("tool name = %v; want morf", tool["name"])
	}
	if tool["publisher"] != "MORF - Mobile Reconnaissance Framework" {
		t.Errorf("tool publisher = %v; want MORF - Mobile Reconnaissance Framework", tool["publisher"])
	}
	if tool["version"] != version.Version {
		t.Errorf("tool version = %v; want %v (real build version, not hardcoded)", tool["version"], version.Version)
	}

	// completeness property.
	props, ok := metadata["properties"].([]interface{})
	if !ok || len(props) == 0 {
		t.Fatal("metadata.properties missing")
	}
	p0 := props[0].(map[string]interface{})
	if p0["name"] != "morf:sbom:completeness" || p0["value"] != "evidence-based-lower-bound" {
		t.Errorf("completeness property = %v; want morf:sbom:completeness=evidence-based-lower-bound", p0)
	}

	// Compositions.
	comps, ok := bom["compositions"].([]interface{})
	if !ok || len(comps) == 0 {
		t.Fatal("compositions missing")
	}
	c0 := comps[0].(map[string]interface{})
	if c0["aggregate"] != "incomplete" {
		t.Errorf("compositions[0].aggregate = %v; want incomplete", c0["aggregate"])
	}
	asm, ok := c0["assemblies"].([]interface{})
	if !ok || len(asm) == 0 || asm[0] != "app" {
		t.Errorf("compositions[0].assemblies = %v; want [app]", c0["assemblies"])
	}

	// Components: index by name for targeted assertions.
	rawComponents, ok := bom["components"].([]interface{})
	if !ok || len(rawComponents) != 3 {
		t.Fatalf("expected 3 components; got %v", bom["components"])
	}
	byName := map[string]map[string]interface{}{}
	for _, rc := range rawComponents {
		m := rc.(map[string]interface{})
		byName[m["name"].(string)] = m
	}

	// Framework: version + manifest-analysis evidence + purl.
	fw := byName["Alamofire"]
	if fw == nil {
		t.Fatal("Alamofire framework component missing")
	}
	if fw["type"] != "framework" {
		t.Errorf("Alamofire type = %v; want framework", fw["type"])
	}
	if fw["version"] != "5.9.0" {
		t.Errorf("Alamofire version = %v; want 5.9.0", fw["version"])
	}
	// Phase 2: Alamofire is a known library, so even name-only (no bundleID) it
	// maps to its real ecosystem coordinate (the SPM host form) rather than
	// pkg:generic. A CocoaPods bundleID would instead yield pkg:cocoapods/Alamofire.
	if fw["purl"] != "pkg:swift/github.com/Alamofire/Alamofire@5.9.0" {
		t.Errorf("Alamofire purl = %v; want pkg:swift/github.com/Alamofire/Alamofire@5.9.0", fw["purl"])
	}
	assertHasTechnique(t, fw, "Alamofire", models.TechniqueManifestAnalysis, models.ConfidenceMedium)
	assertHasOccurrence(t, fw, "Alamofire", "Frameworks/Alamofire.framework")

	// Native lib: hash + hash-comparison HIGH confidence + 2 ABI occurrences.
	nl := byName["libflutter.so"]
	if nl == nil {
		t.Fatal("libflutter.so component missing")
	}
	hashes, ok := nl["hashes"].([]interface{})
	if !ok || len(hashes) == 0 {
		t.Fatal("libflutter.so hashes missing")
	}
	h0 := hashes[0].(map[string]interface{})
	if h0["alg"] != "SHA-256" {
		t.Errorf("hash alg = %v; want SHA-256", h0["alg"])
	}
	assertHasTechnique(t, nl, "libflutter.so", models.TechniqueHashComparison, models.ConfidenceHigh)
	assertHasTechnique(t, nl, "libflutter.so", models.TechniqueFilename, models.ConfidenceMedium)
	assertHasOccurrence(t, nl, "libflutter.so", "lib/arm64-v8a/libflutter.so")
	assertHasOccurrence(t, nl, "libflutter.so", "lib/armeabi-v7a/libflutter.so")

	// Runtime: filename-inference evidence (runtime is detected from the PRESENCE
	// of marker .so files, not byte analysis — so technique=filename at LOW conf).
	rt := byName["Flutter"]
	if rt == nil {
		t.Fatal("Flutter runtime component missing")
	}
	assertHasTechnique(t, rt, "Flutter", models.TechniqueFilename, models.ConfidenceLow)
}

// assertHasTechnique fails unless component comp has an identity method with the
// given technique and confidence.
func assertHasTechnique(t *testing.T, comp map[string]interface{}, name, technique string, confidence float64) {
	t.Helper()
	evidence, ok := comp["evidence"].(map[string]interface{})
	if !ok {
		t.Fatalf("%s: evidence missing", name)
	}
	identities, ok := evidence["identity"].([]interface{})
	if !ok {
		t.Fatalf("%s: evidence.identity missing", name)
	}
	for _, rawID := range identities {
		id := rawID.(map[string]interface{})
		methods, _ := id["methods"].([]interface{})
		for _, rawM := range methods {
			m := rawM.(map[string]interface{})
			if m["technique"] == technique {
				if conf, _ := m["confidence"].(float64); conf == confidence {
					return
				}
				t.Fatalf("%s: technique %s confidence = %v; want %v", name, technique, m["confidence"], confidence)
			}
		}
	}
	t.Fatalf("%s: no identity method with technique %s", name, technique)
}

// assertHasOccurrence fails unless component comp records the given location.
func assertHasOccurrence(t *testing.T, comp map[string]interface{}, name, location string) {
	t.Helper()
	evidence, ok := comp["evidence"].(map[string]interface{})
	if !ok {
		t.Fatalf("%s: evidence missing", name)
	}
	occ, ok := evidence["occurrences"].([]interface{})
	if !ok {
		t.Fatalf("%s: evidence.occurrences missing", name)
	}
	for _, rawO := range occ {
		o := rawO.(map[string]interface{})
		if o["location"] == location {
			return
		}
	}
	t.Fatalf("%s: occurrence %q not found in %v", name, location, occ)
}

// TestExportCycloneDXDoesNotLeakSecrets plants a secret value in the scan
// result and asserts it never appears in the CycloneDX output. The SBOM is an
// inventory of components; secret values from result.Data.Secrets must never
// be serialized into it.
func TestExportCycloneDXDoesNotLeakSecrets(t *testing.T) {
	const plantedSecret = "AKIAIOSFODNN7EXAMPLE_SUPERSECRET"

	job, result := buildCycloneDXFixture()
	result.Data.SecretCount = 1
	result.Data.Secrets = []models.SecretModel{
		{
			Type:             "api_key",
			LineNo:           7,
			FileLocation:     "Payload/example.app/config.plist",
			SecretType:       "AWS_ACCESS_KEY",
			SecretString:     plantedSecret,
			SecretConfidence: "high",
		},
	}

	data, _, err := exportCycloneDX(job, result, nil)
	if err != nil {
		t.Fatalf("exportCycloneDX returned error: %v", err)
	}

	if bytes.Contains(data, []byte(plantedSecret)) {
		t.Fatalf("CycloneDX output leaked the planted secret value %q", plantedSecret)
	}
}

// TestExportResultCycloneDXSBOMAlias verifies the cyclonedx-sbom alias routes
// to the same CycloneDX 1.6 exporter.
func TestExportResultCycloneDXSBOMAlias(t *testing.T) {
	job, result := buildCycloneDXFixture()

	payload, err := json.Marshal(scanResultPayload{Message: result.Message, Data: result.Data})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	job.Result = string(payload)

	data, ct, err := ExportResult(job, ExportFormatCycloneDXSBOM)
	if err != nil {
		t.Fatalf("ExportResult(cyclonedx-sbom) returned error: %v", err)
	}
	if ct != "application/vnd.cyclonedx+json" {
		t.Errorf("content type = %q; want application/vnd.cyclonedx+json", ct)
	}

	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("alias output is not valid JSON: %v", err)
	}
	if bom["specVersion"] != "1.6" {
		t.Errorf("alias specVersion = %v; want 1.6", bom["specVersion"])
	}
	if string(ExportFormatCycloneDXSBOM) != "cyclonedx-sbom" {
		t.Errorf("ExportFormatCycloneDXSBOM = %q; want cyclonedx-sbom", ExportFormatCycloneDXSBOM)
	}
}
