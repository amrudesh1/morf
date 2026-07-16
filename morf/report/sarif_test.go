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

package report

import (
	"encoding/json"
	"strings"
	"testing"

	"morf/models"
)

func sampleSecrets() []models.SecretModel {
	return []models.SecretModel{
		{
			Type:               "secret",
			LineNo:             42,
			FileLocation:       "assets/config.json",
			SecretType:         "AWS Access Key ID",
			SecretString:       "AKIAIOSFODNN7EXAMPLE",
			SecretConfidence:   "high",
			Score:              0.95,
			Tier:               "keep",
			VerificationStatus: "unchecked",
			MASVSID:            "MASVS-CRYPTO-1",
		},
		{
			Type:             "secret",
			LineNo:           7,
			FileLocation:     "res/values/strings.xml",
			SecretType:       "Google API Key",
			SecretString:     "AIzaSyExampleKeyValue1234567890abcdefghij",
			SecretConfidence: "medium",
			Tier:             "info",
		},
		{
			Type:             "secret",
			LineNo:           1,
			FileLocation:     "classes.dex",
			SecretType:       "AWS Access Key ID",
			SecretString:     "AKIAJUSTANOTHERONE12",
			SecretConfidence: "high",
			Tier:             "keep",
		},
	}
}

func TestEncodeSARIF_ValidDocument(t *testing.T) {
	secrets := sampleSecrets()

	out, err := EncodeSARIF("com.example.app", "android", secrets)
	if err != nil {
		t.Fatalf("EncodeSARIF returned error: %v", err)
	}

	// Must be valid JSON.
	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if v, _ := doc["version"].(string); v != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", v)
	}
	if _, ok := doc["$schema"]; !ok {
		t.Errorf("missing $schema field")
	}

	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]interface{})

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if name, _ := driver["name"].(string); name != "MORF" {
		t.Errorf("driver.name = %q, want MORF", name)
	}

	rules, ok := driver["rules"].([]interface{})
	if !ok || len(rules) == 0 {
		t.Fatalf("expected non-empty rules, got %v", driver["rules"])
	}
	// Two distinct secret types => two rules.
	if len(rules) != 2 {
		t.Errorf("expected 2 distinct rules, got %d", len(rules))
	}

	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatalf("results is not an array: %v", run["results"])
	}
	if len(results) != len(secrets) {
		t.Errorf("expected %d results (one per finding), got %d", len(secrets), len(results))
	}
}

func TestEncodeSARIF_RedactsRawValues(t *testing.T) {
	secrets := sampleSecrets()

	out, err := EncodeSARIF("com.example.app", "ios", secrets)
	if err != nil {
		t.Fatalf("EncodeSARIF returned error: %v", err)
	}

	rendered := string(out)
	for _, s := range secrets {
		if strings.Contains(rendered, s.SecretString) {
			t.Errorf("raw secret value %q leaked into SARIF output", s.SecretString)
		}
	}

	// The masked form should still appear so findings remain correlatable.
	if !strings.Contains(rendered, "masked:") {
		t.Errorf("expected masked message marker in output")
	}
}

func TestEncodeSARIF_RuleCarriesMASVSTag(t *testing.T) {
	secrets := sampleSecrets()

	out, err := EncodeSARIF("com.example.app", "android", secrets)
	if err != nil {
		t.Fatalf("EncodeSARIF returned error: %v", err)
	}

	var parsed sarifLog
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal into sarifLog: %v", err)
	}

	found := false
	for _, rule := range parsed.Runs[0].Tool.Driver.Rules {
		if rule.ID != "AWS Access Key ID" {
			continue
		}
		if rule.Properties == nil {
			continue
		}
		for _, tag := range rule.Properties.Tags {
			if tag == "MASVS-CRYPTO-1" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected AWS Access Key ID rule to carry MASVS-CRYPTO-1 tag")
	}
}

func TestEncodeSARIF_LevelMapping(t *testing.T) {
	secrets := []models.SecretModel{
		{SecretType: "A", SecretString: "xxxxxx", Tier: "keep", FileLocation: "f", LineNo: 1},
		{SecretType: "B", SecretString: "yyyyyy", Tier: "info", FileLocation: "f", LineNo: 2},
		{SecretType: "C", SecretString: "zzzzzz", Tier: "", FileLocation: "f", LineNo: 3},
	}

	out, err := EncodeSARIF("t", "android", secrets)
	if err != nil {
		t.Fatalf("EncodeSARIF returned error: %v", err)
	}
	var parsed sarifLog
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]string{"A": "error", "B": "note", "C": "warning"}
	for _, r := range parsed.Runs[0].Results {
		if want[r.RuleID] != r.Level {
			t.Errorf("rule %s level = %q, want %q", r.RuleID, r.Level, want[r.RuleID])
		}
	}
}

// TestMaskResultJSON verifies the result-envelope masker replaces secretString
// values with a masked preview, preserves other fields/structure, and fails
// closed (returns an error, no bytes) on unparseable input.
func TestMaskResultJSON(t *testing.T) {
	in := `{"data":{"fileName":"app.apk","packageName":"com.x","secrets":[` +
		`{"secretType":"AWS API Key","secretString":"AKIAIOSFODNN7EXAMPLE","lineNo":10},` +
		`{"secretType":"Google API Key","secretString":"AIzaSyD-EXAMPLE"}]}}`

	out, err := MaskResultJSON([]byte(in))
	if err != nil {
		t.Fatalf("MaskResultJSON error: %v", err)
	}
	var env struct {
		Data struct {
			FileName    string `json:"fileName"`
			PackageName string `json:"packageName"`
			Secrets     []struct {
				SecretType   string `json:"secretType"`
				SecretString string `json:"secretString"`
				LineNo       int    `json:"lineNo"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal masked output: %v", err)
	}
	// Non-secret fields preserved.
	if env.Data.FileName != "app.apk" || env.Data.PackageName != "com.x" {
		t.Errorf("metadata not preserved: %+v", env.Data)
	}
	if env.Data.Secrets[0].LineNo != 10 || env.Data.Secrets[0].SecretType != "AWS API Key" {
		t.Errorf("secret metadata not preserved: %+v", env.Data.Secrets[0])
	}
	// Raw values must be gone; masked values must be present.
	for _, s := range env.Data.Secrets {
		if s.SecretString == "AKIAIOSFODNN7EXAMPLE" || s.SecretString == "AIzaSyD-EXAMPLE" {
			t.Errorf("secretString was NOT masked: %q", s.SecretString)
		}
		if !strings.Contains(s.SecretString, "…") {
			t.Errorf("masked value missing ellipsis: %q", s.SecretString)
		}
	}

	// Fail closed on invalid JSON.
	if _, err := MaskResultJSON([]byte("not json")); err == nil {
		t.Error("MaskResultJSON on invalid JSON: want error, got nil")
	}
}
