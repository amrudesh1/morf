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

// Unit tests for the pure manifest-parsing helpers in manifest_parser.go. These
// exercise the string/regex logic directly (no aapt invocation): leading-space
// counting, attribute extraction, targetSdk fallback parsing, intent-filter /
// data-block parsing, provider export/authority logic, and the security-default
// setter. They complement manifest_parser_test.go which drives the full
// extract* pipeline against the sample xmltree fixture.

import (
	"os"
	"strings"
	"testing"

	"morf/models"
)

func TestCountLeadingSpaces(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"no indent", "E: activity", 0},
		{"two spaces", "  E: activity", 2},
		{"tabs count", "\t\tE: activity", 2},
		{"mixed tab and space", " \tE: activity", 2},
		{"empty string", "", 0},
		{"only whitespace", "    ", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countLeadingSpaces(tt.in); got != tt.want {
				t.Errorf("countLeadingSpaces(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestExtractAttribute(t *testing.T) {
	tests := []struct {
		name     string
		block    string
		attrName string
		want     string
	}{
		{
			name:     "known scheme attribute",
			block:    `A: android:scheme(0x01010027)="https" (Raw: "https")`,
			attrName: "scheme",
			want:     "https",
		},
		{
			name:     "known host attribute",
			block:    `A: android:host(0x01010028)="example.com" (Raw: "example.com")`,
			attrName: "host",
			want:     "example.com",
		},
		{
			name:     "known path attribute",
			block:    `A: android:path(0x0101002a)="/open" (Raw: "/open")`,
			attrName: "path",
			want:     "/open",
		},
		{
			name:     "unknown attribute uses dynamic fallback",
			block:    `A: android:customAttr(0x01010099)="customval" (Raw: "customval")`,
			attrName: "customAttr",
			want:     "customval",
		},
		{
			name:     "attribute absent returns empty",
			block:    `A: android:host(0x01010028)="example.com"`,
			attrName: "scheme",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractAttribute(tt.block, tt.attrName); got != tt.want {
				t.Errorf("extractAttribute(%q) = %q, want %q", tt.attrName, got, tt.want)
			}
		})
	}
}

func TestExtractTargetSdkFromXMLTree(t *testing.T) {
	tests := []struct {
		name    string
		xmlTree string
		want    int
	}{
		{
			name:    "string format",
			xmlTree: `A: android:targetSdkVersion(0x01010270)="33" (Raw: "33")`,
			want:    33,
		},
		{
			name:    "hex format 0x22 == 34",
			xmlTree: `A: android:targetSdkVersion(0x01010270)=(type 0x10)0x22`,
			want:    34,
		},
		{
			name:    "hex format 0x1e == 30",
			xmlTree: `A: android:targetSdkVersion(0x01010270)=(type 0x10)0x1e`,
			want:    30,
		},
		{
			name:    "absent returns zero",
			xmlTree: `A: android:name(0x01010003)="com.example"`,
			want:    0,
		},
		{
			name:    "string format preferred and parseable",
			xmlTree: "A: android:targetSdkVersion(0x01010270)=\"31\" (Raw: \"31\")\nA: android:targetSdkVersion(0x01010270)=(type 0x10)0x22",
			want:    31,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTargetSdkFromXMLTree(tt.xmlTree); got != tt.want {
				t.Errorf("extractTargetSdkFromXMLTree() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProcessDataBlock(t *testing.T) {
	tests := []struct {
		name      string
		dataBlock string
		wantAdded bool
		check     func(t *testing.T, d models.ManifestFilterData)
	}{
		{
			name: "scheme and host",
			dataBlock: `E: data
  A: android:scheme(0x01010027)="myapp" (Raw: "myapp")
  A: android:host(0x01010028)="open" (Raw: "open")`,
			wantAdded: true,
			check: func(t *testing.T, d models.ManifestFilterData) {
				if d.Scheme != "myapp" {
					t.Errorf("scheme = %q, want myapp", d.Scheme)
				}
				if d.Host != "open" {
					t.Errorf("host = %q, want open", d.Host)
				}
			},
		},
		{
			name: "pathPrefix appended",
			dataBlock: `E: data
  A: android:scheme(0x01010027)="https" (Raw: "https")
  A: android:pathPrefix(0x0101002c)="/deep" (Raw: "/deep")`,
			wantAdded: true,
			check: func(t *testing.T, d models.ManifestFilterData) {
				if len(d.PathPrefix) != 1 || d.PathPrefix[0] != "/deep" {
					t.Errorf("pathPrefix = %v, want [/deep]", d.PathPrefix)
				}
			},
		},
		{
			name:      "empty data block adds nothing",
			dataBlock: `E: data`,
			wantAdded: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &models.ManifestFilter{}
			processDataBlock(tt.dataBlock, filter)
			if tt.wantAdded {
				if len(filter.Data) != 1 {
					t.Fatalf("expected 1 data element added, got %d", len(filter.Data))
				}
				if tt.check != nil {
					tt.check(t, filter.Data[0])
				}
			} else {
				if len(filter.Data) != 0 {
					t.Errorf("expected no data element added, got %d", len(filter.Data))
				}
			}
		})
	}
}

func TestProcessIntentFilterBlock(t *testing.T) {
	t.Run("action category and data with autoVerify", func(t *testing.T) {
		block := `E: intent-filter
  A: android:autoVerify(0x01010568)=(type 0x12)0xffffffff
  E: action
    A: android:name(0x01010003)="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
  E: category
    A: android:name(0x01010003)="android.intent.category.DEFAULT" (Raw: "android.intent.category.DEFAULT")
  E: data
    A: android:scheme(0x01010027)="https" (Raw: "https")
    A: android:host(0x01010028)="app.example.com" (Raw: "app.example.com")`

		filter := processIntentFilterBlock(block)
		if filter == nil {
			t.Fatal("processIntentFilterBlock returned nil for a non-empty filter")
		}
		if !filter.AutoVerify {
			t.Error("expected AutoVerify=true")
		}
		if len(filter.Actions) != 1 || filter.Actions[0] != "android.intent.action.VIEW" {
			t.Errorf("actions = %v, want [android.intent.action.VIEW]", filter.Actions)
		}
		if len(filter.Categories) != 1 || filter.Categories[0] != "android.intent.category.DEFAULT" {
			t.Errorf("categories = %v, want [android.intent.category.DEFAULT]", filter.Categories)
		}
		if len(filter.Data) != 1 || filter.Data[0].Scheme != "https" || filter.Data[0].Host != "app.example.com" {
			t.Errorf("data = %+v, want scheme=https host=app.example.com", filter.Data)
		}
	})

	t.Run("empty filter returns nil", func(t *testing.T) {
		block := `E: intent-filter`
		if filter := processIntentFilterBlock(block); filter != nil {
			t.Errorf("expected nil for empty intent-filter, got %+v", filter)
		}
	})
}

func TestExtractIntentFiltersMultipleSiblings(t *testing.T) {
	// Finding 016: consecutive sibling intent-filters within one component must
	// each be captured, not overwritten so only the last survives.
	block := `E: activity
  A: android:name(0x01010003)="com.example.MainActivity" (Raw: "com.example.MainActivity")
  E: intent-filter
    E: action
      A: android:name(0x01010003)="android.intent.action.MAIN" (Raw: "android.intent.action.MAIN")
  E: intent-filter
    E: action
      A: android:name(0x01010003)="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
    E: data
      A: android:scheme(0x01010027)="myapp" (Raw: "myapp")`

	filters := extractIntentFilters(block)
	if len(filters) != 2 {
		t.Fatalf("expected 2 intent filters, got %d", len(filters))
	}

	// Collect actions across both filters to assert both were parsed.
	var actions []string
	for _, f := range filters {
		actions = append(actions, f.Actions...)
	}
	joined := strings.Join(actions, ",")
	if !strings.Contains(joined, "android.intent.action.MAIN") {
		t.Errorf("expected MAIN action across filters, got %q", joined)
	}
	if !strings.Contains(joined, "android.intent.action.VIEW") {
		t.Errorf("expected VIEW action across filters, got %q", joined)
	}
}

func TestExtractProvidersFromSample(t *testing.T) {
	// Provider-specific assertions against the fixture: authorities parsing and
	// grantUriPermissions reported independently of the exported signal (018).
	xmlTree, err := os.ReadFile("sample_xmltree.txt")
	if err != nil {
		t.Fatalf("failed to read sample xmltree fixture: %v", err)
	}
	lines := strings.Split(string(xmlTree), "\n")
	providers := extractProviders(lines, 34)
	if len(providers) == 0 {
		t.Fatal("expected providers extracted from sample, got 0")
	}

	byName := make(map[string]models.ManifestProviderInfo, len(providers))
	for _, p := range providers {
		byName[p.Name] = p
	}

	// FileProvider in the fixture declares grantUriPermissions and exported=0x0.
	fp, ok := byName["androidx.core.content.FileProvider"]
	if !ok {
		t.Fatal("androidx.core.content.FileProvider not found among extracted providers")
	}
	if fp.Exported {
		t.Errorf("FileProvider expected exported=false, got true")
	}
	if !fp.GrantUriPermissions {
		t.Errorf("FileProvider expected grantUriPermissions=true, got false")
	}
	if len(fp.Authorities) == 0 {
		t.Errorf("FileProvider expected non-empty authorities, got %v", fp.Authorities)
	}
}

func TestExtractProvidersDefaultExportByTargetSdk(t *testing.T) {
	// Finding 018: a provider with no explicit android:exported defaults to
	// exported=true for targetSdk < 17 and false for >= 17.
	block := []string{
		`E: application`,
		`  E: provider (line=1)`,
		`    A: android:name(0x01010003)="com.example.LegacyProvider" (Raw: "com.example.LegacyProvider")`,
		`    A: android:authorities(0x01010018)="com.example.legacy" (Raw: "com.example.legacy")`,
	}

	tests := []struct {
		name         string
		targetSdk    int
		wantExported bool
	}{
		{"legacy sdk 16 defaults exported true", 16, true},
		{"modern sdk 17 defaults exported false", 17, false},
		{"modern sdk 34 defaults exported false", 34, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providers := extractProviders(block, tt.targetSdk)
			if len(providers) != 1 {
				t.Fatalf("expected 1 provider, got %d", len(providers))
			}
			if providers[0].Exported != tt.wantExported {
				t.Errorf("targetSdk=%d: exported = %v, want %v", tt.targetSdk, providers[0].Exported, tt.wantExported)
			}
		})
	}
}

func TestSetDefaultExportedValues(t *testing.T) {
	// The safety fallback (used when aapt xmltree cannot be dumped) must reset
	// every component's Exported flag to false while preserving names.
	metadata := &models.MetaDataModel{}
	metadata.AndroidManifest.Activities = models.JSONComponentArray[models.ManifestActivityInfo]{
		{Name: "A1", Exported: true},
		{Name: "A2", Exported: true},
	}
	metadata.AndroidManifest.Services = models.JSONComponentArray[models.ManifestServiceInfo]{
		{Name: "S1", Exported: true},
	}
	metadata.AndroidManifest.BroadcastReceivers = models.JSONComponentArray[models.ManifestReceiverInfo]{
		{Name: "R1", Exported: true},
	}
	metadata.AndroidManifest.ContentProviders = models.JSONComponentArray[models.ManifestProviderInfo]{
		{Name: "P1", Exported: true},
	}

	setDefaultExportedValues(metadata)

	for _, a := range metadata.AndroidManifest.Activities {
		if a.Exported {
			t.Errorf("activity %s expected exported=false after default reset", a.Name)
		}
	}
	if metadata.AndroidManifest.Activities[0].Name != "A1" || metadata.AndroidManifest.Activities[1].Name != "A2" {
		t.Error("activity names should be preserved by setDefaultExportedValues")
	}
	for _, s := range metadata.AndroidManifest.Services {
		if s.Exported {
			t.Errorf("service %s expected exported=false", s.Name)
		}
	}
	for _, r := range metadata.AndroidManifest.BroadcastReceivers {
		if r.Exported {
			t.Errorf("receiver %s expected exported=false", r.Name)
		}
	}
	for _, p := range metadata.AndroidManifest.ContentProviders {
		if p.Exported {
			t.Errorf("provider %s expected exported=false", p.Name)
		}
	}
}

func TestExtractComponentBlocksIgnoresOutsideApplication(t *testing.T) {
	// extractComponentBlocks must only harvest components nested inside the
	// application element and must skip blocks lacking an android:name.
	lines := []string{
		`E: manifest`,
		`  E: uses-permission`,
		`    A: android:name(0x01010003)="android.permission.INTERNET"`,
		`  E: application`,
		`    E: activity (line=10)`,
		`      A: android:name(0x01010003)="com.example.Main" (Raw: "com.example.Main")`,
		`    E: activity (line=20)`,
		`      A: android:label(0x01010001)="NoName"`,
	}
	blocks := extractComponentBlocks(lines, "activity")
	if len(blocks) != 1 {
		t.Fatalf("expected 1 activity block (the one with android:name), got %d", len(blocks))
	}
	if !strings.Contains(blocks[0], "com.example.Main") {
		t.Errorf("extracted block does not contain expected activity name: %q", blocks[0])
	}
}
