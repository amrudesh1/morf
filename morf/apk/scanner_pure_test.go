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

// Unit tests for the STABLE, pure helpers in scanner.go that do not shell out
// to java/apktool/rg. These cover: JVM heap flag derivation, tools-dir/jar path
// resolution, the secret-value extraction heuristic, the SanitizeSecrets dedup
// key logic, and the combined-regex pattern attribution (response shaping).

import (
	"path/filepath"
	"regexp"
	"testing"

	"morf/models"
)

func TestJVMHeapFlag(t *testing.T) {
	tests := []struct {
		name   string
		envVal string // "" means unset
		setEnv bool
		want   string
	}{
		{name: "default when unset", setEnv: false, want: "-Xmx2048m"},
		{name: "explicit override", setEnv: true, envVal: "4096", want: "-Xmx4096m"},
		{name: "empty falls back to default", setEnv: true, envVal: "", want: "-Xmx2048m"},
		{name: "non-numeric falls back to default", setEnv: true, envVal: "abc", want: "-Xmx2048m"},
		{name: "zero falls back to default", setEnv: true, envVal: "0", want: "-Xmx2048m"},
		{name: "negative falls back to default", setEnv: true, envVal: "-1", want: "-Xmx2048m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("MORF_JVM_MAX_HEAP_MB", tt.envVal)
			} else {
				// Ensure a clean environment for the default case.
				t.Setenv("MORF_JVM_MAX_HEAP_MB", "")
			}
			if got := jvmHeapFlag(); got != tt.want {
				t.Errorf("jvmHeapFlag() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestToolsDirAndJars(t *testing.T) {
	tests := []struct {
		name             string
		envVal           string
		setEnv           bool
		wantDir          string
		wantApktoolBase  string
		wantAnalyzerBase string
	}{
		{
			name:             "default tools dir",
			setEnv:           true,
			envVal:           "",
			wantDir:          "/app/tools",
			wantApktoolBase:  "apktool.jar",
			wantAnalyzerBase: "apkanalyzer.jar",
		},
		{
			name:             "custom tools dir",
			setEnv:           true,
			envVal:           "/custom/tools",
			wantDir:          "/custom/tools",
			wantApktoolBase:  "apktool.jar",
			wantAnalyzerBase: "apkanalyzer.jar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MORF_TOOLS_DIR", tt.envVal)
			if got := toolsDir(); got != tt.wantDir {
				t.Errorf("toolsDir() = %q, want %q", got, tt.wantDir)
			}
			if got := apktoolJar(); got != filepath.Join(tt.wantDir, tt.wantApktoolBase) {
				t.Errorf("apktoolJar() = %q, want %q", got, filepath.Join(tt.wantDir, tt.wantApktoolBase))
			}
			if got := apkanalyzerJar(); got != filepath.Join(tt.wantDir, tt.wantAnalyzerBase) {
				t.Errorf("apkanalyzerJar() = %q, want %q", got, filepath.Join(tt.wantDir, tt.wantAnalyzerBase))
			}
		})
	}
}

func TestExtractSecret(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "value between XML tags",
			content: `<string name="api_key">SECRETVALUE</string>`,
			want:    "SECRETVALUE",
		},
		{
			name:    "value between quotes",
			content: `apiKey = "abc123def"`,
			want:    "abc123def",
		},
		{
			name:    "value after last colon",
			content: `token: xyz789`,
			want:    "xyz789",
		},
		{
			name:    "plain content fallback",
			content: `justatoken`,
			want:    "justatoken",
		},
		{
			name:    "quotes take precedence over colon",
			content: `key: "quotedvalue"`,
			want:    "quotedvalue",
		},
		{
			name:    "xml tags take precedence",
			content: `<item>colon:inside</item>`,
			want:    "colon:inside",
		},
		{
			name:    "empty content",
			content: ``,
			want:    ``,
		},
		{
			name:    "trims whitespace after colon",
			content: `password:    padded   `,
			want:    "padded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractSecret(tt.content); got != tt.want {
				t.Errorf("extractSecret(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

func TestSanitizeSecretsDedup(t *testing.T) {
	tests := []struct {
		name  string
		input []models.SecretModel
		want  int // expected number of surviving (unique) secrets
	}{
		{
			name:  "empty input",
			input: nil,
			want:  0,
		},
		{
			name: "exact duplicate collapses",
			input: []models.SecretModel{
				{FileLocation: "a.xml", LineNo: 10, SecretString: "s1"},
				{FileLocation: "a.xml", LineNo: 10, SecretString: "s1"},
			},
			want: 1,
		},
		{
			name: "same value different file kept",
			input: []models.SecretModel{
				{FileLocation: "a.xml", LineNo: 10, SecretString: "shared"},
				{FileLocation: "b.xml", LineNo: 10, SecretString: "shared"},
			},
			want: 2,
		},
		{
			name: "same value different line kept",
			input: []models.SecretModel{
				{FileLocation: "a.xml", LineNo: 10, SecretString: "shared"},
				{FileLocation: "a.xml", LineNo: 11, SecretString: "shared"},
			},
			want: 2,
		},
		{
			name: "same location different value kept",
			input: []models.SecretModel{
				{FileLocation: "a.xml", LineNo: 10, SecretString: "v1"},
				{FileLocation: "a.xml", LineNo: 10, SecretString: "v2"},
			},
			want: 2,
		},
		{
			name: "empty-value matches at different locations not collapsed",
			input: []models.SecretModel{
				{FileLocation: "a.xml", LineNo: 1, SecretString: ""},
				{FileLocation: "b.xml", LineNo: 2, SecretString: ""},
			},
			want: 2,
		},
		{
			name: "empty-value duplicate at same location collapses",
			input: []models.SecretModel{
				{FileLocation: "a.xml", LineNo: 1, SecretString: ""},
				{FileLocation: "a.xml", LineNo: 1, SecretString: ""},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeSecrets(tt.input)
			if len(got) != tt.want {
				t.Errorf("SanitizeSecrets() returned %d secrets, want %d", len(got), tt.want)
			}
		})
	}
}

func TestSanitizeSecretsPreservesFirstOccurrence(t *testing.T) {
	// The first occurrence of a duplicate key should be the one preserved,
	// along with all of its non-key fields.
	input := []models.SecretModel{
		{Type: "aws", FileLocation: "a.xml", LineNo: 10, SecretString: "s1", SecretConfidence: "high"},
		{Type: "gcp", FileLocation: "a.xml", LineNo: 10, SecretString: "s1", SecretConfidence: "low"},
	}
	got := SanitizeSecrets(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 secret after dedup, got %d", len(got))
	}
	if got[0].Type != "aws" || got[0].SecretConfidence != "high" {
		t.Errorf("expected first occurrence (aws/high) preserved, got %+v", got[0])
	}
}

// buildPatternInfo compiles a regex into a PatternInfo, matching how the
// production loader populates the Compiled field.
func buildPatternInfo(name, confidence, regex string) PatternInfo {
	return PatternInfo{
		Name:       name,
		Regex:      regex,
		Confidence: confidence,
		Compiled:   regexp.MustCompile(regex),
	}
}

func TestBuildCombinedRegexAndAttribution(t *testing.T) {
	patterns := []PatternInfo{
		buildPatternInfo("aws_key", "high", `AKIA[0-9A-Z]{4}`),
		buildPatternInfo("slack_token", "high", `xoxb-[0-9]{3}`),
		// A pattern with an internal capture group to verify group-index mapping.
		buildPatternInfo("prefixed", "medium", `PREFIX-(abc|def)`),
	}

	combined, groupToPattern := scBuildCombinedRegex(patterns)
	if combined == nil {
		t.Fatal("scBuildCombinedRegex returned nil combined regex for compilable patterns")
	}
	if len(groupToPattern) < 1 || groupToPattern[0] != -1 {
		t.Fatalf("groupToPattern[0] should be -1 (whole match), got %v", groupToPattern)
	}

	cache := &scPatternCache{
		patterns:       patterns,
		combined:       combined,
		groupToPattern: groupToPattern,
	}

	tests := []struct {
		name         string
		content      string
		wantName     string // "" means expect nil
		wantNilMatch bool
	}{
		{name: "attributes aws", content: "key=AKIA1234ABCD end", wantName: "aws_key"},
		{name: "attributes slack", content: "token xoxb-123", wantName: "slack_token"},
		{name: "attributes pattern with inner group", content: "PREFIX-abc", wantName: "prefixed"},
		{name: "no match returns nil", content: "nothing here", wantNilMatch: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.findMatchingPattern(tt.content)
			if tt.wantNilMatch {
				if got != nil {
					t.Errorf("findMatchingPattern(%q) = %+v, want nil", tt.content, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("findMatchingPattern(%q) = nil, want %q", tt.content, tt.wantName)
			}
			if got.Name != tt.wantName {
				t.Errorf("findMatchingPattern(%q) attributed to %q, want %q", tt.content, got.Name, tt.wantName)
			}
		})
	}
}

func TestBuildCombinedRegexNoCompilablePatterns(t *testing.T) {
	// When no pattern is RE2-compilable (Compiled == nil), the combined regex
	// cannot be built and both return values must be nil.
	patterns := []PatternInfo{
		{Name: "noncompilable", Regex: `(?=lookahead)`, Compiled: nil},
	}
	combined, groupToPattern := scBuildCombinedRegex(patterns)
	if combined != nil || groupToPattern != nil {
		t.Errorf("scBuildCombinedRegex with no compilable patterns = (%v, %v), want (nil, nil)", combined, groupToPattern)
	}
}

func TestFindMatchingPatternFallbackToNonRE2(t *testing.T) {
	// combined is nil (no RE2-compilable patterns). findMatchingPattern must fall
	// back and attribute a hit to the first non-RE2 (Compiled==nil) pattern as a
	// best effort, per the row-028 sentinel logic.
	patterns := []PatternInfo{
		{Name: "non_re2_pattern", Regex: `(?=x)`, Compiled: nil},
	}
	cache := &scPatternCache{
		patterns:       patterns,
		combined:       nil,
		groupToPattern: nil,
	}
	got := cache.findMatchingPattern("anything at all")
	if got == nil {
		t.Fatal("expected fallback attribution to first non-RE2 pattern, got nil")
	}
	if got.Name != "non_re2_pattern" {
		t.Errorf("fallback attributed to %q, want %q", got.Name, "non_re2_pattern")
	}
}

func TestFindMatchingPatternPerPatternFallbackWhenCombinedNil(t *testing.T) {
	// combined nil but there IS a compilable pattern: the safety-net per-pattern
	// scan should attribute the match.
	patterns := []PatternInfo{
		buildPatternInfo("digits", "low", `[0-9]{4}`),
	}
	cache := &scPatternCache{
		patterns:       patterns,
		combined:       nil, // simulate combined-build failure
		groupToPattern: nil,
	}
	got := cache.findMatchingPattern("value=1234")
	if got == nil || got.Name != "digits" {
		t.Fatalf("per-pattern fallback: got %+v, want name=digits", got)
	}

	// A line matching nothing, with no non-RE2 pattern present, returns nil.
	if none := cache.findMatchingPattern("no digits here"); none != nil {
		t.Errorf("expected nil for non-matching line, got %+v", none)
	}
}
