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

// Unit tests for the pure parsing surface of packageparse.go: the package-level
// compiled regexes that ExtractPackageData uses to pull fields out of `aapt dump
// badging` output. ExtractPackageData itself shells out to aapt and is NOT run
// here; only the regex parsing logic (which is fully deterministic) is tested,
// using representative aapt badging lines as fixtures.

import (
	"testing"
)

// firstSubmatch returns the first capture group of the regex against s, or "".
func firstSubmatch(reMatch []string) string {
	if len(reMatch) > 1 {
		return reMatch[1]
	}
	return ""
}

func TestPackageParseRegexes(t *testing.T) {
	// A representative first line of `aapt dump badging` output.
	packageLine := `package: name='com.example.app' versionCode='42' versionName='1.2.3' compileSdkVersion='34' compileSdkVersionCodename='14'`

	tests := []struct {
		name  string
		line  string
		match []string
		want  string
	}{
		{"package name", packageLine, ppPackageName.FindStringSubmatch(packageLine), "com.example.app"},
		{"version code", packageLine, ppVersionCode.FindStringSubmatch(packageLine), "42"},
		{"version name", packageLine, ppVersionName.FindStringSubmatch(packageLine), "1.2.3"},
		{"compile sdk", packageLine, ppCompileSdkVersion.FindStringSubmatch(packageLine), "34"},
		{"sdk version", `sdkVersion:'21'`, ppSdkVersion.FindStringSubmatch(`sdkVersion:'21'`), "21"},
		{"target sdk", `targetSdkVersion:'34'`, ppTargetSdk.FindStringSubmatch(`targetSdkVersion:'34'`), "34"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstSubmatch(tt.match); got != tt.want {
				t.Errorf("%s: parsed %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestPackageParseRegexesNoMatch(t *testing.T) {
	// Lines that should not match must return no submatch (empty extraction).
	tests := []struct {
		name  string
		match []string
	}{
		{"package name missing", ppPackageName.FindStringSubmatch(`package: foo='bar'`)},
		{"version code missing", ppVersionCode.FindStringSubmatch(`package: name='x'`)},
		{"sdk version wrong prefix", ppSdkVersion.FindStringSubmatch(`notSdk:'21'`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstSubmatch(tt.match); got != "" {
				t.Errorf("%s: expected no match, got %q", tt.name, got)
			}
		})
	}
}

func TestQuotedValueRegexMultiValue(t *testing.T) {
	// ppQuotedValue is used to pull every quoted token out of supports-screens,
	// densities, and native-code lines. It must return each quoted value in order.
	line := `native-code: 'armeabi-v7a' 'arm64-v8a' 'x86'`
	matches := ppQuotedValue.FindAllStringSubmatch(line, -1)

	var got []string
	for _, m := range matches {
		if len(m) > 1 {
			got = append(got, m[1])
		}
	}
	want := []string{"armeabi-v7a", "arm64-v8a", "x86"}
	if len(got) != len(want) {
		t.Fatalf("extracted %d values %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("value[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestQuotedValueRegexEmptyLine(t *testing.T) {
	line := `densities:`
	matches := ppQuotedValue.FindAllStringSubmatch(line, -1)
	if len(matches) != 0 {
		t.Errorf("expected no quoted values in %q, got %v", line, matches)
	}
}
