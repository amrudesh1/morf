package detect

import (
	"slices"
	"testing"
)

// TestBuildRgArgs verifies the ripgrep arg shaping: the default (text pass off)
// stays byte-for-byte the historical ScanCorpus arg list, and enabling Text
// inserts exactly one "-a" flag before the excludes while ExtraExcludes are
// appended after the default excludes and before the roots.
func TestBuildRgArgs(t *testing.T) {
	const patternFile = "/tmp/morf-patterns-xyz.txt"
	excludeGlobs := []string{"-g", "!**/res/drawable*/**"}
	roots := []string{"/ws/source", "/ws/appres"}

	tests := []struct {
		name string
		opts ScanOptions
		want []string
	}{
		{
			name: "text off is the line-bounded (no --multiline) arg list",
			opts: ScanOptions{},
			want: []string{
				"-n", "--file", patternFile,
				"-g", "!**/res/drawable*/**",
				"/ws/source", "/ws/appres",
			},
		},
		{
			name: "text on inserts -a and -o before excludes",
			opts: ScanOptions{Text: true},
			want: []string{
				"-n", "--file", patternFile, "-a", "-o",
				"-g", "!**/res/drawable*/**",
				"/ws/source", "/ws/appres",
			},
		},
		{
			name: "extra excludes appended after defaults, before roots",
			opts: ScanOptions{Text: true, ExtraExcludes: []string{"-g", "!**/smali*/**"}},
			want: []string{
				"-n", "--file", patternFile, "-a", "-o",
				"-g", "!**/res/drawable*/**",
				"-g", "!**/smali*/**",
				"/ws/source", "/ws/appres",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRgArgs(patternFile, excludeGlobs, roots, tt.opts)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("buildRgArgs() =\n  %v\nwant\n  %v", got, tt.want)
			}
		})
	}
}

// TestBuildRgArgs_TextFlagCount guards the load-bearing gap: the binary-safe
// pass must add -a exactly once, and the default (text) pass must never add it.
func TestBuildRgArgs_TextFlagCount(t *testing.T) {
	count := func(args []string) int {
		n := 0
		for _, a := range args {
			if a == "-a" {
				n++
			}
		}
		return n
	}
	if n := count(buildRgArgs("p", nil, nil, ScanOptions{})); n != 0 {
		t.Fatalf("text-off pass added -a %d times, want 0", n)
	}
	if n := count(buildRgArgs("p", nil, nil, ScanOptions{Text: true})); n != 1 {
		t.Fatalf("text-on pass added -a %d times, want 1", n)
	}
}

// TestBuildRgArgs_MaxFileSize guards PERF-2: when the binary (Text) pass sets
// MaxFileSizeMB, ripgrep gets --max-filesize so it SKIPS oversized native blobs
// (e.g. a 100 MB+ Flutter libapp.so whose dense -a/-o match output otherwise
// pins per-match attribution). The text pass (MaxFileSizeMB unset/0) never caps.
func TestBuildRgArgs_MaxFileSize(t *testing.T) {
	// Text pass with a cap: --max-filesize present with the MB suffix.
	got := buildRgArgs("p", nil, nil, ScanOptions{Text: true, MaxFileSizeMB: 50})
	if !slices.Contains(got, "--max-filesize") {
		t.Fatalf("text pass with MaxFileSizeMB=50 missing --max-filesize: %v", got)
	}
	for i, a := range got {
		if a == "--max-filesize" {
			if i+1 >= len(got) || got[i+1] != "50M" {
				t.Fatalf("--max-filesize value = %v, want 50M", got[i+1:])
			}
		}
	}
	// No cap (0) => flag absent (default text-pass behavior preserved).
	if slices.Contains(buildRgArgs("p", nil, nil, ScanOptions{Text: true}), "--max-filesize") {
		t.Error("text pass without MaxFileSizeMB must not set --max-filesize")
	}
	// Non-text pass never caps even if a value leaks in.
	if slices.Contains(buildRgArgs("p", nil, nil, ScanOptions{MaxFileSizeMB: 50}), "--max-filesize") {
		t.Error("non-text pass must not set --max-filesize")
	}
}
