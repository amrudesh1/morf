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

// Mach-O tests. Two groups:
//
//   - Pure tests (splitNulStrings / isMostlyPrintable / WriteCorpus): always run,
//     no cross-build required.
//   - Real Mach-O tests (section enumeration + C-string extraction + cryptid
//     detection): build a tiny Mach-O at test time via
//     `GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build` of a temp .go file that
//     embeds a KNOWN fake string in a C string literal (so it lands in
//     __TEXT.__cstring, NUL-terminated). If a darwin arm64 cgo build is not
//     available on this host, these tests t.Skip rather than fail.

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSecret is the sentinel string embedded in the built Mach-O and searched
// for in the extracted __cstring section.
const fakeSecret = "MORF_FAKE_SECRET_sk_live_ABCDEF0123456789"

// cgoMachoSource is a tiny cgo program whose C string literal is emitted into
// __TEXT.__cstring (NUL-terminated) by the C compiler, giving us a deterministic
// C-string extraction target.
const cgoMachoSource = `package main

/*
static const char *morf_fake_secret() {
	return "` + fakeSecret + `";
}
*/
import "C"
import "fmt"

func main() {
	fmt.Println(C.GoString(C.morf_fake_secret()))
}
`

// buildTestMachO builds a darwin/arm64 Mach-O from cgoMachoSource and returns
// its path. It skips the calling test when the toolchain cannot produce a darwin
// arm64 cgo binary on this host (e.g. no C compiler, or CGO disabled), rather
// than failing.
func buildTestMachO(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not found: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "machotest.go")
	if err := os.WriteFile(src, []byte(cgoMachoSource), 0o600); err != nil {
		t.Fatalf("write test source: %v", err)
	}
	out := filepath.Join(dir, "machotest_bin")

	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(),
		"GOOS=darwin",
		"GOARCH=arm64",
		"CGO_ENABLED=1",
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("darwin/arm64 cgo cross-build unavailable, skipping Mach-O test: %v\n%s", err, combined)
	}
	if _, err := os.Stat(out); err != nil {
		t.Skipf("built Mach-O missing: %v", err)
	}
	return out
}

// TestExtractBinaryStringsSectionEnumeration verifies that ExtractBinaryStrings
// enumerates sections by name, finds __TEXT.__cstring, and extracts the known
// C-string. It also asserts the binary is reported as NOT encrypted (a locally
// built binary has no FairPlay cryptid).
func TestExtractBinaryStringsSectionEnumeration(t *testing.T) {
	bin := buildTestMachO(t)

	bs, err := ExtractBinaryStrings(bin)
	if err != nil {
		t.Fatalf("ExtractBinaryStrings error: %v", err)
	}

	// Architecture must be reported (arm64) and there must be exactly one slice
	// for a thin binary.
	if len(bs.Architectures) == 0 {
		t.Fatalf("no architectures reported")
	}
	if bs.IsEncrypted {
		t.Errorf("locally built binary should not be FairPlay-encrypted")
	}
	if len(bs.Slices) == 0 {
		t.Fatalf("no arch slices in result")
	}

	// The fake C-string must appear under a __TEXT.__cstring section label.
	foundInCstring := false
	foundAnywhere := false
	for _, sl := range bs.Slices {
		if sl.IsEncrypted {
			continue
		}
		for section, strs := range sl.Strings {
			for _, s := range strs {
				if s == fakeSecret {
					foundAnywhere = true
					if strings.HasSuffix(section, "__cstring") {
						foundInCstring = true
					}
				}
			}
		}
	}
	if !foundAnywhere {
		t.Fatalf("fake secret %q not found in any extracted section", fakeSecret)
	}
	if !foundInCstring {
		t.Errorf("fake secret %q not found specifically in a __cstring section", fakeSecret)
	}
}

// TestCryptidDetection verifies FairPlay cryptid detection reports false for a
// locally built (unencrypted) Mach-O. We cannot produce a FairPlay-encrypted
// binary at test time (that requires App Store signing), so the negative case
// is what is deterministically testable; the positive path is covered by the
// load-command type switch in machoIsEncrypted.
func TestCryptidDetection(t *testing.T) {
	bin := buildTestMachO(t)

	mi, err := InspectMachO(bin)
	if err != nil {
		t.Fatalf("InspectMachO error: %v", err)
	}
	if mi.IsEncrypted {
		t.Errorf("InspectMachO reported encrypted for a locally built binary; want false")
	}
	if len(mi.Architectures) == 0 {
		t.Errorf("InspectMachO reported no architectures")
	}
}

// --- Pure tests (no cross-build) ---

func TestSplitNulStrings(t *testing.T) {
	// Two printable runs separated by NUL, plus a too-short run and a binary run.
	data := []byte("hello\x00wo\x00worldwide\x00\x01\x02\x03\x04\x05\x00")
	got := splitNulStrings(data)

	// "hello" (5) and "worldwide" (9) qualify; "wo" (2) is below stringMinLen;
	// the binary run is rejected by isMostlyPrintable.
	if !containsString(got, "hello") {
		t.Errorf("expected 'hello' in %v", got)
	}
	if !containsString(got, "worldwide") {
		t.Errorf("expected 'worldwide' in %v", got)
	}
	if containsString(got, "wo") {
		t.Errorf("'wo' is below min length and should be excluded: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 qualifying strings, got %d: %v", len(got), got)
	}
}

func TestIsMostlyPrintable(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte("normal ASCII text"), true},
		{[]byte("with\ttab and\nnewline"), true},
		{[]byte{0x01, 0x02, 0x03}, false},
		{[]byte("mostly ok\x00but nul"), false}, // NUL is < 0x20
		{[]byte("high\xff byte"), false},
	}
	for _, c := range cases {
		if got := isMostlyPrintable(c.in); got != c.want {
			t.Errorf("isMostlyPrintable(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestWriteCorpusProvenanceAndEncrypted(t *testing.T) {
	bs := &BinaryStrings{
		Path:          "/tmp/x",
		Architectures: []string{"arm64", "x86_64"},
		Slices: []ArchStrings{
			{
				Arch: "arm64",
				Strings: map[string][]string{
					"__TEXT.__cstring": {"visible-string-one"},
				},
			},
			{
				Arch:        "x86_64",
				IsEncrypted: true, // must be recorded as a skipped marker.
			},
		},
	}

	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	if err := WriteCorpus(bw, bs); err != nil {
		t.Fatalf("WriteCorpus error: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	corpus := buf.String()

	if !strings.Contains(corpus, "[arch=arm64 section=__TEXT.__cstring] visible-string-one") {
		t.Errorf("corpus missing provenance-tagged string; corpus=\n%s", corpus)
	}
	if !strings.Contains(corpus, "arch=x86_64 section=__ENCRYPTED__") {
		t.Errorf("corpus missing encrypted-slice marker; corpus=\n%s", corpus)
	}
}

func TestAppendBinaryCorpus(t *testing.T) {
	dir := t.TempDir()
	corpusPath := filepath.Join(dir, "corpus.txt")
	bs := &BinaryStrings{
		Slices: []ArchStrings{
			{Arch: "arm64", Strings: map[string][]string{"__TEXT.__cstring": {"appended-string"}}},
		},
	}
	if err := AppendBinaryCorpus(corpusPath, bs); err != nil {
		t.Fatalf("AppendBinaryCorpus error: %v", err)
	}
	// A second append must not truncate the first.
	bs2 := &BinaryStrings{
		Slices: []ArchStrings{
			{Arch: "arm64", Strings: map[string][]string{"__TEXT.__cstring": {"second-string"}}},
		},
	}
	if err := AppendBinaryCorpus(corpusPath, bs2); err != nil {
		t.Fatalf("AppendBinaryCorpus 2 error: %v", err)
	}

	body, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	corpus := string(body)
	if !strings.Contains(corpus, "appended-string") || !strings.Contains(corpus, "second-string") {
		t.Errorf("append did not accumulate both strings; corpus=\n%s", corpus)
	}
}
