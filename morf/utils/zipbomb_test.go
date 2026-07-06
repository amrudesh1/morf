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
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildZip writes a zip archive to a temp file and returns its path.
// Each entry in entries is (name, compressedContent, uncompressedSize).
// When uncompressedSize == 0 the compressed content is used as-is with
// Deflate method set to Store so sizes match naturally. When uncompressedSize
// is explicitly provided the header fields are patched after the fact to
// simulate a central-directory entry that claims a large uncompressed size
// without actually holding the data — this is exactly what a zip-bomb entry
// looks like to a header-only scanner.
//
// For simplicity, tests use a helper that creates a real zip with real bytes;
// the ratio-trigger test uses t.Setenv to lower APKMaxRatio so normal content
// can trip the guard.
func buildZip(t *testing.T, entries []struct{ name, content string }) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("buildZip: create: %v", err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	for _, e := range entries {
		fw, err := w.Create(e.name)
		if err != nil {
			t.Fatalf("buildZip: create entry %q: %v", e.name, err)
		}
		if _, err := fw.Write([]byte(e.content)); err != nil {
			t.Fatalf("buildZip: write entry %q: %v", e.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("buildZip: close writer: %v", err)
	}
	return path
}

// buildZipBuf returns the raw bytes of a zip containing one entry whose
// central-directory header claims a large UncompressedSize64 while the
// actual compressed payload is tiny — this is the classic zip-bomb fingerprint
// that CheckAPKSafe catches via central-directory inspection only.
//
// archive/zip doesn't let us lie about sizes directly, so we construct the
// bytes manually using zip.Writer and then patch the local file header and
// central directory record in-memory.
//
// For test purposes we use a simpler approach: just write many small entries
// (each 1 byte) and lower the entry-count limit via t.Setenv.
func makeEntrySlice(n int) []struct{ name, content string } {
	s := make([]struct{ name, content string }, n)
	for i := range s {
		s[i] = struct{ name, content string }{
			name:    fmt.Sprintf("entry%d.txt", i),
			content: "x",
		}
	}
	return s
}

// TestCheckAPKSafe_Safe verifies that a normal, small APK-shaped zip passes.
func TestCheckAPKSafe_Safe(t *testing.T) {
	path := buildZip(t, []struct{ name, content string }{
		{"AndroidManifest.xml", "<manifest/>"},
		{"classes.dex", "DEX data here"},
		{"res/layout/main.xml", "<layout/>"},
	})

	if err := CheckAPKSafe(path); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestCheckAPKSafe_MissingFile verifies that a non-existent path returns an error.
func TestCheckAPKSafe_MissingFile(t *testing.T) {
	err := CheckAPKSafe("/does/not/exist/fake.apk")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestCheckAPKSafe_InvalidZip verifies that a file that is not a valid zip
// returns an error.
func TestCheckAPKSafe_InvalidZip(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.apk")
	if err := os.WriteFile(bad, []byte("this is not a zip file at all"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CheckAPKSafe(bad); err == nil {
		t.Fatal("expected error for invalid zip, got nil")
	}
}

// TestCheckAPKSafe_TooManyEntries verifies the entry-count guard.
// We lower the limit via env so the test zip can be small.
func TestCheckAPKSafe_TooManyEntries(t *testing.T) {
	// Build a zip with 5 entries, then set the limit to 3.
	path := buildZip(t, makeEntrySlice(5))

	t.Setenv("MORF_ZIP_MAX_ENTRIES", "3")
	// Re-read the env (init() already ran; tests must update the var directly
	// because init() runs once at program start, not per t.Setenv call).
	APKMaxEntries = 3
	t.Cleanup(func() { APKMaxEntries = defaultAPKMaxEntries })

	err := CheckAPKSafe(path)
	if err == nil {
		t.Fatal("expected entry-count error, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestCheckAPKSafe_TotalSizeExceeded verifies the total-uncompressed-size guard.
// We lower the limit via the package var so the test zip can be small.
func TestCheckAPKSafe_TotalSizeExceeded(t *testing.T) {
	// 3 entries, each 100 bytes; set limit to 150 bytes.
	entries := []struct{ name, content string }{
		{"a.txt", strings.Repeat("A", 100)},
		{"b.txt", strings.Repeat("B", 100)},
		{"c.txt", strings.Repeat("C", 100)},
	}
	path := buildZip(t, entries)

	old := APKMaxTotalUncompressed
	APKMaxTotalUncompressed = 150
	t.Cleanup(func() { APKMaxTotalUncompressed = old })

	err := CheckAPKSafe(path)
	if err == nil {
		t.Fatal("expected total-size error, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestCheckAPKSafe_PerEntryRatioExceeded verifies the per-entry ratio guard.
// We lower APKMaxRatio to 1.5 so that a normally compressed text file
// (which typically compresses well) trips the guard.
func TestCheckAPKSafe_PerEntryRatioExceeded(t *testing.T) {
	// A file with highly repetitive content that zip will compress heavily.
	content := strings.Repeat("AAAAAAAAAA", 500) // 5000 bytes, compresses to ~tens of bytes

	path := buildZip(t, []struct{ name, content string }{
		{"big.txt", content},
	})

	// Verify what ratio we actually get before asserting.
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	var actualRatio float64
	for _, f := range r.File {
		if f.CompressedSize64 > 0 {
			actualRatio = float64(f.UncompressedSize64) / float64(f.CompressedSize64)
		}
	}
	r.Close()

	if actualRatio <= 1.0 {
		t.Skipf("compression ratio %.2f not high enough to test; skip", actualRatio)
	}

	// Set limit just below the actual ratio.
	old := APKMaxRatio
	APKMaxRatio = actualRatio * 0.5 // definitely below actual
	t.Cleanup(func() { APKMaxRatio = old })

	err = CheckAPKSafe(path)
	if err == nil {
		t.Fatalf("expected ratio error (actual ratio %.2f, limit %.2f), got nil", actualRatio, APKMaxRatio)
	}
	t.Logf("got expected error: %v", err)
}

// TestCheckAPKSafe_EnvOverride verifies that MORF_ZIP_MAX_ENTRIES is
// respected when the package var is set (simulating what init() does).
func TestCheckAPKSafe_EnvOverride(t *testing.T) {
	path := buildZip(t, makeEntrySlice(10))

	old := APKMaxEntries
	APKMaxEntries = 5 // simulate env override
	t.Cleanup(func() { APKMaxEntries = old })

	if err := CheckAPKSafe(path); err == nil {
		t.Fatal("expected error with lowered APKMaxEntries, got nil")
	}

	APKMaxEntries = 20 // higher than 10 entries → should pass
	if err := CheckAPKSafe(path); err != nil {
		t.Fatalf("expected nil with raised APKMaxEntries, got %v", err)
	}
}
