package detect

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformScoping loads the real pattern files and verifies that an Android
// scan never compiles iOS-scoped patterns (e.g. "iOS Keychain Access Group"),
// while an iOS scan includes them on top of the shared/generic patterns.
func TestPlatformScoping(t *testing.T) {
	abs, err := filepath.Abs("../patterns")
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(abs); statErr != nil {
		t.Skipf("patterns dir not available at %s: %v", abs, statErr)
	}
	t.Setenv("MORF_PATTERNS_DIR", abs)

	android, err := GetPatternCache("test", "android")
	if err != nil {
		t.Fatalf("android cache: %v", err)
	}
	ios, err := GetPatternCache("test", "ios")
	if err != nil {
		t.Fatalf("ios cache: %v", err)
	}

	if len(android.Patterns) == 0 {
		t.Fatal("android cache is empty (generic patterns should still load)")
	}

	// An Android scan must not carry any iOS-scoped pattern.
	for _, p := range android.Patterns {
		if p.Platform == "ios" {
			t.Errorf("android scan contains iOS-scoped pattern %q (platform=%s)", p.Name, p.Platform)
		}
	}

	// An iOS scan must include iOS-scoped patterns from the ios-*.yml files.
	iosScoped := 0
	for _, p := range ios.Patterns {
		if p.Platform == "ios" {
			iosScoped++
		}
	}
	if iosScoped == 0 {
		t.Error("ios scan has no iOS-scoped patterns; expected the ios-*.yml patterns")
	}

	// iOS set = shared + iOS, so it must be strictly larger than Android (shared only).
	if len(ios.Patterns) <= len(android.Patterns) {
		t.Errorf("expected ios patterns (%d) > android patterns (%d) by the iOS-only rules",
			len(ios.Patterns), len(android.Patterns))
	}
	t.Logf("android patterns=%d, ios patterns=%d (iOS-scoped=%d)",
		len(android.Patterns), len(ios.Patterns), iosScoped)
}
