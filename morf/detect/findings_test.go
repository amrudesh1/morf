package detect

import (
	"regexp"
	"strings"
	"testing"
)

// awsKey is the canonical AWS example access key: AKIA + 16 upper/digit chars.
const awsKey = "AKIAIOSFODNN7EXAMPLE"

// stripeKey is a well-formed test Stripe live key: sk_live_ + 24 alnum chars.
const stripeKey = "sk_live_" + "0123456789abcdefABCDEFgh"

func re2Cache(t *testing.T) *PatternCache {
	t.Helper()
	pats := []PatternInfo{
		{Name: "AWS Access Key", Regex: `AKIA[0-9A-Z]{16}`, Confidence: "high", Compiled: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{Name: "Stripe API Key", Regex: `sk_live_[0-9a-zA-Z]{24}`, Confidence: "high", Compiled: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
	}
	combined, g2p := BuildCombinedRegex(pats)
	if combined == nil {
		t.Fatal("BuildCombinedRegex returned nil combined regex")
	}
	return &PatternCache{Patterns: pats, Combined: combined, GroupToPattern: g2p}
}

// TestFindingsForLine_ExactValueSingle: a clean single-token line yields exactly
// one finding whose value is the precise regex match (no heuristic mangling).
func TestFindingsForLine_ExactValueSingle(t *testing.T) {
	c := re2Cache(t)
	fs := c.FindingsForLine("bin/corpus", 1, awsKey)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].SecretString != awsKey {
		t.Fatalf("value: want %q, got %q", awsKey, fs[0].SecretString)
	}
	if fs[0].Type != "AWS Access Key" || fs[0].SecretConfidence != "high" {
		t.Fatalf("attribution: got type=%q conf=%q", fs[0].Type, fs[0].SecretConfidence)
	}
}

// TestFindingsForLine_PackedMultiSecret is the core regression for the caveat:
// a densely packed line (no separators, surrounding noise, TWO different
// secrets) must yield BOTH secrets with their EXACT values — never one, never a
// wrong token.
func TestFindingsForLine_PackedMultiSecret(t *testing.T) {
	c := re2Cache(t)
	// Mimic a Go __rodata / obfuscated blob: noise + AKIA + noise + stripe + noise,
	// no quotes, colons or separators to help a heuristic.
	line := "runtimebytesmcache" + awsKey + "notflushedmarkroot" + stripeKey + "jobsdone"
	fs := c.FindingsForLine("bin/corpus", 7, line)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (both secrets), got %d: %+v", len(fs), fs)
	}
	got := map[string]string{}
	for _, f := range fs {
		if f.SecretString == "" {
			t.Fatalf("empty SecretString in %+v", f)
		}
		got[f.Type] = f.SecretString
	}
	if got["AWS Access Key"] != awsKey {
		t.Fatalf("AWS value: want %q, got %q", awsKey, got["AWS Access Key"])
	}
	if got["Stripe API Key"] != stripeKey {
		t.Fatalf("Stripe value: want %q, got %q", stripeKey, got["Stripe API Key"])
	}
}

// TestFindingsForLine_QuotedContext: when the match sits in quotes/assignment,
// the reported value is still the exact key (ExtractSecret over the match span).
func TestFindingsForLine_QuotedContext(t *testing.T) {
	c := re2Cache(t)
	fs := c.FindingsForLine("Info.plist", 3, `<string>`+awsKey+`</string>`)
	if len(fs) != 1 || fs[0].SecretString != awsKey {
		t.Fatalf("want single %q, got %+v", awsKey, fs)
	}
}

// TestFindingsForLine_NeverEmpty: every finding has a non-empty value.
func TestFindingsForLine_NeverEmpty(t *testing.T) {
	c := re2Cache(t)
	for _, line := range []string{awsKey, stripeKey, "x" + awsKey + "y", `key="` + stripeKey + `"`} {
		for _, f := range c.FindingsForLine("f", 1, line) {
			if strings.TrimSpace(f.SecretString) == "" {
				t.Fatalf("empty SecretString for line %q", line)
			}
		}
	}
}

// TestFindingsForLine_NonRE2Fallback: a ripgrep-flagged line that no RE2 pattern
// matches is NEVER dropped — it yields one finding attributed to the first
// non-RE2 pattern, with a non-empty value.
func TestFindingsForLine_NonRE2Fallback(t *testing.T) {
	pats := []PatternInfo{
		{Name: "NonRE2 Lookaround", Regex: `(?=foo)`, Confidence: "medium", Compiled: nil}, // not RE2-compilable
		{Name: "AWS Access Key", Regex: `AKIA[0-9A-Z]{16}`, Confidence: "high", Compiled: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	}
	combined, g2p := BuildCombinedRegex(pats) // combined covers only the AKIA pattern
	c := &PatternCache{Patterns: pats, Combined: combined, GroupToPattern: g2p}

	fs := c.FindingsForLine("f", 9, "no recognizable RE2 secret on this line")
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 fallback finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Type != "NonRE2 Lookaround" {
		t.Fatalf("fallback attribution: want NonRE2 Lookaround, got %q", fs[0].Type)
	}
	if strings.TrimSpace(fs[0].SecretString) == "" {
		t.Fatal("fallback finding has empty SecretString")
	}
}

// TestFindingsForLine_UnattributedNeverDropped: with no non-RE2 pattern to fall
// back to and no RE2 match, the line still yields one "unattributed" finding
// (recall guarantee — a ripgrep hit is never silently lost).
func TestFindingsForLine_UnattributedNeverDropped(t *testing.T) {
	c := re2Cache(t) // only RE2 token patterns; none match this line
	fs := c.FindingsForLine("f", 2, "totally benign text")
	if len(fs) != 1 || fs[0].Type != "unattributed" {
		t.Fatalf("want 1 unattributed finding, got %+v", fs)
	}
	if strings.TrimSpace(fs[0].SecretString) == "" {
		t.Fatal("unattributed finding has empty SecretString")
	}
}
