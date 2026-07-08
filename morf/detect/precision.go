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

package detect

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strings"

	"morf/models"
)

// ApplyPrecision post-processes the sanitized secret findings to reduce false
// positives DETERMINISTICALLY — no network, no randomness, no AI — so the same
// input always yields the same output. It is invoked in the scan pipeline
// immediately after SanitizeSecrets and before verification.
//
// For every finding it computes deterministic signals (Shannon entropy, digit
// count) and applies, in order:
//
//   - BANLISTS — placeholder values, bcrypt hashes and natural-language strings
//     are dropped as clear false positives.
//   - STRUCTURAL VALIDATORS — type-keyed shape checks (PEM key body, JWT header,
//     keychain-access-group format, entitlement key-names, benign domains) drop
//     matches whose structure proves they are not a leaked secret.
//   - TIERING — surviving findings are classified into:
//   - drop: removed from the returned slice.
//   - info: real but public-by-design identifiers (GCP OAuth client IDs, iOS
//     reversed client id scheme, Firebase DB URLs, keychain-access-groups).
//     Tier="info", SecretConfidence forced to "low".
//   - keep: everything else that survives. Tier="keep".
//
// Score in [0,1] is populated on every retained finding from entropy/structure.
// The policy is CONSERVATIVE: only CLEAR false positives are dropped; when
// unsure the finding is kept (as info at worst).
func ApplyPrecision(secrets []models.SecretModel) []models.SecretModel {
	out := make([]models.SecretModel, 0, len(secrets))
	for _, s := range secrets {
		verdict, score := classifyPrecision(s)
		switch verdict {
		case precisionDrop:
			// Removed from the returned slice.
			continue
		case precisionInfo:
			s.Tier = "info"
			s.SecretConfidence = "low"
			s.Score = score
			out = append(out, s)
		default: // precisionKeep
			s.Tier = "keep"
			s.Score = score
			out = append(out, s)
		}
	}
	return out
}

type precisionVerdict int

const (
	precisionDrop precisionVerdict = iota
	precisionInfo
	precisionKeep
)

var (
	// PLACEHOLDER matches obvious non-secret placeholder / fixture values.
	placeholderRE = regexp.MustCompile(`(?i)\b(test|example|sample|fake|dummy|placeholder|xxxx|changeme|your[_-]?key)\b`)
	// BCRYPT matches the $2a$/$2b$/$2x$/$2y$ bcrypt hash prefix.
	bcryptRE = regexp.MustCompile(`^\$2[abxy]\$`)
	// BENIGN_DOMAIN matches vendor domains that surface as keychain-group noise.
	benignDomainRE = regexp.MustCompile(`(?i)(sentry\.io|googleapis\.com|apple\.com|crashlytics)`)
	// VALID_KEYCHAIN matches a real keychain-access-group: <10-char TeamID>.<id>.
	validKeychainRE = regexp.MustCompile(`^[A-Z0-9]{10}\.`)
	// pemMarkerRE strips PEM BEGIN/END armor so the key body can be measured.
	pemMarkerRE = regexp.MustCompile(`-----(BEGIN|END)[^-]*-----`)
	// pemBodyRE detects a real base64 key body (>=40 chars) inside a PEM block.
	pemBodyRE = regexp.MustCompile(`[A-Za-z0-9+/]{40,}`)
)

// publicTypes are real-but-public-by-design identifiers: they ship in every
// build and are recon signal, not a leaked secret. They are downgraded to info.
var publicTypes = map[string]bool{
	"Google Cloud Platform OAuth":         true,
	"iOS Google Reversed Client ID Scheme": true,
	"Firebase Database URL":               true,
}

// classifyPrecision returns the tier verdict and the [0,1] score for a finding.
func classifyPrecision(s models.SecretModel) (precisionVerdict, float64) {
	t := s.SecretType
	// Normalize the value the way the reference recipe does: collapse embedded
	// newlines to spaces and trim, so entropy/structure see the logical value.
	v := strings.TrimSpace(strings.ReplaceAll(s.SecretString, "\n", " "))

	ent := shannonEntropy(v)
	digits := countDigits(v)
	score := precisionScore(ent, digits, len(v))

	// ---- BANLISTS -> drop ----
	if placeholderRE.MatchString(v) {
		return precisionDrop, 0
	}
	if bcryptRE.MatchString(v) {
		return precisionDrop, 0
	}
	if isCredentialType(t) && looksNaturalLanguage(v) {
		return precisionDrop, 0
	}

	// ---- STRUCTURAL VALIDATORS -> drop ----
	if isPrivateKeyType(t) && !hasPEMBody(v) {
		return precisionDrop, 0
	}
	if t == "JSON Web Token (JWT)" && jwtIsPublicCert(v) {
		return precisionDrop, 0
	}
	if isKeychainGroupType(t) {
		if v == "keychain-access-groups" {
			return precisionDrop, 0
		}
		if benignDomainRE.MatchString(v) {
			return precisionDrop, 0
		}
		if !validKeychainRE.MatchString(v) {
			return precisionDrop, 0
		}
	}

	// ---- INFO (real but public / config metadata -> downgrade) ----
	if publicTypes[t] {
		return precisionInfo, score
	}
	if isKeychainGroupType(t) {
		// A well-formed keychain-access-group is an app entitlement identifier
		// (config metadata), not a leaked secret.
		return precisionInfo, score
	}

	// ---- KEEP (real secret) ----
	return precisionKeep, score
}

// shannonEntropy returns the Shannon entropy (bits/symbol) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	if n == 0 {
		return 0
	}
	var ent float64
	fn := float64(n)
	for _, c := range counts {
		p := float64(c) / fn
		ent -= p * math.Log2(p)
	}
	return ent
}

func countDigits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

// precisionScore maps entropy/structure to a [0,1] confidence score. Entropy is
// normalized against a ceiling of ~6 bits/symbol (typical for high-entropy
// base64/hex tokens); a small bonus rewards mixed digits and length.
func precisionScore(entropy float64, digits, length int) float64 {
	const entropyCeiling = 6.0
	e := entropy / entropyCeiling
	if e > 1 {
		e = 1
	}
	score := 0.7 * e
	if digits >= 2 {
		score += 0.15
	}
	if length >= 20 {
		score += 0.15
	}
	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}
	return score
}

// looksNaturalLanguage reports whether v reads as prose rather than a credential:
// it contains whitespace AND >=2 alphabetic word tokens of length >=4.
func looksNaturalLanguage(v string) bool {
	if !strings.ContainsAny(strings.TrimSpace(v), " \t") {
		return false
	}
	words := 0
	for _, w := range strings.Fields(v) {
		if len(w) >= 4 && isAllAlpha(w) {
			words++
		}
	}
	return words >= 2
}

func isAllAlpha(w string) bool {
	if w == "" {
		return false
	}
	for _, r := range w {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// hasPEMBody reports whether v carries a real base64 key body (>=40 chars) once
// the BEGIN/END armor is stripped — i.e. it is more than just a PEM header.
func hasPEMBody(v string) bool {
	body := pemMarkerRE.ReplaceAllString(v, "")
	return pemBodyRE.MatchString(body)
}

// jwtIsPublicCert reports whether a JWT's base64url-decoded header carries a
// public certificate chain / key reference (x5c/x5u/jku) — meaning the token is
// a public cert artifact, not a leaked bearer secret.
func jwtIsPublicCert(v string) bool {
	seg := v
	if i := strings.Index(seg, "."); i >= 0 {
		seg = seg[:i]
	}
	// Pad to a multiple of 4 for base64url decoding.
	if pad := len(seg) % 4; pad != 0 {
		seg += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		// Try the raw (unpadded) variant as a fallback.
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
		if err != nil {
			return false
		}
	}
	var hdr map[string]interface{}
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	_, x5c := hdr["x5c"]
	_, x5u := hdr["x5u"]
	_, jku := hdr["jku"]
	return x5c || x5u || jku
}

// isCredentialType reports whether the finding's type denotes a credential value
// (as opposed to a structured artifact like a private-key block or JWT), for
// which a natural-language value is a clear false positive.
func isCredentialType(t string) bool {
	if isPrivateKeyType(t) || t == "JSON Web Token (JWT)" || isKeychainGroupType(t) {
		return false
	}
	return true
}

// isPrivateKeyType matches the family of PEM private-key finding types.
func isPrivateKeyType(t string) bool {
	lt := strings.ToLower(t)
	return strings.Contains(lt, "private key")
}

// isKeychainGroupType matches iOS keychain-access-group finding types (both the
// singular "iOS Keychain Access Group" and the entitlement variants).
func isKeychainGroupType(t string) bool {
	return strings.HasPrefix(t, "iOS Keychain Access Group")
}
