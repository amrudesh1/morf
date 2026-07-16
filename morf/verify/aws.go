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

package verify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"morf/models"
)

// awsSTSBase is the STS endpoint. It is a package variable (not a constant)
// ONLY so tests can point it at a net/http/httptest mock server; production
// code never mutates it.
var awsSTSBase = "https://sts.amazonaws.com"

// AWS SigV4 constants for the STS GetCallerIdentity probe.
const (
	awsRegion  = "us-east-1"
	awsService = "sts"
	// stsAction is a read-only call that returns the identity of the caller.
	// It is the canonical "who am I" probe and mutates nothing.
	stsAction  = "GetCallerIdentity"
	stsVersion = "2011-06-15"

	// awsMaxCandidates bounds how many candidate secret keys are tried per AKIA
	// id so a batch with many 40-char strings cannot fan out unbounded requests
	// against the shared rate limiter.
	awsMaxCandidates = 3
)

// akiaPattern matches an AWS access key ID (AKIA / ASIA / AGPA / AIDA / AROA /
// AIPA / ANPA / ANVA / ASCA prefixes are all 20 chars: 4-char prefix + 16).
// We accept the common long-term (AKIA) and temporary (ASIA) prefixes plus any
// other 4-letter prefix followed by 16 uppercase-alnum chars.
var akiaPattern = regexp.MustCompile(`^(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}$`)

// awsPairablePattern is the subset of access-key IDs that can be verified with
// only an ID + a 40-char secret access key: LONG-TERM keys (AKIA). Temporary
// credentials (ASIA) additionally require an X-Amz-Security-Token that a static
// scan cannot recover, so signing them with just id+secret would 403 and be
// misread as "inactive" (a false negative). We therefore only PAIR AKIA keys;
// ASIA and the other unique-id prefixes fall through to the single-string
// verifier and stay "unknown" rather than being wrongly reported inactive.
var awsPairablePattern = regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)

// awsSecretPattern matches a candidate 40-char AWS secret access key.
var awsSecretPattern = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)

// awsVerifier verifies an AWS access key ID by pairing it with a candidate
// secret access key found in the same scan and issuing a SigV4-signed STS
// GetCallerIdentity request.
//
// The single-string Verify entrypoint cannot see sibling findings, so it always
// returns unknown (an access key ID alone is not verifiable and must never be
// reported active). The real work happens in verifyPair, driven by the
// slice-aware pre-pass in verifyWithRegistry.
type awsVerifier struct{ c *client }

// Verify satisfies the Verifier interface. With only an access key ID and no
// paired secret access key, there is nothing safe to verify, so it returns
// unknown and makes NO network call.
func (v *awsVerifier) Verify(_ context.Context, _ string) (string, error) {
	return statusUnknown, nil
}

func (v *awsVerifier) shared() *client { return v.c }

// verifyPair signs and sends an STS GetCallerIdentity request for the given
// (accessKeyID, secretKey) pair.
//
//   - HTTP 200 with a well-formed GetCallerIdentityResponse => active.
//   - HTTP 403 with InvalidClientTokenId / SignatureDoesNotMatch => the pair is
//     not valid (inactive: this specific credential does not authenticate).
//   - anything else (network error, 5xx, throttling, ambiguous) => unknown.
func (v *awsVerifier) verifyPair(ctx context.Context, accessKeyID, secretKey string) (string, error) {
	req, err := buildSTSGetCallerIdentityRequest(ctx, awsSTSBase, accessKeyID, secretKey, time.Now().UTC())
	if err != nil {
		return statusUnknown, err
	}
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	// Read a bounded amount of the body so we can classify the error code.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	text := string(body)

	switch resp.StatusCode {
	case http.StatusOK:
		if strings.Contains(text, "GetCallerIdentityResponse") || strings.Contains(text, "<Arn>") {
			return statusActive, nil
		}
		return statusUnknown, nil
	case http.StatusForbidden:
		if strings.Contains(text, "InvalidClientTokenId") ||
			strings.Contains(text, "SignatureDoesNotMatch") {
			return statusInactive, nil
		}
		// A 403 we cannot attribute to a bad credential (e.g. an explicit deny
		// policy on a valid key) is inconclusive.
		return statusUnknown, nil
	default:
		return statusUnknown, nil
	}
}

// buildSTSGetCallerIdentityRequest constructs a GET request to the STS endpoint
// for the GetCallerIdentity action, signed with SigV4 via query-string signing
// (X-Amz-* parameters in the URL). GET query-signing keeps the shared client's
// READ-ONLY (safe-method) invariant intact.
func buildSTSGetCallerIdentityRequest(ctx context.Context, base, accessKeyID, secretKey string, now time.Time) (*http.Request, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	credentialScope := dateStamp + "/" + awsRegion + "/" + awsService + "/aws4_request"

	// Query parameters, including the SigV4 X-Amz-* set (minus the signature).
	q := url.Values{}
	q.Set("Action", stsAction)
	q.Set("Version", stsVersion)
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKeyID+"/"+credentialScope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-SignedHeaders", "host")

	host := u.Host
	canonicalURI := u.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQuery := canonicalQueryString(q)
	canonicalHeaders := "host:" + host + "\n"
	signedHeaders := "host"
	payloadHash := sha256Hex("") // GET has an empty body.

	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex(canonicalRequest),
	}, "\n")

	signingKey := sigv4SigningKey(secretKey, dateStamp, awsRegion, awsService)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	q.Set("X-Amz-Signature", signature)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// Ensure the Host used for signing matches what net/http sends.
	req.Host = host
	return req, nil
}

// canonicalQueryString builds the SigV4 canonical query string: parameters
// sorted by key, URI-encoded per RFC 3986, joined key=value with '&'.
func canonicalQueryString(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, val := range q[k] {
			parts = append(parts, awsURIEncode(k, true)+"="+awsURIEncode(val, true))
		}
	}
	return strings.Join(parts, "&")
}

// awsURIEncode implements AWS's SigV4 URI encoding: RFC 3986 unreserved chars
// are left as-is, everything else is percent-encoded uppercase. When encodeSlash
// is false, '/' is preserved (used for path segments).
func awsURIEncode(s string, encodeSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~':
			b.WriteByte(ch)
		case ch == '/' && !encodeSlash:
			b.WriteByte(ch)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[ch>>4])
			b.WriteByte(upperhex[ch&0x0f])
		}
	}
	return b.String()
}

// sigv4SigningKey derives the SigV4 signing key via the documented nested
// HMAC-SHA256 chain: kDate, kRegion, kService, kSigning.
func sigv4SigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// awsCandidate is a scored candidate secret access key drawn from the batch.
type awsCandidate struct {
	secret   string
	sameFile bool
	lineDist int
}

// collectAWSSecretCandidates finds candidate 40-char AWS secret access keys in
// the batch and ranks them by co-location with the AKIA finding: same file
// first, then smallest absolute line distance. It returns at most
// awsMaxCandidates values so the shared rate limiter is respected.
func collectAWSSecretCandidates(secrets []models.SecretModel, akiaIdx int) []string {
	akia := secrets[akiaIdx]
	var cands []awsCandidate
	seen := make(map[string]bool)
	for i := range secrets {
		if i == akiaIdx {
			continue
		}
		val := strings.TrimSpace(secrets[i].SecretString)
		if val == "" || seen[val] {
			continue
		}
		if !awsSecretPattern.MatchString(val) {
			continue
		}
		// Never treat the AKIA id (or another access key id) as a secret key.
		if akiaPattern.MatchString(val) {
			continue
		}
		seen[val] = true
		dist := akia.LineNo - secrets[i].LineNo
		if dist < 0 {
			dist = -dist
		}
		cands = append(cands, awsCandidate{
			secret:   val,
			sameFile: akia.FileLocation != "" && secrets[i].FileLocation == akia.FileLocation,
			lineDist: dist,
		})
	}
	sort.SliceStable(cands, func(a, b int) bool {
		if cands[a].sameFile != cands[b].sameFile {
			return cands[a].sameFile // same-file candidates first
		}
		return cands[a].lineDist < cands[b].lineDist
	})
	out := make([]string, 0, awsMaxCandidates)
	for i := 0; i < len(cands) && i < awsMaxCandidates; i++ {
		out = append(out, cands[i].secret)
	}
	return out
}
