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

package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// algorithm is the AWS Signature Version 4 algorithm identifier.
const algorithm = "AWS4-HMAC-SHA256"

// emptyPayloadHash is hex(sha256("")), used as x-amz-content-sha256 for requests
// without a body (GET/HEAD/DELETE).
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// credentials holds the static AWS credentials used for signing.
type credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional (STS)
}

// hmacSHA256 returns HMAC-SHA256(key, data).
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// sha256Hex returns the lowercase hex of sha256(data).
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// deriveSigningKey computes the AWS SigV4 signing key:
//
//	kDate    = HMAC("AWS4"+secret, dateStamp)
//	kRegion  = HMAC(kDate, region)
//	kService = HMAC(kRegion, service)
//	kSigning = HMAC(kService, "aws4_request")
func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

// uriEncode percent-encodes s per RFC 3986, leaving the unreserved characters
// (A-Z a-z 0-9 - _ . ~) untouched. When encodeSlash is false, '/' is preserved
// (used for the canonical URI path); when true, '/' is encoded (query strings).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			const hexUpper = "0123456789ABCDEF"
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0f])
		}
	}
	return b.String()
}

// canonicalURIPath returns the canonical (single URI-encoded, slash-preserving)
// path. S3 uses single encoding of the path component.
func canonicalURIPath(path string) string {
	if path == "" {
		return "/"
	}
	return uriEncode(path, false)
}

// canonicalQuery returns the canonical query string: parameters sorted by key
// (and value), each component URI-encoded, joined by '&'.
func canonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), values[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// trimAll collapses internal runs of whitespace to a single space and trims the
// ends, per the SigV4 header value normalization rules (sufficient for the
// unquoted header values we produce).
func trimAll(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

// signRequest signs req in place using AWS Signature Version 4 (header based).
//
// It sets X-Amz-Date (and X-Amz-Security-Token when a session token is present),
// signs the host header plus every header already present on req, and writes the
// Authorization header. payloadHash must be hex(sha256(body)); callers that send
// a body are expected to also set the X-Amz-Content-Sha256 header to the same
// value before calling so that it is included in the signed headers.
func signRequest(req *http.Request, payloadHash string, creds credentials, region, service string, signTime time.Time) {
	t := signTime.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Host is carried on req.Host / req.URL.Host rather than the header map.
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Collect headers to sign: host + every header currently on the request.
	headers := map[string]string{"host": host}
	for name, vals := range req.Header {
		headers[strings.ToLower(name)] = trimAll(strings.Join(vals, ","))
	}

	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)

	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(headers[n])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURIPath(req.URL.Path),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(creds.SecretAccessKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authorization := algorithm +
		" Credential=" + creds.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + signature
	req.Header.Set("Authorization", authorization)
}
