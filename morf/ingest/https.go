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

package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"morf/config"
	"morf/utils"
)

// httpsScheme serves generic pre-signed download URLs (pre-signed S3/GCS URLs,
// artifact-store URLs, etc.). The "http" scheme is served by the same adapter
// but is refused unless MORF_INGEST_ALLOW_HTTP=true (plaintext + easier SSRF).
const (
	httpsScheme = "https"
	httpScheme  = "http"
)

// ingestDialTimeout / ingestClientTimeout bound the connection and the overall
// download respectively.
const (
	ingestDialTimeout   = 10 * time.Second
	ingestClientTimeout = 30 * time.Minute
)

// httpsAdapter downloads an artifact from a pre-signed HTTPS URL. It layers the
// codebase's SSRF/size defenses:
//   - utils.ValidateWebhookURL fail-fast (scheme + DNS resolve + disallowed-IP
//     rejection) before any connection is made;
//   - a dial-time Control hook that re-validates the ACTUAL connected IP so a
//     hostname that passes validation but resolves to an internal address at
//     connect time (DNS rebinding) is still refused;
//   - a redirect policy that refuses 3xx so a redirect cannot bounce the request
//     to an internal host;
//   - a size cap enforced while streaming (copyCapped).
//
// It optionally verifies a ?sha256=/#sha256=<hex> digest supplied in the URL.
type httpsAdapter struct {
	scheme    string
	destDir   string
	maxBytes  int64
	allowHTTP bool
}

func init() {
	Register(httpsScheme, func(o Options) (Adapter, error) { return newHTTPSAdapter(httpsScheme, o) })
	Register(httpScheme, func(o Options) (Adapter, error) { return newHTTPSAdapter(httpScheme, o) })
}

func newHTTPSAdapter(scheme string, o Options) (Adapter, error) {
	return &httpsAdapter{
		scheme:    scheme,
		destDir:   o.DestDir,
		maxBytes:  resolveMaxBytes(o),
		allowHTTP: config.Bool("MORF_INGEST_ALLOW_HTTP", false),
	}, nil
}

func (a *httpsAdapter) Scheme() string { return a.scheme }

// allowInternalHosts, when true, disables the loopback/private-IP SSRF checks so
// tests can exercise the download plumbing against an httptest.Server bound to
// 127.0.0.1. It is ALWAYS false in production; only tests flip it (and the SSRF
// rejection is separately asserted with it left false). Both the up-front
// validation gate and the dial-time Control hook honour it.
var allowInternalHosts = false

// validateURL is the up-front SSRF gate. It is a package var so tests can bypass
// it when allowInternalHosts is set; the default delegates to the same validator
// the webhook-intake path uses.
var validateURL = func(ctx context.Context, u string) error {
	if allowInternalHosts {
		return nil
	}
	return utils.ValidateWebhookURL(ctx, u)
}

// ssrfDialer re-validates the connected IP at dial time, defeating DNS rebinding
// exactly as utils.webhookDialer does for webhook delivery. The Control hook runs
// after DNS resolution but before the connection is used.
var ssrfDialer = &net.Dialer{
	Timeout:   ingestDialTimeout,
	KeepAlive: 30 * time.Second,
	Control: func(_, address string, _ syscall.RawConn) error {
		if allowInternalHosts {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("ingest dial: invalid address %q: %v", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("ingest dial: unresolvable address %q", host)
		}
		if isDisallowedIP(ip) {
			return fmt.Errorf("ingest dial: connection to disallowed IP %s blocked (SSRF protection)", ip)
		}
		return nil
	},
}

// ssrfClient mirrors utils.webhookClient: SSRF-aware dialer + a redirect policy
// that refuses to follow 3xx so a redirect cannot be used to reach an internal
// host. Package-level so connections are pooled across fetches.
var ssrfClient = &http.Client{
	Timeout: ingestClientTimeout,
	Transport: &http.Transport{
		DialContext:           ssrfDialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("ingest: redirects are not allowed (SSRF protection)")
	},
}

// isDisallowedIP reports whether ip points at a non-routable/internal address a
// fetch must never reach. It mirrors utils.isDisallowedIP (which is unexported):
// loopback, link-local (incl. the 169.254.169.254 cloud metadata endpoint),
// RFC1918 private ranges, IPv6 unique-local (fc00::/7), unspecified and
// multicast addresses.
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	if v6 := ip.To16(); v6 != nil && len(ip.To4()) == 0 {
		if v6[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}

func (a *httpsAdapter) Fetch(ctx context.Context, ref string) (string, error) {
	ctx = ensureCtx(ctx)

	parsed, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", fmt.Errorf("ingest: invalid URL %q: %w", ref, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case httpsScheme:
		// always allowed
	case httpScheme:
		if !a.allowHTTP {
			return "", fmt.Errorf("ingest: http:// URLs are refused; set MORF_INGEST_ALLOW_HTTP=true to allow plaintext downloads")
		}
	default:
		return "", fmt.Errorf("ingest: URL scheme %q is not http(s)", parsed.Scheme)
	}

	// Fail-fast SSRF gate reusing the exact webhook-intake validator (scheme +
	// DNS resolve + disallowed-IP rejection). The dial-time Control hook on
	// ssrfDialer remains the authoritative anti-rebinding defense.
	if err := validateURL(ctx, parsed.String()); err != nil {
		return "", fmt.Errorf("ingest: URL failed SSRF validation: %w", err)
	}

	// Optional integrity digest carried in the query (?sha256=) or fragment
	// (#sha256=). Stripped from the request URL so it is not sent to the server.
	wantSHA, reqURL := extractSHA256(parsed)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("ingest: building request: %w", err)
	}
	req.Header.Set("User-Agent", "MORF-Ingest/1.0")

	resp, err := ssrfClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ingest: fetching %s: %w", utils.MaskURLForLogging(reqURL), err)
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ingest: fetching %s: unexpected status %d", utils.MaskURLForLogging(reqURL), resp.StatusCode)
	}

	// Reject up front when the server declares an over-cap Content-Length.
	if resp.ContentLength > 0 && resp.ContentLength > a.maxBytes {
		return "", fmt.Errorf("ingest: artifact is %d bytes, exceeds the %d-byte limit", resp.ContentLength, a.maxBytes)
	}

	destDir, err := resolveDestDir(Options{DestDir: a.destDir})
	if err != nil {
		return "", err
	}

	ext := artifactExt(parsed.Path)
	// If we must verify a digest we tee the stream through a hasher.
	var body io.Reader = resp.Body
	var hasher = sha256.New()
	if wantSHA != "" {
		body = io.TeeReader(resp.Body, hasher)
	}

	localPath, err := copyCapped(destDir, ext, body, a.maxBytes)
	if err != nil {
		return "", err
	}
	if wantSHA != "" {
		got := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(got, wantSHA) {
			os.Remove(localPath)
			return "", fmt.Errorf("ingest: sha256 mismatch: want %s, got %s", wantSHA, got)
		}
	}
	return localPath, nil
}

// extractSHA256 pulls a sha256 digest from the URL's query (?sha256=) or fragment
// (#sha256=<hex>) if present, returning the lowercased hex digest and the URL to
// actually request (with the sha256 query param and fragment removed so the
// server never sees them). An empty digest means "no verification requested".
func extractSHA256(u *url.URL) (digest, requestURL string) {
	cp := *u
	// Fragment form: #sha256=<hex>
	if frag := strings.TrimSpace(cp.Fragment); frag != "" {
		if strings.HasPrefix(strings.ToLower(frag), "sha256=") {
			digest = strings.ToLower(frag[len("sha256="):])
		}
	}
	cp.Fragment = ""
	// Query form: ?sha256=<hex> (takes precedence if both are present).
	q := cp.Query()
	if v := strings.TrimSpace(q.Get("sha256")); v != "" {
		digest = strings.ToLower(v)
		q.Del("sha256")
		cp.RawQuery = q.Encode()
	}
	return digest, cp.String()
}
