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

// Package osv provides an opt-in OSV.dev vulnerability correlation client for
// SBOM components. It is entirely OFF by default: no network calls are made
// unless MORF_ENABLE_OSV == "true" (or the caller explicitly calls
// EnrichComponents with a non-nil context and opt-in).
//
// Safety controls (mirrors the verify/ pattern):
//   - Short per-request timeout (osvRequestTimeout).
//   - Global rate limiter across all outbound calls (rate.Limiter).
//   - No redirect following.
//   - Response bodies read with a hard size cap; never logged wholesale.
//   - Context-cancellable at every call site.
//   - Bounded worker concurrency (osvMaxConcurrency).
//
// Supported purl ecosystem -> OSV ecosystem mapping:
//
//	pkg:maven   -> "Maven"
//	pkg:pub     -> "Pub"
//	pkg:npm     -> "npm"
//	pkg:swift   -> "SwiftURL"  (OSV uses "SwiftURL" for Swift packages)
//
// Components without a version, or whose ecosystem is not on the supported
// list (pkg:cocoapods, pkg:generic, …), are silently skipped — no query,
// no error.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"morf/models"
)

// EnvOSVEnabled is the environment variable that opts in to OSV network calls.
// The value must be exactly "true" (case-sensitive) for enrichment to run.
const EnvOSVEnabled = "MORF_ENABLE_OSV"

// Safety parameters – mirrors the verify/ package constants.
const (
	osvRequestTimeout  = 10 * time.Second
	osvRateLimit       = rate.Limit(5) // 5 req/s steady state
	osvRateBurst       = 5
	osvMaxConcurrency  = 4       // bounded worker fan-out
	osvMaxResponseBody = 1 << 20 // 1 MiB cap on response bodies
	osvBaseURL         = "https://api.osv.dev"
)

// OSVVulnerability is the output type: a resolved vulnerability ready to be
// embedded in a CycloneDX 1.6 vulnerabilities array.
type OSVVulnerability struct {
	// ID is the canonical identifier (CVE-*, GHSA-*, OSV-*, …).
	ID string
	// Aliases holds any additional identifiers (e.g. GHSA when the primary is CVE).
	Aliases []string
	// Source is the data source name and URL, e.g. "OSV", "https://osv.dev/…".
	SourceName string
	SourceURL  string
	// Summary is the short description (first ~100 chars of the OSV summary).
	Summary string
	// Severity is the highest CVSS severity label: "critical", "high", "medium",
	// "low", "none", or "unknown".
	Severity string
	// CVSS is the highest CVSS score string present in the OSV record, e.g. "9.8".
	CVSS string
	// CVSSVector is the raw CVSS vector string, if available.
	CVSSVector string
	// AffectedBomRef is the bom-ref of the SBOM component this vuln affects.
	AffectedBomRef string
}

// Client is the OSV enrichment client. A zero Client is not ready; use NewClient.
type Client struct {
	http    *http.Client
	limiter *rate.Limiter
	baseURL string // injectable for tests
}

// NewClient builds a ready-to-use OSV client with the default safety controls.
func NewClient() *Client {
	return &Client{
		http: &http.Client{
			Timeout: osvRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // never follow redirects
			},
		},
		limiter: rate.NewLimiter(osvRateLimit, osvRateBurst),
		baseURL: osvBaseURL,
	}
}

// IsEnabled reports whether MORF_ENABLE_OSV is exactly "true".
func IsEnabled() bool {
	return os.Getenv(EnvOSVEnabled) == "true"
}

// EnrichComponents queries OSV for every supported, versioned SBOM component
// and returns the resolved vulnerability list. Components whose purl type is
// unsupported or that lack a version are silently skipped.
//
// When ctx is cancelled or the call returns an error, degradation is graceful:
// the caller receives whatever partial results were collected before the
// cancellation, plus any per-component errors are logged at Debug level (never
// at Error, to avoid alarming operators for transient network failures). The
// SBOM is always emitted — a failed OSV lookup is not fatal.
//
// IMPORTANT: callers MUST check IsEnabled() (or the --with-cve flag) before
// calling this function. EnrichComponents performs a querybatch network call
// regardless of the env gate; the gate check lives in the callers.
func (c *Client) EnrichComponents(ctx context.Context, components []models.SBOMComponent) []OSVVulnerability {
	type workItem struct {
		comp      models.SBOMComponent
		ecosystem string
		pkgName   string
		version   string
	}

	// Build the work list: only supported ecosystems with a version.
	var work []workItem
	for _, comp := range components {
		eco, name, ver, ok := purlToOSV(comp.Purl)
		if !ok {
			continue
		}
		work = append(work, workItem{comp: comp, ecosystem: eco, pkgName: name, version: ver})
	}
	if len(work) == 0 {
		return nil
	}

	// Build the querybatch request body.
	queries := make([]osvQuery, 0, len(work))
	for _, w := range work {
		queries = append(queries, osvQuery{
			Package: osvPackage{Name: w.pkgName, Ecosystem: w.ecosystem},
			Version: w.version,
		})
	}

	ids, err := c.queryBatch(ctx, queries)
	if err != nil {
		log.WithError(err).Debug("osv: querybatch failed; skipping enrichment")
		return nil
	}

	// Collect unique vuln IDs per work-item index.
	type idSet struct {
		itemIdx int
		vulnIDs []string
	}

	// ids[i] corresponds to work[i].
	var pending []idSet
	for i, batch := range ids {
		if len(batch) > 0 {
			pending = append(pending, idSet{itemIdx: i, vulnIDs: batch})
		}
	}
	if len(pending) == 0 {
		return nil
	}

	// Fan-out vuln detail fetches with bounded concurrency.
	type result struct {
		vuln   *OSVVulnerability
		bomRef string
	}

	resultCh := make(chan result, len(pending)*4)
	sem := make(chan struct{}, osvMaxConcurrency)
	var wg sync.WaitGroup

	for _, p := range pending {
		bomRef := work[p.itemIdx].comp.BomRef
		for _, vulnID := range p.vulnIDs {
			wg.Add(1)
			sem <- struct{}{}
			go func(id, ref string) {
				defer wg.Done()
				defer func() { <-sem }()
				vuln, err := c.fetchVuln(ctx, id)
				if err != nil {
					log.WithField("osv_id", id).Debug("osv: fetchVuln failed")
					return
				}
				vuln.AffectedBomRef = ref
				resultCh <- result{vuln: vuln, bomRef: ref}
			}(vulnID, bomRef)
		}
	}

	wg.Wait()
	close(resultCh)

	var vulns []OSVVulnerability
	for r := range resultCh {
		vulns = append(vulns, *r.vuln)
	}
	return vulns
}

// ---- OSV wire types --------------------------------------------------------

type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

type osvVulnDetail struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific *struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// ---- network helpers -------------------------------------------------------

// queryBatch posts a /v1/querybatch request and returns a slice of vuln-ID
// slices, one per input query. The outer slice always has the same length as
// queries; an entry is nil when no vulns were found for that component.
func (c *Client) queryBatch(ctx context.Context, queries []osvQuery) ([][]string, error) {
	body, err := json.Marshal(osvQueryBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("osv querybatch marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv querybatch build req: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MORF-osv-client")

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("osv rate limit: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv querybatch do: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv querybatch status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, osvMaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("osv querybatch read body: %w", err)
	}

	var batch osvQueryBatchResponse
	if err := json.Unmarshal(respBody, &batch); err != nil {
		return nil, fmt.Errorf("osv querybatch unmarshal: %w", err)
	}

	out := make([][]string, len(queries))
	for i, r := range batch.Results {
		if i >= len(queries) {
			break
		}
		ids := make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			if v.ID != "" {
				ids = append(ids, v.ID)
			}
		}
		if len(ids) > 0 {
			out[i] = ids
		}
	}
	return out, nil
}

// fetchVuln fetches a single vulnerability detail from /v1/vulns/{id}.
func (c *Client) fetchVuln(ctx context.Context, id string) (*OSVVulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("osv fetchVuln build req: %w", err)
	}
	req.Header.Set("User-Agent", "MORF-osv-client")

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("osv rate limit: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv fetchVuln do: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv fetchVuln status %d for %s", resp.StatusCode, id)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, osvMaxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("osv fetchVuln read body: %w", err)
	}

	var detail osvVulnDetail
	if err := json.Unmarshal(respBody, &detail); err != nil {
		return nil, fmt.Errorf("osv fetchVuln unmarshal %s: %w", id, err)
	}

	vuln := &OSVVulnerability{
		ID:         detail.ID,
		Aliases:    detail.Aliases,
		Summary:    truncate(detail.Summary, 256),
		SourceName: "OSV",
		SourceURL:  "https://osv.dev/vulnerability/" + detail.ID,
	}

	// Extract the highest CVSS score / severity from the severity array.
	sev, score, vec := resolveSeverity(detail)
	vuln.Severity = sev
	vuln.CVSS = score
	vuln.CVSSVector = vec

	// Fall back to database_specific.severity when no CVSS is present.
	if vuln.Severity == "" && detail.DatabaseSpecific != nil && detail.DatabaseSpecific.Severity != "" {
		vuln.Severity = strings.ToLower(detail.DatabaseSpecific.Severity)
	}
	if vuln.Severity == "" {
		vuln.Severity = "unknown"
	}

	return vuln, nil
}

// ---- purl -> OSV ecosystem -------------------------------------------------

// purlToOSV extracts (ecosystem, packageName, version, ok) from a purl string.
// Returns ok=false when the purl type is unsupported or the version is missing.
//
// Supported mappings:
//
//	pkg:maven/<group>/<artifact>@<ver>  -> "Maven",  "<group>:<artifact>"
//	pkg:pub/<name>@<ver>               -> "Pub",     "<name>"
//	pkg:npm/<name>@<ver>               -> "npm",     "<name>"
//	pkg:swift/<host>@<ver>             -> "SwiftURL","https://<host>"
func purlToOSV(purl string) (ecosystem, pkgName, version string, ok bool) {
	if purl == "" {
		return "", "", "", false
	}

	// Split scheme: pkg:<type>/<rest>
	rest, found := strings.CutPrefix(purl, "pkg:")
	if !found {
		return "", "", "", false
	}

	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return "", "", "", false
	}
	purlType := rest[:slashIdx]
	nameAndVer := rest[slashIdx+1:] // everything after "pkg:<type>/"

	// Extract version: last '@' token.
	var ver string
	atIdx := strings.LastIndex(nameAndVer, "@")
	if atIdx >= 0 {
		ver = nameAndVer[atIdx+1:]
		nameAndVer = nameAndVer[:atIdx]
	}
	if ver == "" {
		return "", "", "", false // no version => skip
	}

	switch purlType {
	case "maven":
		// pkg:maven/<group>/<artifact>  -> name = "<group>:<artifact>"
		// nameAndVer is "<group>/<artifact>" at this point.
		parts := strings.SplitN(nameAndVer, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", "", false
		}
		return "Maven", parts[0] + ":" + parts[1], ver, true

	case "pub":
		if nameAndVer == "" {
			return "", "", "", false
		}
		return "Pub", nameAndVer, ver, true

	case "npm":
		if nameAndVer == "" {
			return "", "", "", false
		}
		return "npm", nameAndVer, ver, true

	case "swift":
		// pkg:swift/<host>/<org>/<repo>  -> OSV name = "https://<host>/<org>/<repo>"
		if nameAndVer == "" {
			return "", "", "", false
		}
		return "SwiftURL", "https://" + nameAndVer, ver, true

	default:
		// cocoapods, generic, etc. — not supported.
		return "", "", "", false
	}
}

// ---- helpers ---------------------------------------------------------------

// resolveSeverity picks the highest CVSS severity from the OSV severity array.
// Returns (severityLabel, scoreString, vectorString).
func resolveSeverity(d osvVulnDetail) (sev, score, vec string) {
	// CVSS rank order: CRITICAL > HIGH > MEDIUM > LOW > NONE.
	rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1}
	bestRank := -1

	for _, s := range d.Severity {
		label, sc, v := parseCVSS(s.Type, s.Score)
		if r, ok := rank[label]; ok && r > bestRank {
			bestRank = r
			sev = label
			score = sc
			vec = v
		}
	}
	return
}

// parseCVSS extracts (severityLabel, scoreString, vectorString) from an OSV
// severity entry. OSV uses type="CVSS_V3" with the vector as Score field.
func parseCVSS(typ, scoreField string) (label, score, vec string) {
	_ = typ // reserved for future CVSS v2/v4 handling
	// scoreField is the CVSS vector string, e.g.
	// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	// The base score is not included in the OSV field directly; derive severity
	// from the vector's components when possible, else return "unknown".
	vec = scoreField

	// Extract a numeric base score if the vector contains "/", otherwise treat the
	// field itself as a plain score string (some OSV records supply a number).
	if !strings.Contains(scoreField, "/") {
		// Plain numeric score string, e.g. "9.8".
		score = scoreField
		label = scoreToLabel(scoreField)
		vec = ""
		return
	}

	// Derive severity from CVSS 3.x vector: look for the component score that
	// can be inferred. We use a simple heuristic on the Confidentiality/Integrity/
	// Availability impact to avoid importing a full CVSS library.
	// For MORF's purposes (triage), a conservative label is better than none.
	label = severityFromVector(scoreField)
	return
}

// scoreToLabel maps a numeric CVSS score string to a severity label.
func scoreToLabel(s string) string {
	var f float64
	_, _ = fmt.Sscanf(s, "%f", &f)
	switch {
	case f >= 9.0:
		return "critical"
	case f >= 7.0:
		return "high"
	case f >= 4.0:
		return "medium"
	case f > 0:
		return "low"
	default:
		return "unknown"
	}
}

// severityFromVector infers a CVSS 3.x severity label from the vector string
// without importing a full CVSS calculator. It uses the C/I/A IMPACT metrics as
// a proxy, counting only their High/Medium values. Crucially it does NOT do a
// naive strings.Count(":H"): the AC (Attack Complexity) and PR (Privileges
// Required) metrics also take an "H" value, but there "H" LOWERS severity
// (harder to exploit) — counting those inflated the label (e.g. AC:H + C:H was
// scored "high" when the real CVSS base is ~5.1 "medium"). Only C/I/A are
// counted here. Scope:Changed widens impact and can push into the critical band.
func severityFromVector(vec string) string {
	countH, countM := 0, 0
	for _, part := range strings.Split(vec, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "C", "I", "A": // Confidentiality / Integrity / Availability impact
			switch kv[1] {
			case "H":
				countH++
			case "M": // not a valid full-CVSS impact value, but tolerated as a proxy
				countM++
			}
		}
	}
	// Scope:Changed pushes the impact into a wider (potentially critical) range.
	scopeChanged := strings.Contains(vec, "S:C")

	switch {
	case (countH >= 3 && scopeChanged) || countH >= 4:
		return "critical"
	case countH >= 2 || (countH >= 1 && scopeChanged):
		return "high"
	case countH >= 1 || countM >= 2:
		return "medium"
	case countM >= 1:
		return "low"
	default:
		return "unknown"
	}
}

// truncate limits s to maxLen runes, appending "…" when truncated.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-1]) + "…"
}
