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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Safety controls (see package doc / VerifySecrets). These bound how hard
// verification can hit any provider even for a very large finding set.
const (
	// userAgent is sent on every outbound verification request so providers can
	// attribute the traffic to MORF.
	userAgent = "MORF-verifier"

	// perRequestTimeout caps a single verification HTTP request.
	perRequestTimeout = 5 * time.Second

	// rateLimit / rateBurst throttle the GLOBAL outbound request rate shared
	// across all verifiers so a large scan cannot hammer providers.
	rateLimit = rate.Limit(5) // 5 requests/second, steady state
	rateBurst = 5

	// cacheTTL bounds how long a verification outcome is reused before the
	// provider is contacted again for the same secret.
	cacheTTL = 5 * time.Minute
)

// cacheEntry is a cached verification outcome keyed by sha256(secret).
type cacheEntry struct {
	status  string
	expires time.Time
}

// client bundles the shared, process-wide verification machinery: a single
// http.Client, a global rate limiter, and an in-memory result cache keyed by
// sha256 of the secret (never the raw secret). It is safe for concurrent use.
type client struct {
	http    *http.Client
	limiter *rate.Limiter

	mu    sync.Mutex
	cache map[string]cacheEntry

	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

// newClient builds the shared verification client with the default safety
// controls. Redirects are NOT followed so a credential is never replayed to an
// unexpected host.
func newClient() *client {
	return &client{
		http: &http.Client{
			Timeout: perRequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		limiter: rate.NewLimiter(rateLimit, rateBurst),
		cache:   make(map[string]cacheEntry),
		now:     time.Now,
	}
}

// hashSecret returns the sha256 hex digest of a secret. Used only as a cache
// key so the raw secret is never stored or logged.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// cacheGet returns a cached, non-expired status for the given secret hash.
func (c *client) cacheGet(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok {
		return "", false
	}
	if c.now().After(e.expires) {
		delete(c.cache, key)
		return "", false
	}
	return e.status, true
}

// cacheSet records a verification outcome for the given secret hash. Only
// definitive outcomes ("active"/"inactive") are cached; "unknown" is left
// uncached so a transient failure is retried on a later scan.
func (c *client) cacheSet(key, status string) {
	if status != statusActive && status != statusInactive {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = cacheEntry{status: status, expires: c.now().Add(cacheTTL)}
}

// do performs a rate-limited, read-only HTTP request using the shared client.
// The request's method MUST be a safe method (GET/HEAD); callers construct
// requests accordingly. It blocks on the global limiter until ctx is done.
func (c *client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return c.http.Do(req)
}
