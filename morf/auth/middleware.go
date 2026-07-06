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

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"morf/db"
	"morf/models"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

// APIKeyAuth middleware validates API keys
func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract API key from header or query parameter
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key required. Provide X-API-Key header or api_key query parameter",
			})
			c.Abort()
			return
		}

		// Validate API key. Successful validations are served from a short-lived
		// in-memory cache so repeated requests from the same key don't hit the DB
		// on every call (see validateAPIKeyCached / SetAPIKeyCacheTTL).
		key, err := validateAPIKeyCached(apiKey)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
				"ip":    c.ClientIP(),
			}).Warn("Invalid API key attempt")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}

		// Check if key is valid (active and not expired)
		if !key.IsValid() {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key is inactive or expired",
			})
			c.Abort()
			return
		}

		// Record usage WITHOUT blocking the request. The last-used timestamp is
		// accumulated in memory and flushed to the DB in coalesced batches by a
		// background goroutine, replacing the old synchronous per-request UPDATE.
		recordKeyUsage(key.ID)

		// Set API key info in context
		c.Set("api_key_id", key.ID)
		c.Set("api_key_name", key.Name)
		c.Set("scopes", key.Scopes)
		c.Set("rate_limit", key.RateLimit)

		c.Next()
	}
}

// isSensitiveAPIPath reports whether the matched route is a high-risk surface
// that must be authenticated even when global API-key auth is opted out: the
// SSRF integration routes (/api/jira, /api/slackscan) and any non-GET method
// under /api/patterns (pattern mutation). It keys off the gin route pattern
// (FullPath) so it is stable regardless of path params.
func isSensitiveAPIPath(c *gin.Context) bool {
	switch c.FullPath() {
	case "/api/jira", "/api/slackscan":
		return true
	}
	if strings.HasPrefix(c.FullPath(), "/api/patterns") && c.Request.Method != http.MethodGet {
		return true
	}
	return false
}

// APIKeyAuthSelective wraps APIKeyAuth for fail-closed defaults (S-2). When
// enforceAll is true every data route is authenticated. When false (operator set
// MORF_REQUIRE_API_KEY=false) it still authenticates the sensitive SSRF/pattern
// routes via isSensitiveAPIPath, so the high-blast-radius surface is never
// exposed unauthenticated, while read/scan routes stay open. APIKeyAuth advances
// the handler chain itself on success, so the wrapper must not call c.Next()
// after delegating.
func APIKeyAuthSelective(enforceAll bool) gin.HandlerFunc {
	inner := APIKeyAuth()
	return func(c *gin.Context) {
		if enforceAll || isSensitiveAPIPath(c) {
			inner(c)
			return
		}
		c.Next()
	}
}

// RequireScopeForSensitive enforces the given scope only on the sensitive
// SSRF/pattern-mutation routes (MED-scopes). It is intended to be enabled by an
// operator (e.g. MORF_ENFORCE_SCOPES=true) once scoped keys are provisioned,
// because enabling it without a key-management surface to assign scopes would
// deny every key.
func RequireScopeForSensitive(scope string) gin.HandlerFunc {
	checker := RequireScope(scope)
	return func(c *gin.Context) {
		if isSensitiveAPIPath(c) {
			checker(c)
			return
		}
		c.Next()
	}
}

// RequireScope returns a middleware that enforces the authenticated API key
// carries the named scope. It must run AFTER APIKeyAuth, which stores the key's
// scopes on the context at key "scopes" (see APIKeyAuth above).
//
// Behaviour:
//   - If the context has no scopes set, the request was not authenticated by
//     APIKeyAuth; deny with 401 (cannot evaluate scope on an anonymous request).
//   - If the key's scope set contains "*" (wildcard) or the required scope, the
//     request is allowed.
//   - Otherwise the request is denied with 403.
//
// An empty required scope is treated as a no-op (allow) so callers can compose
// it unconditionally. The scopes value is matched against the type APIKeyAuth
// stores (models.JSONStringArray), with []string and a comma-separated string
// also accepted for robustness.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Empty requirement: nothing to enforce.
		if scope == "" {
			c.Next()
			return
		}

		raw, exists := c.Get("scopes")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key required",
			})
			c.Abort()
			return
		}

		scopes := normalizeScopes(raw)
		for _, s := range scopes {
			if s == "*" || s == scope {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "API key missing required scope: " + scope,
		})
		c.Abort()
	}
}

// normalizeScopes coerces the context "scopes" value into a []string,
// accepting the stored models.JSONStringArray, a plain []string, or a
// comma-separated string.
func normalizeScopes(raw interface{}) []string {
	switch v := raw.(type) {
	case models.JSONStringArray:
		return []string(v)
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// Cached API-key validation
//
// Validating an API key requires a DB lookup. Doing that on every single
// request is wasteful under load, so successful validations are cached
// in-memory for a short, configurable TTL (default 60s). Repeated requests
// from the same key are then served from the cache without touching the DB.
// Only successful validations are cached; invalid keys always fall through to
// the DB so revocations/expiries take effect within at most one TTL window.
// ---------------------------------------------------------------------------

// defaultAPIKeyCacheTTL is the default lifetime of a cached validated key.
const defaultAPIKeyCacheTTL = 60 * time.Second

// apiKeyCacheTTLNanos holds the cache TTL in nanoseconds, stored atomically so
// it can be reconfigured safely at runtime via SetAPIKeyCacheTTL.
var apiKeyCacheTTLNanos atomic.Int64

// apiKeyCache maps a hashed API key -> cachedAPIKey. A sync.Map suits the
// read-heavy access pattern over a small, stable set of keys.
var apiKeyCache sync.Map

// cachedAPIKey is a single cache entry for a validated API key.
type cachedAPIKey struct {
	key       *models.APIKey
	expiresAt time.Time
}

func init() {
	apiKeyCacheTTLNanos.Store(int64(defaultAPIKeyCacheTTL))
}

// SetAPIKeyCacheTTL configures how long a validated API key stays cached.
// A non-positive duration disables caching (every request hits the DB).
func SetAPIKeyCacheTTL(ttl time.Duration) {
	apiKeyCacheTTLNanos.Store(int64(ttl))
}

func apiKeyCacheTTL() time.Duration {
	return time.Duration(apiKeyCacheTTLNanos.Load())
}

// validateAPIKeyCached validates an API key, serving it from the in-memory
// cache when a fresh entry exists. The cached *models.APIKey is treated as
// read-only by callers, so it is safe to share across concurrent requests.
func validateAPIKeyCached(apiKey string) (*models.APIKey, error) {
	ttl := apiKeyCacheTTL()
	hashed := hashAPIKey(apiKey)

	if ttl > 0 {
		if v, ok := apiKeyCache.Load(hashed); ok {
			entry := v.(cachedAPIKey)
			if time.Now().Before(entry.expiresAt) {
				return entry.key, nil
			}
			apiKeyCache.Delete(hashed)
		}
	}

	key, err := ValidateAPIKey(apiKey, db.GormDB)
	if err != nil {
		return nil, err
	}

	if ttl > 0 {
		apiKeyCache.Store(hashed, cachedAPIKey{
			key:       key,
			expiresAt: time.Now().Add(ttl),
		})
	}
	return key, nil
}

// InvalidateAPIKeyCache evicts a single API key from the validation cache.
//
// Row 062: the cache stores the full *models.APIKey, including its IsActive
// flag, so a revocation (IsActive=false) or any other DB-side change is not
// observed until the cached entry's TTL elapses (default 60s). Call this from
// the code path that revokes/deactivates or otherwise mutates a key so the
// change takes effect immediately on the next request instead of after the
// TTL window. The plain API key (the value clients send) must be passed
// because the cache is keyed by the hashed key.
func InvalidateAPIKeyCache(apiKey string) {
	apiKeyCache.Delete(hashAPIKey(apiKey))
}

// ---------------------------------------------------------------------------
// Asynchronous, batched API-key usage tracking
//
// Recording "last used" on every authenticated request used to issue a
// synchronous UPDATE, a throughput killer at scale. Instead, usage is
// accumulated in memory and flushed to the DB periodically by a single
// background goroutine. Multiple requests for the same key between flushes are
// coalesced into a single UPDATE.
// ---------------------------------------------------------------------------

// defaultUsageFlushInterval is how often buffered usage is flushed by default.
const defaultUsageFlushInterval = 30 * time.Second

// usageFlushInterval is read once when the flusher starts. Configure it via
// SetUsageFlushInterval before calling StartAPIKeyUsageFlusher.
var usageFlushInterval = defaultUsageFlushInterval

// keyUsage accumulates pending usage for a single API key between flushes.
type keyUsage struct {
	lastSeen time.Time
	count    int64 // number of coalesced requests since the last flush
}

var (
	usageMu      sync.Mutex
	pendingUsage = make(map[uint]*keyUsage)
	flusherOnce  sync.Once
)

// SetUsageFlushInterval configures how often pending usage is flushed to the
// DB. Call it before StartAPIKeyUsageFlusher; it has no effect afterwards.
func SetUsageFlushInterval(d time.Duration) {
	if d > 0 {
		usageFlushInterval = d
	}
}

// recordKeyUsage records that keyID was just used. It never blocks on the DB;
// the update is buffered in memory and flushed asynchronously. The flusher is
// started lazily on first use if main did not start it explicitly.
func recordKeyUsage(keyID uint) {
	now := time.Now()

	usageMu.Lock()
	u, ok := pendingUsage[keyID]
	if !ok {
		u = &keyUsage{}
		pendingUsage[keyID] = u
	}
	u.lastSeen = now
	u.count++
	usageMu.Unlock()

	// Lazily start the flusher with a background context if main didn't.
	StartAPIKeyUsageFlusher(context.Background())
}

// StartAPIKeyUsageFlusher starts the background goroutine that periodically
// flushes buffered API-key usage to the database. It is safe to call multiple
// times; only the first call actually starts the flusher (guarded by
// sync.Once), so an explicit call from main and the middleware's lazy fallback
// never race into two goroutines. The goroutine stops when ctx is cancelled,
// performing one final flush, so there is no goroutine leak.
func StartAPIKeyUsageFlusher(ctx context.Context) {
	flusherOnce.Do(func() {
		go runUsageFlusher(ctx)
	})
}

func runUsageFlusher(ctx context.Context) {
	ticker := time.NewTicker(usageFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			flushPendingUsage() // final flush on shutdown
			return
		case <-ticker.C:
			flushPendingUsage()
		}
	}
}

// flushPendingUsage writes all buffered usage to the DB in a single batched
// pass: one coalesced UPDATE per key. It swaps the pending map out under the
// lock so request handlers are never blocked on the DB writes.
func flushPendingUsage() {
	usageMu.Lock()
	if len(pendingUsage) == 0 {
		usageMu.Unlock()
		return
	}
	batch := pendingUsage
	pendingUsage = make(map[uint]*keyUsage)
	usageMu.Unlock()

	gormDB := db.GormDB
	if gormDB == nil {
		log.Warn("API key usage flush skipped: database not initialized")
		return
	}

	for keyID, u := range batch {
		if err := gormDB.Model(&models.APIKey{}).
			Where("id = ?", keyID).
			Update("last_used", u.lastSeen).Error; err != nil {
			log.WithFields(log.Fields{
				"error":      err.Error(),
				"api_key_id": keyID,
				"requests":   u.count,
			}).Warn("Failed to flush API key usage")
		}
	}
}

// ValidateAPIKey validates an API key against the database
func ValidateAPIKey(apiKey string, gormDB *gorm.DB) (*models.APIKey, error) {
	if gormDB == nil {
		return nil, gorm.ErrRecordNotFound
	}

	// Hash the provided key for comparison
	hashedKey := hashAPIKey(apiKey)

	var key models.APIKey
	// `key` is a MySQL reserved word; GORM does not quote raw Where strings, so
	// it must be backtick-quoted or the query fails with a 1064 syntax error.
	result := gormDB.Where("`key` = ?", hashedKey).First(&key)
	if result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// hashAPIKey hashes an API key using SHA256
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// GenerateAPIKey generates a new API key (returns both plain and hashed versions)
func GenerateAPIKey() (plainKey string, hashedKey string) {
	// Generate a random key (using UUID-like format)
	plainKey = generateRandomKey()
	hashedKey = hashAPIKey(plainKey)
	return plainKey, hashedKey
}

// generateRandomKey generates a random API key string using crypto/rand
func generateRandomKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based if crypto/rand fails
		log.Warn("Failed to generate random key with crypto/rand, using fallback")
		for i := range b {
			b[i] = byte(time.Now().UnixNano() % 256)
		}
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// RateLimiter provides per-API-key rate limiting
type RateLimiter struct {
	limiters map[uint]*rate.Limiter
	mu       sync.RWMutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[uint]*rate.Limiter),
	}
}

// GetLimiter gets or creates a rate limiter for an API key
func (rl *RateLimiter) GetLimiter(keyID uint, requestsPerHour int) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[keyID]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	// Row 066: guard against a zero/negative limit before computing the
	// interval. rate.Every divides time.Hour by requestsPerHour, which panics
	// with an integer divide-by-zero at 0 and yields a nonsensical interval
	// when negative. Fall back to the DB default of 100 requests/hour.
	if requestsPerHour <= 0 {
		requestsPerHour = 100
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Row 065: double-checked locking. Another goroutine may have created the
	// limiter between releasing the RLock above and acquiring this write lock.
	// Re-check under the write lock so concurrent callers for the same key
	// share a single limiter instance instead of overwriting each other's.
	if limiter, exists := rl.limiters[keyID]; exists {
		return limiter
	}

	// Create new limiter: requestsPerHour requests per hour
	limiter = rate.NewLimiter(rate.Every(time.Hour/time.Duration(requestsPerHour)), requestsPerHour)
	rl.limiters[keyID] = limiter

	return limiter
}

// globalRateLimiter is the global rate limiter instance
var globalRateLimiter = NewRateLimiter()

// RateLimitMiddleware provides rate limiting per API key
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key ID from context (set by APIKeyAuth middleware)
		keyID, exists := c.Get("api_key_id")
		if !exists {
			// If no API key, skip rate limiting (shouldn't happen if APIKeyAuth is applied first)
			c.Next()
			return
		}

		// Get rate limit from context
		rateLimit, exists := c.Get("rate_limit")
		if !exists {
			rateLimit = 100 // Default: 100 requests/hour
		}

		// Get limiter for this API key
		limiter := globalRateLimiter.GetLimiter(keyID.(uint), rateLimit.(int))

		// Check if request is allowed
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": int(time.Hour.Seconds()),
			})
			c.Header("Retry-After", "3600") // 1 hour in seconds
			c.Abort()
			return
		}

		c.Next()
	}
}
