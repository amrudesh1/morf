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
	result := gormDB.Where("key = ?", hashedKey).First(&key)
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

	// Create new limiter: requestsPerHour requests per hour
	limiter = rate.NewLimiter(rate.Every(time.Hour/time.Duration(requestsPerHour)), requestsPerHour)

	rl.mu.Lock()
	rl.limiters[keyID] = limiter
	rl.mu.Unlock()

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
