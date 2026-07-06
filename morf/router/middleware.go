package router

import (
	"fmt"
	"morf/config"
	"morf/metrics"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// CorrelationIDMiddleware adds correlation IDs to requests for tracing
func CorrelationIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get or generate request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// The correlation ID is only read back via the gin context (c.Get)
		// and the response header, so we avoid cloning *http.Request with
		// WithContext(...) — that allocation was a no-op copy on every request.
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()

		// Emit exactly one structured log line per request, after the chain
		// has run. Doing it post-Next (rather than a "started"/"completed"
		// pair around it) collapses the three synchronous logrus writes that
		// previously sat ahead of the rate limiter into a single cheap call,
		// and lets us record the final status in the same line.
		log.WithFields(log.Fields{
			"request_id": requestID,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"ip":         c.ClientIP(),
			"status":     c.Writer.Status(),
		}).Info("request")
	}
}

// RateLimiter is a per-IP token-bucket limiter with idle-cleanup.
// Defaults are tuned for upload endpoints; values are configurable via env:
//
//	MORF_RATE_LIMIT_RPS    requests per second (token refill rate, default 5)
//	MORF_RATE_LIMIT_BURST  bucket size              (default 10)
//	MORF_RATE_LIMIT_IDLE   idle TTL before reaping  (default 10m)
//
// Setting RPS=0 disables the limiter entirely.
//
// The visitor map is sharded across rlShardCount independent shards, each with
// its own mutex, so concurrent requests from different IPs almost never
// contend on the same lock. This replaces the previous single global mutex,
// which serialized every request through one lock under load.
type RateLimiter struct {
	shards [rlShardCount]rlShard
	rps    rate.Limit
	burst  int
	idle   time.Duration
}

// rlShardCount must be a power of two so shard selection can mask the hash.
const rlShardCount = 32

type rlShard struct {
	mu       sync.Mutex
	visitors map[string]*rateVisitor
}

type rateVisitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter constructs a limiter from env or the supplied defaults.
func NewRateLimiter() *RateLimiter {
	rps := envFloat("MORF_RATE_LIMIT_RPS", 5)
	burst := envIntDefault("MORF_RATE_LIMIT_BURST", 10)
	idle := envDuration("MORF_RATE_LIMIT_IDLE", 10*time.Minute)

	// Clamp burst to a positive floor. rate.NewLimiter(rps, 0) yields a
	// zero-capacity bucket whose .Allow() rejects 100% of traffic with 429
	// whenever rps>0, bricking the API; guard against an out-of-range env value.
	if burst < 1 {
		log.Warnf("MORF_RATE_LIMIT_BURST=%d is out of range; clamping to 10", burst)
		burst = 10
	}
	// Clamp idle to a positive floor. time.NewTicker panics with
	// "non-positive interval for NewTicker" when idle <= 0, and the reaper runs
	// in an unrecovered background goroutine, so a 0 value would crash the
	// entire server process at startup.
	if idle <= 0 {
		log.Warnf("MORF_RATE_LIMIT_IDLE=%s is non-positive; clamping to 10m", idle)
		idle = 10 * time.Minute
	}

	rl := &RateLimiter{
		rps:   rate.Limit(rps),
		burst: burst,
		idle:  idle,
	}
	for i := range rl.shards {
		rl.shards[i].visitors = make(map[string]*rateVisitor)
	}
	if rps > 0 {
		go rl.reaper()
	}
	return rl
}

// shardFor selects a shard by FNV-1a hashing the IP. The hash is computed
// inline to avoid the allocation that hash/fnv's hasher would incur per call.
func (rl *RateLimiter) shardFor(ip string) *rlShard {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	var h uint32 = offset32
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= prime32
	}
	return &rl.shards[h&(rlShardCount-1)]
}

func (rl *RateLimiter) get(ip string) *rate.Limiter {
	s := rl.shardFor(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.visitors[ip]
	if !ok {
		v = &rateVisitor{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		s.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *RateLimiter) reaper() {
	ticker := time.NewTicker(rl.idle)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.idle)
		for i := range rl.shards {
			s := &rl.shards[i]
			s.mu.Lock()
			for ip, v := range s.visitors {
				if v.lastSeen.Before(cutoff) {
					delete(s.visitors, ip)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Middleware returns a Gin handler enforcing the bucket. RPS=0 is a no-op.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if rl.rps <= 0 {
			c.Next()
			return
		}
		ip := c.ClientIP()
		if !rl.get(ip).Allow() {
			metrics.RecordError("rate_limited")
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": 1,
			})
			return
		}
		c.Next()
	}
}

// envFloat reads a float from env with default fallback. It delegates to the
// shared config helper so parsing lives in one place.
func envFloat(name string, def float64) float64 {
	return config.Float(name, def)
}

// envIntDefault reads an int from env with default fallback.
func envIntDefault(name string, def int) int {
	return config.Int(name, def)
}

// envDuration reads a Go duration from env with default fallback.
func envDuration(name string, def time.Duration) time.Duration {
	return config.Duration(name, def)
}

// MetricsMiddleware records HTTP request metrics
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		method := c.Request.Method

		// Skip metrics endpoint to avoid recursion
		if path == "/api/metrics" {
			c.Next()
			return
		}

		c.Next()

		// Record metrics
		status := fmt.Sprintf("%d", c.Writer.Status())
		duration := time.Since(start).Seconds()

		metrics.RecordHTTPRequest(method, path, status)
		metrics.RecordHTTPRequestDuration(method, path, duration)
	}
}
