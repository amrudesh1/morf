/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// TestRateLimiterBlocksAfterBurst verifies the per-IP token bucket admits up to
// `burst` requests then returns 429. Driven via env (NewRateLimiter reads its
// limits at construction). Refill is ~rps/sec so within a tight loop no token is
// replenished, making the counts deterministic.
func TestRateLimiterBlocksAfterBurst(t *testing.T) {
	t.Setenv("MORF_RATE_LIMIT_RPS", "1")
	t.Setenv("MORF_RATE_LIMIT_BURST", "2")
	rl := NewRateLimiter()

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	allowed, limited := 0, 0
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.7:5000"
		r.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", w.Code)
		}
	}
	if allowed != 2 {
		t.Errorf("allowed = %d, want 2 (burst)", allowed)
	}
	if limited != 3 {
		t.Errorf("limited(429) = %d, want 3", limited)
	}
}

// TestRateLimiterDisabledWhenRPSZero verifies RPS=0 disables limiting entirely
// (a guard against bricking the API).
func TestRateLimiterDisabledWhenRPSZero(t *testing.T) {
	t.Setenv("MORF_RATE_LIMIT_RPS", "0")
	rl := NewRateLimiter()

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.8:5000"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("rps=0 should not limit, got %d on request %d", w.Code, i)
		}
	}
}

// TestRateLimiterPerIPIsolation confirms one noisy IP does not exhaust another's
// bucket (sharded per-IP limiter).
func TestRateLimiterPerIPIsolation(t *testing.T) {
	t.Setenv("MORF_RATE_LIMIT_RPS", "1")
	t.Setenv("MORF_RATE_LIMIT_BURST", "1")
	rl := NewRateLimiter()

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	hit := func(ip string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = ip + ":5000"
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := hit("198.51.100.1"); code != http.StatusOK {
		t.Errorf("first request from IP1 = %d, want 200", code)
	}
	if code := hit("198.51.100.1"); code != http.StatusTooManyRequests {
		t.Errorf("second request from IP1 = %d, want 429", code)
	}
	// A different IP still has its full burst.
	if code := hit("198.51.100.2"); code != http.StatusOK {
		t.Errorf("first request from IP2 = %d, want 200 (isolated bucket)", code)
	}
}
