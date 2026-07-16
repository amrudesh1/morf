/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newBodyLimitEngine builds a minimal engine that mirrors the production
// wiring: the JSON mutation route carries MaxBodyBytesMiddleware while the
// upload-style route does not. Handlers drain the body so the MaxBytesReader
// actually trips mid-read on a chunked/oversized request (not just on the
// Content-Length fast path).
func newBodyLimitEngine(limit int64) *gin.Engine {
	r := gin.New()
	r.POST("/patterns", MaxBodyBytesMiddleware(limit), func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			// A tripped MaxBytesReader surfaces here; the real handlers map
			// their bind error to 400. Mirror that so we can assert the body
			// cap is enforced even when Content-Length was absent/untruthful.
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.String(http.StatusOK, "ok")
	})
	// Upload route intentionally has NO body cap; it streams large APKs.
	r.POST("/upload", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.String(http.StatusOK, "ok")
	})
	return r
}

// TestMaxBodyBytesAllowsSmallBody confirms a body under the cap binds normally
// and reaches the handler with a 200.
func TestMaxBodyBytesAllowsSmallBody(t *testing.T) {
	r := newBodyLimitEngine(1 << 20) // 1 MiB

	body := `{"name":"test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/patterns", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("small body: got %d, want 200", w.Code)
	}
}

// TestMaxBodyBytesRejectsOversizedBody confirms an over-cap body on a capped
// route is rejected. With a truthful Content-Length the middleware fast-rejects
// with 413 up front.
func TestMaxBodyBytesRejectsOversizedBody(t *testing.T) {
	const limit = 1024
	r := newBodyLimitEngine(limit)

	oversized := strings.Repeat("a", limit*4)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/patterns", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body (known length): got %d, want 413", w.Code)
	}
}

// TestMaxBodyBytesRejectsOversizedChunkedBody confirms the MaxBytesReader trips
// mid-read when Content-Length is unknown (chunked). The fast path can't fire,
// so the reader must abort the body during the handler's read, yielding a 400.
func TestMaxBodyBytesRejectsOversizedChunkedBody(t *testing.T) {
	const limit = 1024
	r := newBodyLimitEngine(limit)

	oversized := strings.Repeat("a", limit*4)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/patterns", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	// Force the chunked path: no truthful Content-Length for the fast reject.
	req.ContentLength = -1
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized chunked body: got %d, want 400 (reader tripped)", w.Code)
	}
}

// TestMaxBodyBytesUploadRouteUnaffected proves the cap is scoped, not global:
// a body far larger than the JSON cap sails through the uncapped upload route.
func TestMaxBodyBytesUploadRouteUnaffected(t *testing.T) {
	const limit = 1024
	r := newBodyLimitEngine(limit)

	big := strings.Repeat("a", limit*100)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(big))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("upload route should be uncapped: got %d, want 200", w.Code)
	}
}

// TestMaxBodyBytesDefaultOnNonPositiveEnv verifies a misconfigured
// MORF_MAX_BODY_BYTES falls back to the default cap rather than disabling it.
func TestMaxBodyBytesDefaultOnNonPositiveEnv(t *testing.T) {
	t.Setenv("MORF_MAX_BODY_BYTES", "0")
	if got := maxBodyBytes(); got != defaultMaxBodyBytes {
		t.Fatalf("env=0: maxBodyBytes()=%d, want default %d", got, defaultMaxBodyBytes)
	}

	t.Setenv("MORF_MAX_BODY_BYTES", "2048")
	if got := maxBodyBytes(); got != 2048 {
		t.Fatalf("env=2048: maxBodyBytes()=%d, want 2048", got)
	}
}
