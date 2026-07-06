/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"morf/models"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// TestRequireScope covers MED-scopes enforcement: deny anonymous (401), allow on
// exact match or "*" wildcard, deny on a missing scope (403), no-op on empty.
func TestRequireScope(t *testing.T) {
	cases := []struct {
		name     string
		setScope interface{}
		set      bool
		require  string
		wantCode int
	}{
		{"exact match allows", models.JSONStringArray{"scan:write"}, true, "scan:write", http.StatusOK},
		{"wildcard allows", models.JSONStringArray{"*"}, true, "scan:write", http.StatusOK},
		{"missing scope forbidden", models.JSONStringArray{"read"}, true, "scan:write", http.StatusForbidden},
		{"unauthenticated denied", nil, false, "scan:write", http.StatusUnauthorized},
		{"empty requirement is no-op", nil, false, "", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/api/patterns", nil)
			if c.set {
				ctx.Set("scopes", c.setScope)
			}
			RequireScope(c.require)(ctx)
			// On allow, RequireScope calls Next() (no handler) and does not write a
			// status, so the recorder stays at the default 200.
			if w.Code != c.wantCode {
				t.Errorf("status = %d, want %d (aborted=%v)", w.Code, c.wantCode, ctx.IsAborted())
			}
		})
	}
}

func TestNormalizeScopes(t *testing.T) {
	cases := []struct {
		in   interface{}
		want []string
	}{
		{models.JSONStringArray{"a", "b"}, []string{"a", "b"}},
		{[]string{"x"}, []string{"x"}},
		{"p, q ,r", []string{"p", "q", "r"}},
		{"", nil},
		{nil, nil},
	}
	for _, c := range cases {
		got := normalizeScopes(c.in)
		if len(got) != len(c.want) {
			t.Errorf("normalizeScopes(%v) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("normalizeScopes(%v)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestAPIKeyAuthSelective covers S-2: when global auth is OFF (enforceAll=false)
// non-sensitive routes pass through unauthenticated, but the sensitive SSRF /
// pattern-mutation routes are still challenged. When enforceAll=true everything
// is challenged. (No DB needed: a missing key is rejected before any lookup.)
func TestAPIKeyAuthSelective(t *testing.T) {
	build := func(enforceAll bool) *gin.Engine {
		r := gin.New()
		g := r.Group("/api")
		g.Use(APIKeyAuthSelective(enforceAll))
		ok := func(c *gin.Context) { c.String(http.StatusOK, "ok") }
		g.GET("/results/:jobID", ok)
		g.POST("/jira", ok)
		g.POST("/patterns/:filename", ok)
		g.GET("/patterns", ok)
		return r
	}

	do := func(r *gin.Engine, method, path string) int {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}

	off := build(false)
	if code := do(off, http.MethodGet, "/api/results/abc"); code != http.StatusOK {
		t.Errorf("global-off non-sensitive GET /results = %d, want 200 (pass-through)", code)
	}
	if code := do(off, http.MethodGet, "/api/patterns"); code != http.StatusOK {
		t.Errorf("global-off GET /patterns (read) = %d, want 200 (pass-through)", code)
	}
	if code := do(off, http.MethodPost, "/api/jira"); code != http.StatusUnauthorized {
		t.Errorf("global-off sensitive POST /jira = %d, want 401", code)
	}
	if code := do(off, http.MethodPost, "/api/patterns/x.yaml"); code != http.StatusUnauthorized {
		t.Errorf("global-off sensitive POST /patterns/:filename = %d, want 401", code)
	}

	on := build(true)
	if code := do(on, http.MethodGet, "/api/results/abc"); code != http.StatusUnauthorized {
		t.Errorf("global-on GET /results = %d, want 401 (all enforced)", code)
	}
}
