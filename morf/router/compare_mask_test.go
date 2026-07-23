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

package router

// Tests for the two security fixes in this package:
//
//   (A) compare_mask: GET /compare/:jobID1/:jobID2 must not leak raw secretString
//       values in Added/Removed/Unchanged slices (mirrors export_mask_test.go).
//
//   (B) perkey_ratelimit_auth_off: even when MORF_REQUIRE_API_KEY=false the
//       per-API-key RateLimitMiddleware must fire on the protected data routes
//       once an api_key_id is present in context (set by APIKeyAuthSelective
//       which still authenticates isProtectedDataPath even with global auth off).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"

	"morf/auth"
	"morf/models"
	"morf/queue"
	"morf/report"
	"morf/utils"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestQueue returns a miniredis-backed JobQueue and registers a test cleanup
// to close the miniredis server. It also sets queue.GlobalJobQueue so handlers
// that call queue.GetQueue() see the test queue. The previous GlobalJobQueue is
// restored on cleanup.
func newTestQueue(t *testing.T) *queue.JobQueue {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	// Use the exported NewJobQueue constructor with the miniredis address.
	q, err := queue.NewJobQueue(mr.Addr())
	if err != nil {
		t.Fatalf("queue.NewJobQueue: %v", err)
	}

	prev := queue.GlobalJobQueue
	queue.GlobalJobQueue = q
	t.Cleanup(func() { queue.GlobalJobQueue = prev })

	return q
}

// enqueueCompleted stores a completed ScanJob with the given result JSON.
func enqueueCompleted(t *testing.T, q *queue.JobQueue, id, resultJSON string) {
	t.Helper()
	job := &models.ScanJob{
		ID:     id,
		Status: models.JobStatusCompleted,
		Result: resultJSON,
	}
	if err := q.EnqueueJobAtomic(job); err != nil {
		t.Fatalf("EnqueueJobAtomic(%s): %v", id, err)
	}
}

// buildCompareRouter builds a minimal gin router that registers only the
// GET /compare/:jobID1/:jobID2 handler using the same logic as InitRouters,
// so we can drive it without a full auth/DB stack.
func buildCompareRouter(maskResults bool) *gin.Engine {
	r := gin.New()
	r.GET("/compare/:jobID1/:jobID2", func(c *gin.Context) {
		jobID1 := c.Param("jobID1")
		jobID2 := c.Param("jobID2")

		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "queue not initialized"})
			return
		}

		job1, err := queue.GetQueue().GetJob(jobID1)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Job %s not found", jobID1)})
			return
		}
		job2, err := queue.GetQueue().GetJob(jobID2)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Job %s not found", jobID2)})
			return
		}
		if job1.Status != models.JobStatusCompleted || job2.Status != models.JobStatusCompleted {
			c.JSON(http.StatusBadRequest, gin.H{"error": "both jobs must be completed"})
			return
		}

		comparison, err := utils.CompareScans(job1, job2)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if !maskResults {
			c.JSON(http.StatusOK, comparison)
			return
		}

		raw, marshalErr := json.Marshal(comparison)
		if marshalErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result_error": "result unavailable (masking failed)"})
			return
		}
		masked, maskErr := report.MaskComparisonJSON(raw)
		if maskErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"result_error": "result unavailable (masking failed)"})
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", masked)
	})
	return r
}

// resultJSON constructs a scan-result envelope with a single secret.
func resultJSON(secretValue string) string {
	return `{"data":{"fileName":"app.apk","packageName":"com.test","secrets":[` +
		`{"secretType":"AWS Access Key","secretString":"` + secretValue + `","fileLocation":"a.smali","lineNo":3}` +
		`]}}`
}

// ---------------------------------------------------------------------------
// (A) Compare masking tests
// ---------------------------------------------------------------------------

// TestCompareMask_DefaultMasksSecrets verifies that GET /compare leaks no raw
// AKIA… secret value in its response and that the masked ellipsis is present.
func TestCompareMask_DefaultMasksSecrets(t *testing.T) {
	const planted = "AKIAIOSFODNN7EXAMPLE"

	q := newTestQueue(t)
	enqueueCompleted(t, q, "job-cmp-1", resultJSON(planted))
	enqueueCompleted(t, q, "job-cmp-2", resultJSON(planted))

	r := buildCompareRouter(true /* mask */)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/compare/job-cmp-1/job-cmp-2", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if strings.Contains(body, planted) {
		t.Errorf("response LEAKED the raw secret %q in body: %s", planted, body)
	}
	if !strings.Contains(body, "…") {
		t.Errorf("response missing masked ellipsis (…); body: %s", body)
	}
}

// TestCompareMask_RawWhenMaskDisabled verifies that MORF_MASK_RESULTS=false
// returns the raw secret value (operator opt-out parity with /results).
func TestCompareMask_RawWhenMaskDisabled(t *testing.T) {
	const planted = "AKIAIOSFODNN7EXAMPLE"

	q := newTestQueue(t)
	enqueueCompleted(t, q, "job-raw-1", resultJSON(planted))
	enqueueCompleted(t, q, "job-raw-2", resultJSON(planted))

	r := buildCompareRouter(false /* no mask */)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/compare/job-raw-1/job-raw-2", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, planted) {
		t.Errorf("raw mode: expected %q in response, body: %s", planted, body)
	}
}

// TestCompareMask_AddedRemovedUnchangedAllMasked verifies that all three
// secret-list fields (added, removed, unchanged) have their secretStrings
// masked — not just one of them.
func TestCompareMask_AddedRemovedUnchangedAllMasked(t *testing.T) {
	const (
		secret1 = "AKIAIOSFODNN7EXAMPLE"
		secret2 = "AKIAY6KZEXAMPLEKEY99"
	)

	job1Result := `{"data":{"fileName":"app.apk","packageName":"com.test","secrets":[` +
		`{"secretType":"AWS Access Key","secretString":"` + secret1 + `","fileLocation":"a.smali","lineNo":1},` +
		`{"secretType":"AWS Access Key","secretString":"` + secret2 + `","fileLocation":"b.smali","lineNo":2}` +
		`]}}`
	job2Result := `{"data":{"fileName":"app2.apk","packageName":"com.test","secrets":[` +
		`{"secretType":"AWS Access Key","secretString":"` + secret2 + `","fileLocation":"b.smali","lineNo":2}` +
		`]}}`

	q := newTestQueue(t)
	enqueueCompleted(t, q, "job-all-1", job1Result)
	enqueueCompleted(t, q, "job-all-2", job2Result)

	r := buildCompareRouter(true /* mask */)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/compare/job-all-1/job-all-2", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	for _, raw := range []string{secret1, secret2} {
		if strings.Contains(body, raw) {
			t.Errorf("response LEAKED raw secret %q; body: %s", raw, body)
		}
	}
	if !strings.Contains(body, "…") {
		t.Errorf("response missing masked ellipsis (…); body: %s", body)
	}
}

// TestCompareMask_MaskComparisonJSONDirect tests report.MaskComparisonJSON
// in isolation (unit-level, no HTTP), mirroring export_mask_test.go style.
func TestCompareMask_MaskComparisonJSONDirect(t *testing.T) {
	const planted = "AKIAIOSFODNN7EXAMPLE"

	// Build a ComparisonResult JSON by hand with the planted value in all three
	// list fields to ensure all are masked.
	entry := fmt.Sprintf(`{"secretType":"AWS Access Key","secretString":"%s","fileLocation":"a.smali","lineNo":1}`, planted)
	raw := fmt.Sprintf(`{"job_id_1":"j1","job_id_2":"j2","added":[%s],"removed":[%s],"unchanged":[%s],"total_job_1":1,"total_job_2":1,"added_count":0,"removed_count":0,"unchanged_count":1}`,
		entry, entry, entry)

	masked, err := report.MaskComparisonJSON([]byte(raw))
	if err != nil {
		t.Fatalf("MaskComparisonJSON: %v", err)
	}

	body := string(masked)
	if strings.Contains(body, planted) {
		t.Errorf("MaskComparisonJSON LEAKED the raw secret %q; output: %s", planted, body)
	}
	if !strings.Contains(body, "…") {
		t.Errorf("MaskComparisonJSON missing masked ellipsis (…); output: %s", body)
	}
	// Structural fields must be preserved.
	if !strings.Contains(body, `"job_id_1":"j1"`) {
		t.Errorf("MaskComparisonJSON dropped job_id_1; output: %s", body)
	}
}

// ---------------------------------------------------------------------------
// (B) Per-key rate limit with auth disabled — harness note
// ---------------------------------------------------------------------------
//
// The per-key RateLimitMiddleware (auth.RateLimitMiddleware) is now registered
// unconditionally in InitRouters (the fix). Its behaviour is:
//   - when api_key_id is present in context → enforce the per-key token bucket
//   - when api_key_id is absent → skip (c.Next()), so open routes are unaffected
//
// Testing the full "auth off → protected route → key required by
// APIKeyAuthSelective → api_key_id set → rate limited" flow would require a live
// DB for ValidateAPIKey (called by APIKeyAuth) with no test-injectable hook. We
// cannot add a mock at that layer without touching auth/ code outside our unit
// surface, and we must not hit live DB endpoints.
//
// What we CAN test deterministically here (without DB) is that
// auth.RateLimitMiddleware fires and issues 429 once the per-key bucket is
// exhausted when api_key_id is already present in context — which is exactly
// what APIKeyAuthSelective provides on the protected data paths even with global
// auth off. This isolates and proves the limiter behaviour that was previously
// unreachable (the middleware was gated behind requireAPIKey=true).

// TestPerKeyRateLimitFires verifies that auth.RateLimitMiddleware issues 429
// after the per-key burst is exhausted when api_key_id is pre-populated in
// context (simulating what APIKeyAuthSelective does on protected routes with
// auth globally off).
func TestPerKeyRateLimitFires(t *testing.T) {
	// Reset the global limiter state between tests by recreating it. The
	// auth package exposes a module-level globalRateLimiter; we drive it via
	// RateLimitMiddleware() which reads from that same global. Since we use a
	// unique key ID per test, bucket isolation is guaranteed.
	const testKeyID uint = 9988776655

	// Build a tiny router: inject api_key_id + rate_limit into context, then
	// apply the real per-key limiter middleware.
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Simulate what APIKeyAuth sets in context.
		c.Set("api_key_id", testKeyID)
		c.Set("rate_limit", 3) // 3 requests/hour → burst=3
		c.Next()
	})
	r.Use(auth.RateLimitMiddleware())
	r.GET("/api/compare/:j1/:j2", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	hit := func() int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/compare/j1/j2", nil)
		r.ServeHTTP(w, req)
		return w.Code
	}

	allowed, limited := 0, 0
	for i := 0; i < 6; i++ {
		switch hit() {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			limited++
		}
	}

	// rate.NewLimiter(rate.Every(hour/3), 3) ← burst=3, so first 3 calls pass.
	if allowed < 3 {
		t.Errorf("allowed = %d, want >= 3 (burst)", allowed)
	}
	if limited == 0 {
		t.Errorf("rate limiter never fired — fix may have regressed (limited=%d)", limited)
	}
}

// TestPerKeyRateLimitSkipsWhenNoKeyInContext verifies that
// auth.RateLimitMiddleware is a no-op when no api_key_id is in context (open
// routes where APIKeyAuthSelective calls c.Next() without auth). This ensures
// the unconditional mount does not break unauthenticated open routes.
func TestPerKeyRateLimitSkipsWhenNoKeyInContext(t *testing.T) {
	r := gin.New()
	// Do NOT inject api_key_id — simulates an open route (MORF_REQUIRE_API_KEY=false,
	// and route is NOT in isProtectedDataPath / isSensitiveAPIPath).
	r.Use(auth.RateLimitMiddleware())
	r.GET("/api/upload", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/upload", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200 (no api_key_id → limiter must skip)", i, w.Code)
		}
	}
}

// Note: gin.TestMode is already set by the init() in ratelimit_test.go which
// shares this package. No additional init is needed here.
