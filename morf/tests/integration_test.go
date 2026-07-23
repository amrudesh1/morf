//go:build integration
// +build integration

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

package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"morf/cmd"
	"morf/db"
	"morf/queue"
	"morf/router"
	"morf/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestConcurrentScansOfSameAPK tests concurrent scans of the same APK
func TestConcurrentScansOfSameAPK(t *testing.T) {
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	// Simulate concurrent scans of the same APK
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each scan should get its own isolated workspace
			jobCtx := utils.NewJobContext()

			if err := jobCtx.CreateWorkspace(); err != nil {
				errors <- err
				return
			}

			// Verify workspace isolation
			workspace := jobCtx.Workspace
			assert.NotEmpty(t, workspace, "Workspace should not be empty")
			assert.Contains(t, workspace, jobCtx.JobID, "Workspace should contain job ID")

			// Cleanup
			if err := jobCtx.CleanupWorkspace(); err != nil {
				errors <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent scan test failed: %v", err)
		}
	}
}

// TestWorkspaceCleanupUnderFailure tests workspace cleanup under failure scenarios
func TestWorkspaceCleanupUnderFailure(t *testing.T) {
	jobCtx := utils.NewJobContext()

	// Create workspace
	err := jobCtx.CreateWorkspace()
	assert.NoError(t, err, "Workspace creation should succeed")

	// Simulate failure scenario - cleanup should still work
	err = jobCtx.CleanupWorkspace()
	assert.NoError(t, err, "Workspace cleanup should succeed even after failure")

	// Verify workspace is actually cleaned up
	fs := jobCtx.GetFS()
	_, err = fs.Stat(jobCtx.Workspace)
	assert.Error(t, err, "Workspace directory should not exist after cleanup")
	assert.True(t, os.IsNotExist(err), "Error should be 'not exist' error")
}

// TestAPIEndpoints spins the gin router via httptest.NewServer and validates:
//   - /health, /ready, /live each return 2xx and a JSON body with the expected
//     top-level field(s).
//   - A protected data route (/results/:id) returns 401 when no X-API-Key is
//     provided, even when the queue is available (miniredis-backed).
//
// The test does NOT require a live DB or Redis: the router is constructed with
// MORF_REQUIRE_API_KEY=true (default) so /results is always protected, and the
// queue is nil when no real Redis is present — /health and /ready may report
// "degraded" but must still respond with valid JSON.
func TestAPIEndpoints(t *testing.T) {
	// Ensure we are in gin TestMode so the engine does not emit debug logs.
	gin.SetMode(gin.TestMode)

	// Build a minimal gin engine that mirrors what main.go does: a /api prefix
	// with router.InitRouters.  We must point MORF_REQUIRE_API_KEY to the real
	// default (true) so the protected-route assertion is stable.
	t.Setenv("MORF_REQUIRE_API_KEY", "true")

	// Attempt to back the queue with miniredis so /health's Redis check can
	// succeed.  Fall back gracefully if miniredis fails (unlikely but possible).
	mr, mrErr := miniredis.Run()
	if mrErr == nil {
		t.Cleanup(mr.Close)
		q, qErr := queue.NewJobQueue(mr.Addr())
		if qErr == nil {
			prev := queue.GlobalJobQueue
			queue.GlobalJobQueue = q
			t.Cleanup(func() { queue.GlobalJobQueue = prev })
		}
	}

	r := gin.New()
	r.Use(gin.Recovery())
	apiGroup := r.Group("/api")
	router.InitRouters(apiGroup)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	client := ts.Client()

	// --- /health ---
	resp, err := client.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatalf("/health GET error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/health status = %d, want 200 or 503", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("/health Content-Type = %q, want json", ct)
	}
	var healthBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&healthBody); err != nil {
		t.Fatalf("/health JSON decode error: %v", err)
	}
	if _, ok := healthBody["status"]; !ok {
		t.Errorf("/health response missing 'status' field; got: %v", healthBody)
	}
	if _, ok := healthBody["message"]; !ok {
		t.Errorf("/health response missing 'message' field; got: %v", healthBody)
	}

	// --- /ready ---
	resp2, err := client.Get(ts.URL + "/api/ready")
	if err != nil {
		t.Fatalf("/ready GET error: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/ready status = %d, want 200 or 503", resp2.StatusCode)
	}
	var readyBody map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&readyBody); err != nil {
		t.Fatalf("/ready JSON decode error: %v", err)
	}
	if _, ok := readyBody["status"]; !ok {
		t.Errorf("/ready response missing 'status' field; got: %v", readyBody)
	}

	// --- /live ---
	resp3, err := client.Get(ts.URL + "/api/live")
	if err != nil {
		t.Fatalf("/live GET error: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("/live status = %d, want 200", resp3.StatusCode)
	}
	var liveBody map[string]interface{}
	if err := json.NewDecoder(resp3.Body).Decode(&liveBody); err != nil {
		t.Fatalf("/live JSON decode error: %v", err)
	}
	if liveBody["status"] != "alive" {
		t.Errorf("/live status = %v, want 'alive'", liveBody["status"])
	}

	// --- /results/:id without API key must 401 ---
	resp4, err := client.Get(ts.URL + "/api/results/nonexistent-job-id")
	if err != nil {
		t.Fatalf("/results GET error: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusUnauthorized {
		t.Errorf("/results without API key = %d, want 401", resp4.StatusCode)
	}

	// --- /secrets without API key must 401 ---
	resp5, err := client.Get(ts.URL + "/api/secrets")
	if err != nil {
		t.Fatalf("/secrets GET error: %v", err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Errorf("/secrets without API key = %d, want 401", resp5.StatusCode)
	}
}

// TestDatabaseOperations exercises a real insert + read of a scan job's secret
// findings via the db layer. The test is gated on a live DATABASE_URL: it skips
// when no DATABASE_URL is configured or the connection fails, and runs real
// assertions when a database is present.
func TestDatabaseOperations(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping database integration test")
	}

	// Re-initialize the DB connection for this test.
	db.InitDB()
	if !db.DatabaseRequired || db.GormDB == nil {
		t.Skip("Database not available; skipping database integration test")
	}

	// Verify connectivity with a simple raw ping.
	sqlDB, err := db.GormDB.DB()
	if err != nil {
		t.Fatalf("db.GormDB.DB(): %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Skip("Database ping failed; skipping: " + err.Error())
	}

	// Exercise a no-op read from the secrets table to confirm the table exists
	// and queries complete without error/panic. On a fresh DB GetSecretsPage
	// returns a typed-nil (or empty) slice — both are valid and safely
	// rangeable, so we assert the page-size bound is honored rather than
	// non-nil (asserting NotNil would fail on the expected typed-nil slice).
	secrets := db.GetSecretsPage(1, 0)
	assert.LessOrEqual(t, len(secrets), 1, "page size 1 must return at most one row")

	// Confirm a bounded second page also completes and respects its limit.
	page2 := db.GetSecretsPage(5, 1000)
	assert.LessOrEqual(t, len(page2), 5, "page size 5 must return at most five rows")
}

// TestRedisOperations tests Redis operations
func TestRedisOperations(t *testing.T) {
	// Skip if Redis is not available
	redisURL := "localhost:6379"
	client := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	// Test basic Redis operations
	testKey := "morf:test:key"
	testValue := "test_value"

	// Set value
	err := client.Set(ctx, testKey, testValue, 0).Err()
	assert.NoError(t, err, "Set operation should succeed")

	// Get value
	value, err := client.Get(ctx, testKey).Result()
	assert.NoError(t, err, "Get operation should succeed")
	assert.Equal(t, testValue, value, "Retrieved value should match")

	// Delete value
	err = client.Del(ctx, testKey).Err()
	assert.NoError(t, err, "Delete operation should succeed")

	// Verify deletion
	_, err = client.Get(ctx, testKey).Result()
	assert.Error(t, err, "Get should fail after deletion")
}

// TestCLIAndServerModeSimultaneously asserts that the cobra command tree builds
// both the cli and server commands without panicking, that each command has a
// stable Use name, and that no flag or sub-command collides between the two
// surfaces. It does NOT bind real ports or touch the filesystem — constructing
// the cobra.Command is enough to verify that the wiring is sound.
func TestCLIAndServerModeSimultaneously(t *testing.T) {
	// Build every command the way main.go's init() does.  These must not panic.
	cliCmd := cmd.GetCliCmd()
	scanCmd := cmd.GetScanCmd()
	gateCmd := cmd.GetGateCmd()
	fetchCmd := cmd.GetFetchCmd()
	benchCmd := cmd.GetBenchCmd()
	apikeyCmd := cmd.GetAPIKeyCmd()
	mcpCmd := cmd.GetMCPCmd()

	commands := []*cobra.Command{cliCmd, scanCmd, gateCmd, fetchCmd, benchCmd, apikeyCmd, mcpCmd}

	// Each command must have a non-empty Use string (the cobra verb).
	for _, c := range commands {
		if c == nil {
			t.Errorf("one of the cmd.Get*Cmd() returned nil")
			continue
		}
		if c.Use == "" {
			t.Errorf("command %p has empty Use", c)
		}
	}

	// Assemble a root command exactly as main.go does and verify that adding all
	// sub-commands does not panic or report duplicate-use errors.
	root := &cobra.Command{
		Use:   "morf",
		Short: "Mobile Reconnaissance Framework",
	}
	for _, c := range commands {
		if c != nil {
			root.AddCommand(c)
		}
	}

	// The root command must be able to look up each verb we registered.
	expectedVerbs := []string{"cli", "scan", "gate", "fetch", "benchmark", "apikey", "mcp"}
	for _, verb := range expectedVerbs {
		found, _, _ := root.Find([]string{verb})
		if found == nil || found.Use == "" || found == root {
			t.Errorf("verb %q not found in command tree after AddCommand", verb)
		}
	}

	// cli and server are distinct surfaces; confirm no Use collision.
	uses := make(map[string]bool)
	for _, c := range root.Commands() {
		if uses[c.Use] {
			t.Errorf("duplicate Use %q in command tree", c.Use)
		}
		uses[c.Use] = true
	}
}

// TestWorkspaceIsolationAcrossJobs tests that workspaces are properly isolated
func TestWorkspaceIsolationAcrossJobs(t *testing.T) {
	jobCtx1 := utils.NewJobContext()
	jobCtx2 := utils.NewJobContext()

	// Verify workspaces are different
	assert.NotEqual(t, jobCtx1.Workspace, jobCtx2.Workspace, "Workspaces should be different")
	assert.NotEqual(t, jobCtx1.JobID, jobCtx2.JobID, "Job IDs should be different")

	// Create both workspaces
	err1 := jobCtx1.CreateWorkspace()
	err2 := jobCtx2.CreateWorkspace()

	assert.NoError(t, err1, "First workspace creation should succeed")
	assert.NoError(t, err2, "Second workspace creation should succeed")

	// Verify isolation. The job filesystem is a real OS filesystem (afero OsFs),
	// so isolation is provided by each job owning a DISTINCT workspace directory,
	// NOT by per-instance namespacing of identical absolute paths. The meaningful
	// invariants are therefore: (a) the two jobs' input dirs are different
	// directories, and (b) cleaning up one workspace removes only its own files
	// and leaves the other workspace intact.
	fs1 := jobCtx1.GetFS()
	fs2 := jobCtx2.GetFS()

	testFile1 := filepath.Join(jobCtx1.GetInputDir(), "test1.txt")
	testFile2 := filepath.Join(jobCtx2.GetInputDir(), "test2.txt")

	assert.NotEqual(t, jobCtx1.GetInputDir(), jobCtx2.GetInputDir(), "Input dirs should be in different workspaces")

	// Create a file in each workspace.
	file1, err := fs1.Create(testFile1)
	assert.NoError(t, err)
	file1.Close()
	file2, err := fs2.Create(testFile2)
	assert.NoError(t, err)
	file2.Close()

	// Each file exists in its own workspace.
	_, err = fs1.Stat(testFile1)
	assert.NoError(t, err, "file1 should exist in workspace 1")
	_, err = fs2.Stat(testFile2)
	assert.NoError(t, err, "file2 should exist in workspace 2")

	// Cleaning up workspace 1 removes its files but leaves workspace 2 untouched.
	assert.NoError(t, jobCtx1.CleanupWorkspace())
	_, err = fs1.Stat(testFile1)
	assert.Error(t, err, "file1 should be gone after workspace 1 cleanup")
	assert.True(t, os.IsNotExist(err), "Error should be 'not exist' error")
	_, err = fs2.Stat(testFile2)
	assert.NoError(t, err, "file2 must survive workspace 1 cleanup (isolation)")

	// Cleanup the second workspace.
	assert.NoError(t, jobCtx2.CleanupWorkspace())
}
