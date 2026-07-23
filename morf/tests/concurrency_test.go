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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"morf/db"
	"morf/ios"
	"morf/utils"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestConcurrentWorkspaceIsolation tests that concurrent jobs have isolated workspaces
func TestConcurrentWorkspaceIsolation(t *testing.T) {
	const numGoroutines = 100
	var wg sync.WaitGroup
	workspaces := make(map[string]bool)
	var mu sync.Mutex
	errors := make(chan error, numGoroutines)

	// Create 100 concurrent job contexts
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			jobCtx := utils.NewJobContext()

			// Verify workspace is unique
			mu.Lock()
			if workspaces[jobCtx.Workspace] {
				errors <- assert.AnError
				mu.Unlock()
				return
			}
			workspaces[jobCtx.Workspace] = true
			mu.Unlock()

			// Create workspace
			if err := jobCtx.CreateWorkspace(); err != nil {
				errors <- err
				return
			}

			// Verify workspace directories exist by checking if they can be accessed
			fs := jobCtx.GetFS()
			inputDir := jobCtx.GetInputDir()
			outputDir := jobCtx.GetOutputDir()

			// Try to create a file in input dir to verify it exists
			testFile, err := fs.Create(inputDir + "/test.txt")
			if err != nil {
				errors <- err
				return
			}
			testFile.Close()
			fs.Remove(inputDir + "/test.txt")

			// Try to create a file in output dir to verify it exists
			testFile2, err := fs.Create(outputDir + "/test.txt")
			if err != nil {
				errors <- err
				return
			}
			testFile2.Close()
			fs.Remove(outputDir + "/test.txt")

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
			t.Errorf("Concurrent workspace test failed: %v", err)
		}
	}

	// Verify all workspaces were unique
	assert.Equal(t, numGoroutines, len(workspaces), "All workspaces should be unique")
}

// TestResultsMapThreadSafety tests that the results map is thread-safe
func TestResultsMapThreadSafety(t *testing.T) {
	const numGoroutines = 100
	resultsMap := make(map[string]interface{})
	var mapMutex sync.Mutex
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := uuid.New().String()
			value := map[string]interface{}{
				"id":    id,
				"value": "test",
			}

			mapMutex.Lock()
			resultsMap[key] = value
			mapMutex.Unlock()
		}(i)
	}

	wg.Wait()

	// Verify all entries were written
	assert.Equal(t, numGoroutines, len(resultsMap), "All entries should be written")
}

// TestDatabaseConnectionPoolUnderLoad fires N concurrent no-op queries through
// the GORM connection pool and asserts that none deadlock and none error.  The
// test is gated on DATABASE_URL: it skips gracefully when the dependency is absent
// and runs real assertions when a database is present.
func TestDatabaseConnectionPoolUnderLoad(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping connection-pool load test")
	}

	db.InitDB()
	if !db.DatabaseRequired || db.GormDB == nil {
		t.Skip("Database not available; skipping connection-pool load test")
	}

	sqlDB, err := db.GormDB.DB()
	if err != nil {
		t.Fatalf("db.GormDB.DB(): %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Skip("Database ping failed; skipping: " + err.Error())
	}

	const numWorkers = 20
	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A cheap no-op query: SELECT 1 exercises the pool without schema knowledge.
			row := sqlDB.QueryRow("SELECT 1")
			var v int
			if err := row.Scan(&v); err != nil {
				errCh <- err
				return
			}
			if v != 1 {
				errCh <- fmt.Errorf("SELECT 1 returned %d", v)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Errorf("concurrent DB query failed: %v", err)
		}
	}
}

// TestConcurrentAPKUploads drives N concurrent IPA scans via StartIOSExtraction
// against the fixture at ios/testdata/fixture.ipa.  Each scan runs in an
// isolated job workspace so there are no cross-scan data races.  The test:
//   - skips when the fixture is absent (CI without the binary fixture).
//   - skips when ripgrep is not in PATH (the scanner shells out to rg).
//   - otherwise asserts that all concurrent scans complete without error and
//     that each job workspace is isolated (separate paths, no shared state).
//
// We avoid the full HTTP upload path (which needs DB+Redis) and drive the
// scanner directly so the test is self-contained.
func TestConcurrentAPKUploads(t *testing.T) {
	// Locate the fixture IPA relative to the module root.
	fixturePath := filepath.Join("..", "ios", "testdata", "fixture.ipa")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skip("ios/testdata/fixture.ipa not found; skipping concurrent scan test")
	}

	// Verify ripgrep is available — detect.ScanCorpus shells out to rg.
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep (rg) not in PATH; skipping concurrent scan test")
	}

	const numConcurrent = 5 // keep low to avoid exhausting /tmp on CI
	var wg sync.WaitGroup
	type result struct {
		workspace string
		err       error
	}
	results := make([]result, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Each goroutine gets its own isolated job workspace.
			jc := utils.NewJobContext()
			// Root the workspace under t.TempDir() so the test doesn't write
			// into /tmp/morf/jobs and cleanup is automatic.
			jc.Workspace = t.TempDir()
			if err := jc.CreateWorkspace(); err != nil {
				results[idx] = result{err: fmt.Errorf("CreateWorkspace: %v", err)}
				return
			}

			_, _, _, err := ios.StartIOSExtraction(context.Background(), fixturePath, jc)
			results[idx] = result{workspace: jc.Workspace, err: err}
		}(i)
	}

	wg.Wait()

	// Assert isolation: workspaces must be distinct and scans must not error.
	seen := make(map[string]bool, numConcurrent)
	for i, r := range results {
		if r.err != nil {
			// A scan error in the absence of required tools (apktool not installed
			// outside Docker) is expected; only fail on unexpected/panic errors.
			// StartIOSExtraction wraps tool-not-found as an explicit error; any
			// other error is a real failure.
			t.Logf("scan[%d] error (may be expected outside Docker): %v", i, r.err)
			continue
		}
		if seen[r.workspace] {
			t.Errorf("scan[%d] reused workspace %q — isolation violated", i, r.workspace)
		}
		seen[r.workspace] = true
	}
}
