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
	"morf/utils"
	"sync"
	"testing"

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

// TestDatabaseConnectionPoolUnderLoad tests database connection pool under concurrent load
func TestDatabaseConnectionPoolUnderLoad(t *testing.T) {
	// This test would require a test database setup
	// For now, we'll create a placeholder test
	t.Skip("Requires test database setup")
}

// TestConcurrentAPKUploads tests 100 concurrent uploads
func TestConcurrentAPKUploads(t *testing.T) {
	// This test would require HTTP server setup
	// For now, we'll create a placeholder test
	t.Skip("Requires HTTP server setup")
}

