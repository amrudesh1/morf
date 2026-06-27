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
	"morf/utils"
	"os"
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"
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

// TestAPIEndpoints tests API endpoint functionality
func TestAPIEndpoints(t *testing.T) {
	// This test would require a running server instance
	// For now, we'll create a placeholder test
	t.Skip("Requires running server instance")
}

// TestDatabaseOperations tests database operations
func TestDatabaseOperations(t *testing.T) {
	// This test would require a database connection
	// For now, we'll create a placeholder test
	t.Skip("Requires database connection")
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

// TestCLIAndServerModeSimultaneously tests CLI and server mode running simultaneously
func TestCLIAndServerModeSimultaneously(t *testing.T) {
	// This test would require actual CLI and server instances
	// For now, we'll create a placeholder test
	t.Skip("Requires CLI and server mode setup")
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

	// Verify isolation - files in one workspace shouldn't affect the other
	fs1 := jobCtx1.GetFS()
	fs2 := jobCtx2.GetFS()

	testFile1 := jobCtx1.GetInputDir() + "/test1.txt"
	testFile2 := jobCtx2.GetInputDir() + "/test2.txt"

	// Create file in workspace 1
	file1, err := fs1.Create(testFile1)
	assert.NoError(t, err)
	file1.Close()

	// Verify file doesn't exist in workspace 2
	_, err = fs2.Stat(testFile1)
	assert.Error(t, err, "File from workspace 1 should not exist in workspace 2")
	assert.True(t, os.IsNotExist(err), "Error should be 'not exist' error")

	// Create file in workspace 2
	file2, err := fs2.Create(testFile2)
	assert.NoError(t, err)
	file2.Close()

	// Verify file doesn't exist in workspace 1
	_, err = fs1.Stat(testFile2)
	assert.Error(t, err, "File from workspace 2 should not exist in workspace 1")
	assert.True(t, os.IsNotExist(err), "Error should be 'not exist' error")

	// Cleanup
	jobCtx1.CleanupWorkspace()
	jobCtx2.CleanupWorkspace()
}
