/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www/apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewJobContext(t *testing.T) {
	ctx := NewJobContext()

	assert.NotEmpty(t, ctx.JobID, "JobID should not be empty")
	assert.NotEmpty(t, ctx.Workspace, "Workspace should not be empty")
	assert.Contains(t, ctx.Workspace, "/tmp/morf/jobs", "Workspace should be in /tmp/morf/jobs")
	assert.Contains(t, ctx.Workspace, ctx.JobID, "Workspace should contain JobID")

	// Verify JobID is a valid UUID
	_, err := uuid.Parse(ctx.JobID)
	assert.NoError(t, err, "JobID should be a valid UUID")
}

func TestJobContextCreateWorkspace(t *testing.T) {
	ctx := NewJobContext()

	err := ctx.CreateWorkspace()
	assert.NoError(t, err, "CreateWorkspace should succeed")

	// Verify all directories exist
	assert.DirExists(t, ctx.Workspace, "Workspace directory should exist")
	assert.DirExists(t, ctx.GetInputDir(), "Input directory should exist")
	assert.DirExists(t, ctx.GetOutputDir(), "Output directory should exist")
	assert.DirExists(t, ctx.GetSourceDir(), "Source directory should exist")
	assert.DirExists(t, ctx.GetResDir(), "Res directory should exist")
	assert.DirExists(t, ctx.GetFilesDir(), "Files directory should exist")

	// Cleanup
	defer ctx.CleanupWorkspace()
}

func TestJobContextCleanupWorkspace(t *testing.T) {
	ctx := NewJobContext()

	// Create workspace first
	err := ctx.CreateWorkspace()
	assert.NoError(t, err, "CreateWorkspace should succeed")

	// Verify it exists
	assert.DirExists(t, ctx.Workspace, "Workspace should exist before cleanup")

	// Cleanup
	err = ctx.CleanupWorkspace()
	assert.NoError(t, err, "CleanupWorkspace should succeed")

	// Verify it's gone
	_, err = os.Stat(ctx.Workspace)
	assert.True(t, os.IsNotExist(err), "Workspace should not exist after cleanup")
}

func TestJobContextPathMethods(t *testing.T) {
	ctx := NewJobContext()

	// Test GetInputDir
	inputDir := ctx.GetInputDir()
	assert.Equal(t, filepath.Join(ctx.Workspace, "input"), inputDir)

	// Test GetOutputDir
	outputDir := ctx.GetOutputDir()
	assert.Equal(t, filepath.Join(ctx.Workspace, "output"), outputDir)

	// Test GetSourceDir
	sourceDir := ctx.GetSourceDir()
	assert.Equal(t, filepath.Join(ctx.Workspace, "output", "apk", "source"), sourceDir)

	// Test GetResDir
	resDir := ctx.GetResDir()
	assert.Equal(t, filepath.Join(ctx.Workspace, "output", "apk", "appres"), resDir)

	// Test GetFilesDir
	filesDir := ctx.GetFilesDir()
	assert.Equal(t, filepath.Join(ctx.Workspace, "output", "apk", "source"), filesDir)

	// Test GetTmpDir
	tmpDir := ctx.GetTmpDir()
	assert.Equal(t, ctx.Workspace, tmpDir)

	// Test GetApkPath
	apkPath := ctx.GetApkPath("/path/to/test.apk")
	assert.Equal(t, filepath.Join(inputDir, "test.apk"), apkPath)
}

func TestJobContextIsolation(t *testing.T) {
	// Create two job contexts
	ctx1 := NewJobContext()
	ctx2 := NewJobContext()

	// Verify they have different JobIDs
	assert.NotEqual(t, ctx1.JobID, ctx2.JobID, "Job contexts should have different JobIDs")

	// Verify they have different workspaces
	assert.NotEqual(t, ctx1.Workspace, ctx2.Workspace, "Job contexts should have different workspaces")

	// Create both workspaces
	err1 := ctx1.CreateWorkspace()
	err2 := ctx2.CreateWorkspace()

	assert.NoError(t, err1, "First workspace creation should succeed")
	assert.NoError(t, err2, "Second workspace creation should succeed")

	// Verify both exist independently
	assert.DirExists(t, ctx1.Workspace, "First workspace should exist")
	assert.DirExists(t, ctx2.Workspace, "Second workspace should exist")

	// Cleanup
	defer ctx1.CleanupWorkspace()
	defer ctx2.CleanupWorkspace()
}
