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

package utils

import (
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	alf "github.com/spf13/afero"
)

// JobContext represents a job execution context with isolated workspace
type JobContext struct {
	JobID     string
	Workspace string
	fs        alf.Fs
}

// NewJobContext creates a new job context with an isolated workspace keyed on a
// freshly generated UUID. Callers that already have a stable job ID should use
// NewJobContextForID so the workspace directory is deterministically named.
func NewJobContext() *JobContext {
	return NewJobContextForID("")
}

// NewJobContextForID creates a job context whose isolated workspace directory is
// keyed on the supplied job ID rather than a random UUID. A deterministic,
// job-ID-keyed workspace makes stray workspaces correlatable back to their job
// (aiding cleanup / the startup /tmp sweep and observability). An empty id falls
// back to a generated UUID so callers without a job ID still get a unique dir.
func NewJobContextForID(jobID string) *JobContext {
	if strings.TrimSpace(jobID) == "" {
		jobID = uuid.New().String()
	}
	workspace := filepath.Join("/tmp/morf/jobs", jobID)

	return &JobContext{
		JobID:     jobID,
		Workspace: workspace,
		fs:        alf.NewOsFs(),
	}
}

// CreateWorkspace creates the workspace directories for this job
func (jc *JobContext) CreateWorkspace() error {
	dirs := []string{
		jc.Workspace,
		jc.GetInputDir(),
		jc.GetOutputDir(),
		jc.GetSourceDir(),
		jc.GetResDir(),
		jc.GetFilesDir(),
	}

	for _, dir := range dirs {
		if err := jc.fs.MkdirAll(dir, 0755); err != nil {
			log.WithFields(log.Fields{
				"job_id": jc.JobID,
				"dir":    dir,
				"error":  err.Error(),
			}).Error("Failed to create workspace directory")
			return err
		}
	}

	log.WithFields(log.Fields{
		"job_id":    jc.JobID,
		"workspace": jc.Workspace,
	}).Info("Created isolated workspace for job")

	return nil
}

// CleanupWorkspace removes the workspace directory for this job
func (jc *JobContext) CleanupWorkspace() error {
	if err := jc.fs.RemoveAll(jc.Workspace); err != nil {
		log.WithFields(log.Fields{
			"job_id":    jc.JobID,
			"workspace": jc.Workspace,
			"error":     err.Error(),
		}).Error("Failed to cleanup workspace")
		return err
	}

	log.WithFields(log.Fields{
		"job_id":    jc.JobID,
		"workspace": jc.Workspace,
	}).Info("Cleaned up workspace for job")

	return nil
}

// GetInputDir returns the input directory for this job
func (jc *JobContext) GetInputDir() string {
	return filepath.Join(jc.Workspace, "input")
}

// GetOutputDir returns the output directory for this job
func (jc *JobContext) GetOutputDir() string {
	return filepath.Join(jc.Workspace, "output")
}

// GetSourceDir returns the source directory for this job
func (jc *JobContext) GetSourceDir() string {
	return filepath.Join(jc.Workspace, "output", "apk", "source")
}

// GetResDir returns the resources directory for this job
func (jc *JobContext) GetResDir() string {
	return filepath.Join(jc.Workspace, "output", "apk", "appres")
}

// GetFilesDir returns the files directory for this job.
// It is an alias of GetSourceDir: the files and source trees share the same
// output/apk/source location (mirroring directory_parser.go's filesDir/sourceDir),
// so it delegates rather than duplicating the path literal.
func (jc *JobContext) GetFilesDir() string {
	return jc.GetSourceDir()
}

// GetTmpDir returns the temporary directory for this job (same as workspace)
func (jc *JobContext) GetTmpDir() string {
	return jc.Workspace
}

// GetApkPath returns the full path to an APK file in the input directory
func (jc *JobContext) GetApkPath(apkPath string) string {
	return filepath.Join(jc.GetInputDir(), filepath.Base(apkPath))
}

// GetFS returns the filesystem instance for this job
func (jc *JobContext) GetFS() alf.Fs {
	return jc.fs
}
