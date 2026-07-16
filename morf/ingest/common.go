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

package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"morf/config"
	"morf/utils"
)

// DefaultMaxBytes is the default per-fetch download cap. It defaults to the same
// 500 MiB APK-download cap the Slack path enforces (utils.MaxAPKDownloadSize) so
// ingestion and the existing download surface share one limit. It is overridable
// per fetch via Options.MaxBytes, or process-wide via MORF_INGEST_MAX_BYTES.
func DefaultMaxBytes() int64 {
	return config.Int64Positive("MORF_INGEST_MAX_BYTES", utils.MaxAPKDownloadSize)
}

// ErrAdapterNotConfigured is the sentinel returned by every vendor stub adapter
// whose credentials/config are not present. Callers (e.g. `morf fetch`) can
// errors.Is against it to distinguish "you need to configure X" from a genuine
// operational failure. The wrapped message names the exact env vars to set.
var ErrAdapterNotConfigured = errors.New("ingest: adapter not configured")

// fileScheme is the builtin passthrough scheme for a bare local path.
const fileScheme = "file"

// resolveMaxBytes returns the effective byte cap for opts.
func resolveMaxBytes(opts Options) int64 {
	if opts.MaxBytes > 0 {
		return opts.MaxBytes
	}
	return DefaultMaxBytes()
}

// resolveDestDir returns the destination directory to download into, creating a
// fresh temp dir when opts.DestDir is empty (mirroring the worker/CLI, which use
// a per-job workspace / os.MkdirTemp for fetch scratch). When DestDir is set it
// must already exist and be a directory; the download is written inside it.
func resolveDestDir(opts Options) (string, error) {
	dir := strings.TrimSpace(opts.DestDir)
	if dir == "" {
		created, err := os.MkdirTemp("", "morf-ingest-*")
		if err != nil {
			return "", fmt.Errorf("ingest: creating scratch dir: %w", err)
		}
		return created, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("ingest: destination dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("ingest: destination %q is not a directory", dir)
	}
	return dir, nil
}

// artifactExt returns a safe file extension for the fetched artifact based on
// name (the object key or URL path). It only preserves the recognized package
// extensions (.apk/.ipa); anything else yields ".bin" so a hostile name can
// never inject an unexpected extension or path separator. The returned value is
// always a leading-dot extension with no path element.
func artifactExt(name string) string {
	base := strings.ToLower(filepath.Base(name))
	switch {
	case strings.HasSuffix(base, ".apk"):
		return ".apk"
	case strings.HasSuffix(base, ".ipa"):
		return ".ipa"
	default:
		return ".bin"
	}
}

// copyCapped streams src into a newly created temp file inside destDir, aborting
// if the cumulative bytes would exceed maxBytes. It reuses the router/Slack
// defense-in-depth idiom: an io.LimitReader bounds the read to maxBytes+1 so an
// over-cap or lying-Content-Length body is detected and rejected rather than
// silently truncated. ext controls the temp file suffix (.apk/.ipa/.bin). On any
// error the partial temp file is removed. On success the closed file's path is
// returned.
func copyCapped(destDir, ext string, src io.Reader, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes()
	}
	tmp, err := os.CreateTemp(destDir, "artifact-*"+ext)
	if err != nil {
		return "", fmt.Errorf("ingest: creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Read at most maxBytes+1: if we can read that many bytes the source is over
	// the cap, so reject. This catches both an over-large body and a source that
	// under-declares its Content-Length.
	limited := io.LimitReader(src, maxBytes+1)
	written, copyErr := io.Copy(tmp, limited)
	if copyErr != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("ingest: downloading artifact: %w", copyErr)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("ingest: finalizing temp file: %w", err)
	}
	if written > maxBytes {
		os.Remove(tmpPath)
		return "", fmt.Errorf("ingest: artifact exceeds maximum allowed size of %d bytes", maxBytes)
	}
	return tmpPath, nil
}

// ensureCtx returns ctx or context.Background when nil, so adapters can be
// called defensively.
func ensureCtx(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
