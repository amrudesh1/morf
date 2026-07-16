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
	"fmt"
	"os"
	"strings"
)

// fileAdapter is the builtin passthrough for a bare local path (or an explicit
// file:// reference). It does not download; it validates that the path exists,
// is a regular file, and carries a supported package extension, then returns it
// unchanged so `morf fetch ./app.apk` and existing local-path callers keep
// working through the same entry point as remote schemes.
type fileAdapter struct{}

func init() {
	Register(fileScheme, func(Options) (Adapter, error) {
		return &fileAdapter{}, nil
	})
}

func (a *fileAdapter) Scheme() string { return fileScheme }

func (a *fileAdapter) Fetch(_ context.Context, ref string) (string, error) {
	path := strings.TrimSpace(ref)
	// Accept an explicit file:// prefix as well as a bare path.
	if i := strings.Index(path, "://"); i > 0 && isSchemeToken(path[:i]) {
		path = strings.TrimPrefix(path, "file://")
	}
	if path == "" {
		return "", fmt.Errorf("ingest: empty local path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("ingest: local artifact %q: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("ingest: local artifact %q is a directory, not a file", path)
	}
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".apk") && !strings.HasSuffix(lower, ".ipa") {
		return "", fmt.Errorf("ingest: local artifact %q must be an .apk or .ipa file", path)
	}
	return path, nil
}
