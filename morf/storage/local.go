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

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultUploadDir is used when MORF_UPLOAD_DIR is unset.
const DefaultUploadDir = "/tmp/morf/uploads"

// LocalStorage stores artifacts as files rooted at a base directory.
type LocalStorage struct {
	base string
}

// compile-time interface check.
var _ Storage = (*LocalStorage)(nil)

// NewLocalStorage creates a LocalStorage rooted at dir (or DefaultUploadDir when
// dir is empty). The base directory is created if it does not exist.
func NewLocalStorage(dir string) (*LocalStorage, error) {
	base := strings.TrimSpace(dir)
	if base == "" {
		base = DefaultUploadDir
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, fmt.Errorf("storage: resolving upload dir %q: %w", base, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("storage: creating upload dir %q: %w", abs, err)
	}
	return &LocalStorage{base: abs}, nil
}

// sanitizeKey rejects keys that are absolute or contain ".." so that a key can
// never escape the base directory (path-traversal protection).
func sanitizeKey(key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return "", errors.New("storage: empty key")
	}
	if filepath.IsAbs(key) || strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("storage: absolute key not allowed: %q", key)
	}
	if strings.Contains(key, "..") {
		return "", fmt.Errorf("storage: key %q must not contain %q", key, "..")
	}
	return filepath.Clean(key), nil
}

// resolve returns the absolute on-disk path for key after sanitizing it.
func (l *LocalStorage) resolve(key string) (string, error) {
	rel, err := sanitizeKey(key)
	if err != nil {
		return "", err
	}
	return filepath.Join(l.base, rel), nil
}

// Put stores size bytes from r under key. The write is atomic: data is written
// to a temporary file in the destination directory and then renamed into place.
func (l *LocalStorage) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	full, err := l.resolve(key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("storage: creating dir %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".morf-tmp-*")
	if err != nil {
		return fmt.Errorf("storage: creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	var copyErr error
	if size >= 0 {
		var n int64
		n, copyErr = io.CopyN(tmp, r, size)
		// io.CopyN returns io.EOF if the reader ends early; treat a short read
		// as an error, but a reader that supplies exactly size bytes is fine.
		if copyErr == io.EOF && n == size {
			copyErr = nil
		}
	} else {
		_, copyErr = io.Copy(tmp, r)
	}
	if copyErr != nil {
		_ = tmp.Close()
		return fmt.Errorf("storage: writing %q: %w", key, copyErr)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("storage: syncing %q: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("storage: closing temp for %q: %w", key, err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		return fmt.Errorf("storage: committing %q: %w", key, err)
	}
	committed = true
	return nil
}

// Open returns a reader for key; the caller is responsible for closing it.
func (l *LocalStorage) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	full, err := l.resolve(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Delete removes key. It returns nil if the key does not exist.
func (l *LocalStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	full, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage: deleting %q: %w", key, err)
	}
	return nil
}

// Stat returns the size in bytes of key.
func (l *LocalStorage) Stat(ctx context.Context, key string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	full, err := l.resolve(key)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(full)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// LocalPath returns the filesystem path for key and true, since this backend is
// local. The returned path is rooted under the base directory.
func (l *LocalStorage) LocalPath(key string) (string, bool) {
	rel, err := sanitizeKey(key)
	if err != nil {
		// Fall back to a cleaned join; never escape the base.
		rel = filepath.Join("/", key)
	}
	return filepath.Join(l.base, rel), true
}
