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

// Package storage provides a small abstraction over an object store used by
// MORF to keep uploaded artifacts (APKs, etc.) outside of any single process'
// local filesystem, so the API/worker fleet can be horizontally stateless.
//
// Two backends are provided:
//
//   - LocalStorage: a directory on the local filesystem (default).
//   - S3Storage:    any S3-compatible service (AWS S3, MinIO, Cloudflare R2),
//     implemented with the standard library only and signed with AWS
//     Signature Version 4 (no AWS SDK dependency).
//
// Select the backend from the environment with NewFromEnv.
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// Storage is the artifact store abstraction. Implementations must be safe for
// concurrent use by multiple goroutines.
type Storage interface {
	// Put stores size bytes from r under key.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Open returns a reader for key; caller closes.
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes key (no error if absent).
	Delete(ctx context.Context, key string) error
	// Stat returns the size of key.
	Stat(ctx context.Context, key string) (int64, error)
	// LocalPath returns a filesystem path for key and true IF this backend is
	// local (so callers that must hand a path to an external tool can avoid a copy).
	// Returns ("", false) for remote backends.
	LocalPath(key string) (string, bool)
}

// Backend names accepted in MORF_STORAGE_BACKEND.
const (
	BackendLocal = "local"
	BackendS3    = "s3"
)

// NewFromEnv selects the backend from MORF_STORAGE_BACKEND ("local" default, or "s3").
func NewFromEnv() (Storage, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("MORF_STORAGE_BACKEND")))
	switch backend {
	case "", BackendLocal:
		return NewLocalStorage(os.Getenv("MORF_UPLOAD_DIR"))
	case BackendS3:
		return NewS3StorageFromEnv()
	default:
		return nil, fmt.Errorf("storage: unknown MORF_STORAGE_BACKEND %q (want %q or %q)", backend, BackendLocal, BackendS3)
	}
}

// ValidateConfiguredBackend fails fast for a MISCONFIGURED explicit storage
// backend. The upload store is otherwise constructed lazily on the first
// /upload and its error is swallowed, so a bad MORF_STORAGE_BACKEND=s3 (missing
// bucket/credentials, unknown backend name) would boot green and then 500 on
// every upload. Calling this at startup surfaces the misconfiguration
// immediately with a clear, actionable error. When the backend is unset or
// "local" it is lenient (the local dir is created on demand), so a normal
// deployment is unaffected. STORAGE-startup.
func ValidateConfiguredBackend() error {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("MORF_STORAGE_BACKEND")))
	if backend == "" || backend == BackendLocal {
		return nil
	}
	if _, err := NewFromEnv(); err != nil {
		return fmt.Errorf("MORF_STORAGE_BACKEND=%q is misconfigured: %w", backend, err)
	}
	return nil
}
