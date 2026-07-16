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

	"morf/storage"
)

// s3Scheme fetches an object from the S3-compatible store MORF is already
// configured to use (storage.S3Storage). The reference form is:
//
//	s3://<bucket>/<key>   or   s3://<key>
//
// The configured store already targets a single bucket (MORF_S3_BUCKET); when a
// bucket component is present it must match that configured bucket (a mismatch
// is refused so a reference cannot silently target an unexpected bucket). The
// remainder is the object key.
const schemeS3 = "s3"

// s3StorageOpener is the subset of storage.Storage the adapter needs. It is an
// interface so tests can inject a fake without real network/credentials.
type s3StorageOpener interface {
	Stat(ctx context.Context, key string) (int64, error)
	Open(ctx context.Context, key string) (readCloser, error)
}

// readCloser aliases io.ReadCloser via a tiny indirection so the interface above
// stays local to this file; storage.Storage.Open already returns io.ReadCloser.
type readCloser interface {
	Read(p []byte) (int, error)
	Close() error
}

// s3Adapter downloads an object from the configured S3 store into destDir.
type s3Adapter struct {
	destDir  string
	maxBytes int64
	// store is the artifact store. It is populated lazily from
	// storage.NewFromEnv-style construction, or injected in tests.
	store  s3StorageOpener
	bucket string // configured bucket, for the optional bucket-match check
	// newStore builds the store on first use so constructing the adapter never
	// requires S3 credentials (only Fetch does). Overridable in tests.
	newStore func() (s3StorageOpener, string, error)
}

func init() {
	Register(schemeS3, func(o Options) (Adapter, error) {
		return &s3Adapter{
			destDir:  o.DestDir,
			maxBytes: resolveMaxBytes(o),
			newStore: newEnvS3Store,
		}, nil
	})
}

func (a *s3Adapter) Scheme() string { return schemeS3 }

// newEnvS3Store builds the real S3 storage backend from the environment. It is
// the default store constructor; tests override s3Adapter.newStore instead.
func newEnvS3Store() (s3StorageOpener, string, error) {
	s3, err := storage.NewS3StorageFromEnv()
	if err != nil {
		return nil, "", fmt.Errorf("%w: S3 ingestion requires MORF_S3_BUCKET, AWS_ACCESS_KEY_ID and "+
			"AWS_SECRET_ACCESS_KEY (see docs/INGESTION.md): %v", ErrAdapterNotConfigured, err)
	}
	return storageOpenerAdapter{s3}, os.Getenv("MORF_S3_BUCKET"), nil
}

// storageOpenerAdapter adapts a storage.Storage to s3StorageOpener (Open's
// return type io.ReadCloser satisfies readCloser structurally).
type storageOpenerAdapter struct{ s storage.Storage }

func (o storageOpenerAdapter) Stat(ctx context.Context, key string) (int64, error) {
	return o.s.Stat(ctx, key)
}
func (o storageOpenerAdapter) Open(ctx context.Context, key string) (readCloser, error) {
	rc, err := o.s.Open(ctx, key)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

func (a *s3Adapter) Fetch(ctx context.Context, ref string) (string, error) {
	ctx = ensureCtx(ctx)

	key, bucket, err := parseS3Ref(ref)
	if err != nil {
		return "", err
	}

	if a.store == nil {
		store, cfgBucket, serr := a.newStore()
		if serr != nil {
			return "", serr
		}
		a.store = store
		a.bucket = cfgBucket
	}
	// When the reference names a bucket, it must match the configured one.
	if bucket != "" && a.bucket != "" && !strings.EqualFold(bucket, a.bucket) {
		return "", fmt.Errorf("ingest: s3 reference bucket %q does not match configured bucket %q", bucket, a.bucket)
	}

	// Reject an over-cap object before opening/downloading any bytes (mirrors the
	// worker's disk-admission stat before streaming a remote object).
	if size, statErr := a.store.Stat(ctx, key); statErr == nil && size > a.maxBytes {
		return "", fmt.Errorf("ingest: s3 object %q is %d bytes, exceeds the %d-byte limit", key, size, a.maxBytes)
	}

	rc, err := a.store.Open(ctx, key)
	if err != nil {
		return "", fmt.Errorf("ingest: opening s3 object %q: %w", key, err)
	}
	defer rc.Close()

	destDir, err := resolveDestDir(Options{DestDir: a.destDir})
	if err != nil {
		return "", err
	}
	return copyCapped(destDir, artifactExt(key), rc, a.maxBytes)
}

// parseS3Ref splits an s3:// reference into an object key and an optional bucket.
// Accepted forms:
//
//	s3://bucket/path/to/app.apk  -> bucket="bucket", key="path/to/app.apk"
//	s3://path/to/app.apk         -> bucket="",       key="path/to/app.apk"
//
// The first segment is treated as a bucket only when a "/" separates it from a
// remaining key; a single-segment reference (s3://app.apk) is treated as a bare
// key so it works against a store whose bucket comes solely from env. The key is
// validated against path traversal so a reference can never escape via "..".
func parseS3Ref(ref string) (key, bucket string, err error) {
	r := strings.TrimSpace(ref)
	rest := strings.TrimPrefix(r, "s3://")
	if rest == r {
		// no lowercase s3:// prefix; tolerate an uppercase scheme.
		rest = strings.TrimPrefix(r, "S3://")
	}
	// A triple-slash form (s3:///key) carries an empty authority: there is no
	// bucket component, so the remainder (after the leading slash) is a bare key.
	emptyAuthority := strings.HasPrefix(rest, "/")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return "", "", fmt.Errorf("ingest: s3 reference %q has no object key", ref)
	}
	if emptyAuthority {
		key = rest
	} else if i := strings.Index(rest, "/"); i > 0 {
		bucket = rest[:i]
		key = strings.TrimPrefix(rest[i+1:], "/")
	} else {
		key = rest
	}
	if key == "" {
		return "", "", fmt.Errorf("ingest: s3 reference %q has no object key", ref)
	}
	if err := validateObjectKey(key); err != nil {
		return "", "", err
	}
	return key, bucket, nil
}

// validateObjectKey rejects a key that is absolute or contains a ".." path
// segment, mirroring storage/local.go's sanitizeKey traversal guard so a fetched
// key can never point outside its intended namespace.
func validateObjectKey(key string) error {
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("ingest: s3 object key %q must not be absolute", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return fmt.Errorf("ingest: s3 object key %q must not contain a %q path segment", key, "..")
		}
	}
	return nil
}
