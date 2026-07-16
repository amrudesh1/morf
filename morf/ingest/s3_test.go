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
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

func TestParseS3Ref(t *testing.T) {
	cases := []struct {
		ref        string
		wantKey    string
		wantBucket string
		wantErr    bool
	}{
		{"s3://bucket/path/to/app.apk", "path/to/app.apk", "bucket", false},
		{"s3://app.apk", "app.apk", "", false}, // single segment => bare key
		{"s3://bucket/app.ipa", "app.ipa", "bucket", false},
		{"S3://Bucket/App.apk", "App.apk", "Bucket", false},                 // uppercase scheme tolerated
		{"s3:///leading-slash/app.apk", "leading-slash/app.apk", "", false}, // empty authority => bare key
		{"s3://", "", "", true},                                             // no key
		{"s3://bucket/", "", "", true},                                      // no key after bucket
		{"s3://bucket/../etc/passwd", "", "", true},                         // traversal rejected
		{"s3://bucket/a/../../b.apk", "", "", true},                         // traversal rejected
	}
	for _, c := range cases {
		key, bucket, err := parseS3Ref(c.ref)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseS3Ref(%q): expected error, got key=%q bucket=%q", c.ref, key, bucket)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseS3Ref(%q): unexpected error %v", c.ref, err)
			continue
		}
		if key != c.wantKey || bucket != c.wantBucket {
			t.Errorf("parseS3Ref(%q) = (key=%q bucket=%q), want (key=%q bucket=%q)",
				c.ref, key, bucket, c.wantKey, c.wantBucket)
		}
	}
}

// fakeStore is an in-memory s3StorageOpener so the S3 adapter's fetch plumbing
// is exercised without any network or credentials.
type fakeStore struct {
	objects   map[string][]byte
	statErr   error
	openErr   error
	statByKey map[string]int64 // optional size override for Stat
}

func (f *fakeStore) Stat(_ context.Context, key string) (int64, error) {
	if f.statErr != nil {
		return 0, f.statErr
	}
	if f.statByKey != nil {
		if n, ok := f.statByKey[key]; ok {
			return n, nil
		}
	}
	b, ok := f.objects[key]
	if !ok {
		return 0, os.ErrNotExist
	}
	return int64(len(b)), nil
}

func (f *fakeStore) Open(_ context.Context, key string) (readCloser, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	b, ok := f.objects[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// newS3AdapterWithStore builds an s3Adapter wired to a fake store for testing.
func newS3AdapterWithStore(store s3StorageOpener, bucket, destDir string, maxBytes int64) *s3Adapter {
	return &s3Adapter{
		destDir:  destDir,
		maxBytes: maxBytes,
		store:    store,
		bucket:   bucket,
	}
}

func TestS3FetchFromFakeStore(t *testing.T) {
	body := []byte("PK\x03\x04 fake apk in s3")
	store := &fakeStore{objects: map[string][]byte{"builds/app.apk": body}}
	destDir := t.TempDir()
	a := newS3AdapterWithStore(store, "my-bucket", destDir, 1<<20)

	got, err := a.Fetch(context.Background(), "s3://my-bucket/builds/app.apk")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, body) {
		t.Errorf("content mismatch: got %d bytes", len(data))
	}
}

func TestS3FetchBucketMismatch(t *testing.T) {
	store := &fakeStore{objects: map[string][]byte{"app.apk": []byte("x")}}
	a := newS3AdapterWithStore(store, "configured-bucket", t.TempDir(), 1<<20)

	_, err := a.Fetch(context.Background(), "s3://other-bucket/app.apk")
	if err == nil {
		t.Fatal("expected bucket-mismatch error, got nil")
	}
	if !contains(err.Error(), "does not match configured bucket") {
		t.Errorf("error %q is not a bucket mismatch", err.Error())
	}
}

func TestS3FetchRejectsOversizeBeforeDownload(t *testing.T) {
	store := &fakeStore{
		objects:   map[string][]byte{"big.apk": []byte("x")},
		statByKey: map[string]int64{"big.apk": 10 << 20}, // Stat reports 10 MiB
	}
	a := newS3AdapterWithStore(store, "b", t.TempDir(), 1<<20) // cap 1 MiB

	_, err := a.Fetch(context.Background(), "s3://b/big.apk")
	if err == nil {
		t.Fatal("expected oversize rejection, got nil")
	}
	if !contains(err.Error(), "exceeds") {
		t.Errorf("error %q is not an oversize rejection", err.Error())
	}
}

func TestS3FetchNotConfiguredWithoutEnv(t *testing.T) {
	// With no injected store and no S3 env, the default newStore path must fail
	// with the actionable not-configured error.
	t.Setenv("MORF_STORAGE_BACKEND", "s3")
	t.Setenv("MORF_S3_BUCKET", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	a := &s3Adapter{destDir: t.TempDir(), maxBytes: 1 << 20, newStore: newEnvS3Store}
	_, err := a.Fetch(context.Background(), "s3://bucket/app.apk")
	if err == nil {
		t.Fatal("expected not-configured error, got nil")
	}
	if !isNotConfigured(err) {
		t.Errorf("error %v does not wrap ErrAdapterNotConfigured", err)
	}
}
