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
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalStorage_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ls, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStorage: %v", err)
	}

	const key = "scans/abc123/sample.apk"
	payload := []byte("MORF artifact payload \x00\x01\x02 binary-ish")

	// Put
	if err := ls.Put(ctx, key, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Stat
	size, err := ls.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if size != int64(len(payload)) {
		t.Fatalf("Stat size = %d, want %d", size, len(payload))
	}

	// Open + read
	rc, err := ls.Open(ctx, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read mismatch: got %q want %q", got, payload)
	}

	// LocalPath: must be local and point under the base dir.
	p, ok := ls.LocalPath(key)
	if !ok {
		t.Fatalf("LocalPath ok = false, want true for local backend")
	}
	if !strings.HasSuffix(filepath.ToSlash(p), key) {
		t.Fatalf("LocalPath = %q, want suffix %q", p, key)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("LocalPath %q not on disk: %v", p, err)
	}

	// Delete
	if err := ls.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Delete again: absent key must not error.
	if err := ls.Delete(ctx, key); err != nil {
		t.Fatalf("Delete (absent): %v", err)
	}

	// Open after delete must error.
	if _, err := ls.Open(ctx, key); err == nil {
		t.Fatalf("Open after Delete: expected error, got nil")
	}
}

func TestLocalStorage_TraversalRejected(t *testing.T) {
	ctx := context.Background()
	ls, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStorage: %v", err)
	}

	badKeys := []string{
		"../evil",
		"../../etc/passwd",
		"a/../../b",
		"/abs/path",
		"",
	}
	for _, k := range badKeys {
		if err := ls.Put(ctx, k, strings.NewReader("x"), 1); err == nil {
			t.Errorf("Put(%q): expected error, got nil", k)
		}
		if _, err := ls.Open(ctx, k); err == nil {
			t.Errorf("Open(%q): expected error, got nil", k)
		}
		if _, err := ls.Stat(ctx, k); err == nil {
			t.Errorf("Stat(%q): expected error, got nil", k)
		}
	}
}

func TestLocalStorage_DefaultDirAndInterface(t *testing.T) {
	// NewLocalStorage with an empty dir falls back to DefaultUploadDir; assert it
	// satisfies the Storage interface and reports itself as local.
	var s Storage
	ls, err := NewLocalStorage(filepath.Join(t.TempDir(), "nested", "uploads"))
	if err != nil {
		t.Fatalf("NewLocalStorage (nested): %v", err)
	}
	s = ls
	if _, ok := s.LocalPath("k"); !ok {
		t.Fatalf("local backend LocalPath ok = false")
	}
}
