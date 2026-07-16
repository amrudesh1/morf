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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isNotConfigured reports whether err wraps ErrAdapterNotConfigured.
func isNotConfigured(err error) bool { return errors.Is(err, ErrAdapterNotConfigured) }

// contains is a tiny substring helper used across the package tests.
func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestFileAdapterPassthrough(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatal(err)
	}

	// bare path
	got, err := Fetch(context.Background(), apk, Options{})
	if err != nil {
		t.Fatalf("Fetch(%q): %v", apk, err)
	}
	if got != apk {
		t.Errorf("Fetch returned %q, want passthrough %q", got, apk)
	}

	// explicit file:// form resolves to the same path
	got2, err := Fetch(context.Background(), "file://"+apk, Options{})
	if err != nil {
		t.Fatalf("Fetch(file://%q): %v", apk, err)
	}
	if got2 != apk {
		t.Errorf("file:// Fetch returned %q, want %q", got2, apk)
	}
}

func TestFileAdapterRejects(t *testing.T) {
	dir := t.TempDir()

	// nonexistent
	if _, err := Fetch(context.Background(), filepath.Join(dir, "missing.apk"), Options{}); err == nil {
		t.Error("expected error for missing file")
	}
	// wrong extension
	txt := filepath.Join(dir, "app.txt")
	os.WriteFile(txt, []byte("x"), 0o644)
	if _, err := Fetch(context.Background(), txt, Options{}); err == nil {
		t.Error("expected error for non-apk/ipa extension")
	}
	// a directory
	if _, err := Fetch(context.Background(), dir, Options{}); err == nil {
		t.Error("expected error for directory path")
	}
}
