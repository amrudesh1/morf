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

package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFetchFilePassthroughPrintsPath(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code, err := runFetch(context.Background(), fetchOptions{}, apk, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runFetch: %v", err)
	}
	if code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if got := strings.TrimSpace(stdout.String()); got != apk {
		t.Errorf("stdout = %q, want %q", got, apk)
	}
}

func TestRunFetchUnknownSchemeIsOperational(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := runFetch(context.Background(), fetchOptions{}, "ftp://host/app.apk", &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
	if code != exitOperational {
		t.Errorf("exit code = %d, want %d", code, exitOperational)
	}
}

func TestRunFetchVendorStubIsOperationalAndActionable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, err := runFetch(context.Background(), fetchOptions{}, "googleplay://com.example.app", &stdout, &stderr)
	if err == nil {
		t.Fatal("expected not-configured error for vendor stub")
	}
	if code != exitOperational {
		t.Errorf("exit code = %d, want %d", code, exitOperational)
	}
	if !strings.Contains(err.Error(), "MORF_GOOGLE_PLAY_SA_JSON") {
		t.Errorf("error %q does not name the required env var", err.Error())
	}
	if !strings.Contains(err.Error(), "docs/INGESTION.md") {
		t.Errorf("error %q does not point at the docs", err.Error())
	}
}

func TestGetFetchCmdWiring(t *testing.T) {
	cmd := GetFetchCmd()
	if cmd.Use != "fetch <ref>" {
		t.Errorf("Use = %q", cmd.Use)
	}
	for _, flag := range []string{"out", "max-bytes", "scan", "verify"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing --%s flag", flag)
		}
	}
	// ExactArgs(1): zero args must be rejected.
	if err := cmd.Args(cmd, nil); err == nil {
		t.Error("expected ExactArgs(1) to reject zero args")
	}
}
