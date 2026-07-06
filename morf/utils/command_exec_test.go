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
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestRunWithContext exercises RunWithContext + ExitCodeOf across the success,
// non-zero-exit, and timeout paths.
func TestRunWithContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh -c based tests are not supported on windows")
	}

	tests := []struct {
		name         string
		args         []string
		ctxTimeout   time.Duration
		wantStdout   string
		wantExitCode int
		wantDeadline bool
	}{
		{
			name:         "exit 0 with stdout",
			args:         []string{"-c", "printf 'hello world'"},
			ctxTimeout:   5 * time.Second,
			wantStdout:   "hello world",
			wantExitCode: 0,
		},
		{
			name:         "exit 2 is reported by ExitCodeOf",
			args:         []string{"-c", "exit 2"},
			ctxTimeout:   5 * time.Second,
			wantExitCode: 2,
		},
		{
			name:         "timeout yields DeadlineExceeded and -2 sentinel",
			args:         []string{"-c", "sleep 5"},
			ctxTimeout:   150 * time.Millisecond,
			wantExitCode: -2,
			wantDeadline: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.ctxTimeout)
			defer cancel()

			stdout, err := RunWithContext(ctx, "sh", tc.args...)

			if got := ExitCodeOf(err); got != tc.wantExitCode {
				t.Fatalf("ExitCodeOf(err)=%d, want %d (err=%v)", got, tc.wantExitCode, err)
			}
			if tc.wantExitCode == 0 && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if string(stdout) != tc.wantStdout {
				t.Fatalf("stdout=%q, want %q", string(stdout), tc.wantStdout)
			}
			if tc.wantDeadline && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected errors.Is(err, context.DeadlineExceeded), got %v", err)
			}
			if !tc.wantDeadline && tc.wantExitCode != 0 && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("did not expect DeadlineExceeded, got %v", err)
			}
		})
	}
}

// TestRunWithContextStream verifies that stdout is delivered line-by-line.
func TestRunWithContextStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh -c based tests are not supported on windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lines []string
	err := RunWithContextStream(ctx, func(line []byte) error {
		// The slice is only valid during the callback; copy by converting to string.
		lines = append(lines, string(line))
		return nil
	}, "sh", "-c", "printf 'a\\nb\\nc\\n'")
	if err != nil {
		t.Fatalf("RunWithContextStream returned error: %v", err)
	}

	want := []string{"a", "b", "c"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines %q, want %d %q", len(lines), lines, len(want), want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line[%d]=%q, want %q", i, lines[i], want[i])
		}
	}
}

// TestRunWithContextStreamCallbackError verifies that a callback error stops the
// stream and is propagated back to the caller.
func TestRunWithContextStreamCallbackError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh -c based tests are not supported on windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sentinel := errors.New("stop now")
	count := 0
	err := RunWithContextStream(ctx, func(line []byte) error {
		count++
		return sentinel
	}, "sh", "-c", "printf '1\\n2\\n3\\n'")

	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if count != 1 {
		t.Fatalf("expected callback to be invoked once before stopping, got %d", count)
	}
}

// TestExitCodeOf covers the classification table directly.
func TestExitCodeOf(t *testing.T) {
	if got := ExitCodeOf(nil); got != 0 {
		t.Fatalf("ExitCodeOf(nil)=%d, want 0", got)
	}
	if got := ExitCodeOf(context.DeadlineExceeded); got != -2 {
		t.Fatalf("ExitCodeOf(DeadlineExceeded)=%d, want -2", got)
	}
	if got := ExitCodeOf(errors.New("some other error")); got != -1 {
		t.Fatalf("ExitCodeOf(other)=%d, want -1", got)
	}
}

// TestExecuteCommandWithTimeoutPreservesContract ensures the legacy wrapper still
// returns ("", err) on failure and the stdout string on success.
func TestExecuteCommandWithTimeoutPreservesContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh -c based tests are not supported on windows")
	}

	out, err := ExecuteCommandWithTimeout(5*time.Second, "sh", "-c", "printf 'ok'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Fatalf("stdout=%q, want %q", out, "ok")
	}

	out, err = ExecuteCommandWithTimeout(5*time.Second, "sh", "-c", "exit 3")
	if err == nil {
		t.Fatalf("expected error for exit 3")
	}
	if out != "" {
		t.Fatalf("expected empty stdout on error, got %q", out)
	}
	if got := ExitCodeOf(err); got != 3 {
		t.Fatalf("ExitCodeOf(err)=%d, want 3", got)
	}

	out, err = ExecuteCommandWithTimeout(150*time.Millisecond, "sh", "-c", "sleep 5")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if out != "" {
		t.Fatalf("expected empty stdout on timeout, got %q", out)
	}
	// Sanity: ensure stderr folding does not panic on a command that writes stderr.
	_, err = RunWithContext(context.Background(), "sh", "-c", "echo boom 1>&2; exit 1")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected stderr 'boom' folded into error, got %v", err)
	}
}
