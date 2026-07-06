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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// ExecuteCommand executes a shell command with a default timeout and returns its output
func ExecuteCommand(command string, args ...string) (string, error) {
	// Default timeout: 5 minutes
	return ExecuteCommandWithTimeout(5*time.Minute, command, args...)
}

// ExecuteCommandWithTimeout executes a shell command with a specified timeout and returns its output.
//
// It is a thin wrapper over RunWithContext: it builds a context with the given
// timeout and delegates execution. Its external contract is preserved for the
// (still un-migrated) callers that depend on it — it returns ("", err) on ANY
// failure, where err satisfies errors.Is(err, context.DeadlineExceeded) on timeout.
func ExecuteCommandWithTimeout(timeout time.Duration, command string, args ...string) (string, error) {
	log.Infof("Executing command: %s %s (timeout: %v)", command, strings.Join(args, " "), timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout, err := RunWithContext(ctx, command, args...)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Errorf("Command execution timeout after %v: %s %s\n%v", timeout, command, strings.Join(args, " "), err)
		} else {
			log.Errorf("Command execution failed: %v", err)
		}
		// Preserve historical behavior: discard partial stdout on error.
		return "", err
	}

	return string(stdout), nil
}

// RunWithContext runs name+args bound to the caller-supplied ctx and returns the
// child's full stdout. The whole stdout is buffered in memory; for large or
// streaming output prefer RunWithContextStream.
//
// Behavior:
//   - Uses the passed ctx (exec.CommandContext) — no internal context.Background.
//   - Runs the child in its own process group (Setpgid). On ctx cancel/deadline
//     the ENTIRE process group is SIGKILLed (not just the direct child) so any
//     grandchildren (e.g. java/rg helpers) die too. This is done via cmd.Cancel,
//     so there is no watcher goroutine to leak.
//   - Best-effort applies a memory rlimit (see applyMemoryLimitBestEffort) when
//     MORF_SUBPROC_MEM_BYTES is set.
//   - stderr is captured and folded into the returned error on failure.
//   - The returned error preserves *exec.ExitError (errors.As works). On
//     timeout/cancel the returned error satisfies errors.Is(err, context.DeadlineExceeded)
//     (resp. context.Canceled) instead, so ExitCodeOf can report the timeout sentinel.
func RunWithContext(ctx context.Context, name string, args ...string) (stdout []byte, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	configureChildProcess(cmd)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if startErr := cmd.Start(); startErr != nil {
		return nil, fmt.Errorf("failed to start command %q: %w", name, startErr)
	}

	// The child is running now; apply the best-effort memory rlimit to it.
	applyMemoryLimitBestEffort(cmd.Process.Pid)

	waitErr := cmd.Wait()
	if waitErr != nil {
		return outBuf.Bytes(), mapRunError(name, ctx, waitErr, &errBuf)
	}
	return outBuf.Bytes(), nil
}

// RunWithContextStream runs name+args bound to ctx and streams the child's stdout
// line-by-line to onLine WITHOUT accumulating the whole output in memory
// (addresses the SCAN-7 buffering / memory concern). The scanner uses an enlarged
// buffer so very long lines (up to ~4MB) are handled instead of failing.
//
// The slice passed to onLine is only valid for the duration of that call (it is
// the scanner's internal buffer); callers that need to retain it must copy. If
// onLine returns an error, the child's process group is killed and that error is
// returned. Otherwise, after the stream drains, the child is waited on and its
// exit error is returned (preserving *exec.ExitError / context.DeadlineExceeded,
// exactly like RunWithContext).
func RunWithContextStream(ctx context.Context, onLine func(line []byte) error, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	configureChildProcess(cmd)

	stdoutPipe, pipeErr := cmd.StdoutPipe()
	if pipeErr != nil {
		return fmt.Errorf("failed to open stdout pipe for command %q: %w", name, pipeErr)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	if startErr := cmd.Start(); startErr != nil {
		return fmt.Errorf("failed to start command %q: %w", name, startErr)
	}
	applyMemoryLimitBestEffort(cmd.Process.Pid)

	scanner := bufio.NewScanner(stdoutPipe)
	// Grow the max token size to 4MB so long lines do not abort the scan.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var callbackErr error
	for scanner.Scan() {
		if cbErr := onLine(scanner.Bytes()); cbErr != nil {
			callbackErr = cbErr
			break
		}
	}
	scanErr := scanner.Err()

	if callbackErr != nil {
		// Stop the child (whole group) so Wait can return promptly.
		if cmd.Process != nil {
			_ = killProcessGroup(cmd.Process.Pid)
		}
	}

	waitErr := cmd.Wait()

	// Callback error takes priority: it is the reason we stopped reading.
	if callbackErr != nil {
		return callbackErr
	}
	if scanErr != nil {
		// A read error on the pipe; still report any ctx/exit error if more telling.
		if waitErr != nil {
			return mapRunError(name, ctx, waitErr, &errBuf)
		}
		return fmt.Errorf("error reading stdout of command %q: %w", name, scanErr)
	}
	if waitErr != nil {
		return mapRunError(name, ctx, waitErr, &errBuf)
	}
	return nil
}

// ExitCodeOf classifies an error produced by the Run* helpers into an exit code:
//   - nil                              -> 0
//   - wraps *exec.ExitError            -> its ExitCode()
//   - wraps context.DeadlineExceeded   -> -2 (timeout sentinel)
//   - anything else                    -> -1
func ExitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return -2
	}
	return -1
}

// mapRunError converts a cmd.Wait() error into the error contract used by the
// Run* helpers. When the failure was caused by the context being done
// (deadline/cancel) we surface the ctx error (so errors.Is works and ExitCodeOf
// can report the timeout sentinel) rather than the "signal: killed" ExitError
// that the kill produced. Otherwise we preserve the original error (commonly an
// *exec.ExitError) via %w and fold in captured stderr for diagnostics.
func mapRunError(name string, ctx context.Context, waitErr error, stderr *bytes.Buffer) error {
	stderrText := strings.TrimSpace(stderr.String())
	if ctxErr := ctx.Err(); ctxErr != nil {
		if stderrText != "" {
			return fmt.Errorf("command %q did not complete (%w); stderr: %s", name, ctxErr, stderrText)
		}
		return fmt.Errorf("command %q did not complete: %w", name, ctxErr)
	}
	if stderrText != "" {
		return fmt.Errorf("command %q failed: %w; stderr: %s", name, waitErr, stderrText)
	}
	return fmt.Errorf("command %q failed: %w", name, waitErr)
}

// configureChildProcess makes the child its own process-group leader and rewires
// cmd.Cancel so that ctx cancel/deadline kills the WHOLE group rather than just
// the direct child. Using cmd.Cancel (Go 1.20+) avoids spawning a watcher
// goroutine, so there is nothing to leak.
func configureChildProcess(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true // child becomes leader of a new process group

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killProcessGroup(cmd.Process.Pid)
	}
	// Give the group a short grace period to die after Cancel before Wait gives
	// up, so a stuck child cannot hang the caller indefinitely.
	cmd.WaitDelay = 10 * time.Second
}

// killProcessGroup SIGKILLs the entire process group led by pid. Because the
// child was started with Setpgid, its PGID equals its PID, so the group is -pid.
// Falls back to killing just the process if the group kill fails.
func killProcessGroup(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		return syscall.Kill(pid, syscall.SIGKILL)
	}
	return nil
}

// applyMemoryLimitBestEffort applies a RLIMIT_AS (address-space) limit to the
// freshly-started child identified by pid, when MORF_SUBPROC_MEM_BYTES is set to
// a positive byte count.
//
// IMPORTANT: this is BEST-EFFORT and deliberately not claimed to always work.
// Setting RLIMIT_AS on *another* process from the parent requires prlimit(2),
// which is Linux-only and is NOT exposed portably by the Go standard syscall
// package (it is absent on darwin, the primary dev platform). Rather than
// fabricate a guarantee, we shell out to the prlimit(1) utility when it is
// present on PATH. On platforms where prlimit is unavailable, or where the call
// is denied by permissions, we log at debug level and continue WITHOUT failing
// the run. The hook is intentionally left in place so a Linux deployment that
// ships util-linux gets the limit, while no platform is misled into thinking the
// limit is guaranteed.
func applyMemoryLimitBestEffort(pid int) {
	if runtime.GOOS == "windows" {
		return
	}
	raw := os.Getenv("MORF_SUBPROC_MEM_BYTES")
	if raw == "" {
		return
	}
	n, parseErr := strconv.ParseInt(raw, 10, 64)
	if parseErr != nil || n <= 0 {
		log.Debugf("MORF_SUBPROC_MEM_BYTES=%q is not a valid positive byte count; skipping memory rlimit", raw)
		return
	}
	prlimitPath, lookErr := exec.LookPath("prlimit")
	if lookErr != nil {
		log.Debugf("MORF_SUBPROC_MEM_BYTES set but prlimit(1) is unavailable (%v); memory rlimit applied best-effort only", lookErr)
		return
	}
	out, runErr := exec.Command(prlimitPath, "--pid", strconv.Itoa(pid), fmt.Sprintf("--as=%d", n)).CombinedOutput()
	if runErr != nil {
		log.Debugf("best-effort RLIMIT_AS via prlimit for pid %d failed: %v (%s)", pid, runErr, strings.TrimSpace(string(out)))
		return
	}
	log.Debugf("applied best-effort RLIMIT_AS=%d bytes to pid %d via prlimit", n, pid)
}

// sanitizePatterns holds the regexes used by SanitizeCommandOutput to mask
// sensitive values (passwords, keys, secrets, tokens, auth) in command output.
// They are compiled once at package init so SanitizeCommandOutput performs real
// regex matching rather than an impossible literal-string replacement.
var sanitizePatterns = []struct {
	re   *regexp.Regexp
	mask string
}{
	{regexp.MustCompile(`password=[\w\-\.]+`), "password=*****"},
	{regexp.MustCompile(`key=[\w\-\.]+`), "key=*****"},
	{regexp.MustCompile(`secret=[\w\-\.]+`), "secret=*****"},
	{regexp.MustCompile(`token=[\w\-\.]+`), "token=*****"},
	{regexp.MustCompile(`auth=[\w\-\.]+`), "auth=*****"},
}

// SanitizeCommandOutput removes sensitive information from command output
func SanitizeCommandOutput(input string) string {
	result := input
	for _, p := range sanitizePatterns {
		result = p.re.ReplaceAllString(result, p.mask)
	}

	return result
}
