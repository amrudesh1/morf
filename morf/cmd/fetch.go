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
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"morf/ingest"

	"github.com/spf13/cobra"
)

// fetchOptions carries the resolved flag state for a single `morf fetch`.
type fetchOptions struct {
	out      string // destination directory for the downloaded artifact
	maxBytes int64  // per-fetch size cap; 0 => framework default
	scan     bool   // if set, scan the fetched artifact instead of printing its path
	verify   bool   // passed through to the scan when --scan is set
}

// runFetch is the testable core of `morf fetch`: it resolves the adapter for
// ref's scheme, downloads into opts.out (or a temp dir), and prints the local
// path to stdout. It returns the process exit code and an error. The os.Exit
// boundary is kept in the cobra Run wrapper.
//
// Exit codes match the scan command's vocabulary: exitOK on success,
// exitOperational on any failure (unknown scheme, unconfigured vendor adapter,
// download/SSRF/size error). When --scan is set it hands the fetched path to the
// existing in-process scan pipeline and returns that command's exit code.
func runFetch(ctx context.Context, opts fetchOptions, ref string, stdout, stderr io.Writer) (int, error) {
	localPath, err := ingest.Fetch(ctx, ref, ingest.Options{
		DestDir:  opts.out,
		MaxBytes: opts.maxBytes,
	})
	if err != nil {
		// Surface the actionable "configure X" message for a vendor stub as-is;
		// it already names the env vars and points at docs/INGESTION.md.
		if errors.Is(err, ingest.ErrAdapterNotConfigured) {
			return exitOperational, err
		}
		return exitOperational, err
	}

	if opts.scan {
		scanOpts := scanOptions{verify: opts.verify}
		return runScan(ctx, scanOpts, localPath, stdout, stderr)
	}

	fmt.Fprintln(stdout, localPath)
	return exitOK, nil
}

// GetFetchCmd returns the `morf fetch` command: resolve a scheme-prefixed
// artifact reference to an adapter and download it to a local path, which is
// printed to stdout so it composes with the scan pipeline:
//
//	morf scan "$(morf fetch s3://bucket/app.apk --out /tmp)"
//
// or, in one step:
//
//	morf fetch https://host/signed-app.ipa --scan
func GetFetchCmd() *cobra.Command {
	var opts fetchOptions

	fetchCmd := &cobra.Command{
		Use:   "fetch <ref>",
		Short: "Fetch a mobile artifact from a remote source to a local path",
		Long: `Fetch an .apk/.ipa artifact named by a scheme-prefixed reference into a local
file and print its path to stdout. Supported schemes:

  s3://<bucket>/<key>    object in the configured S3 store (MORF_S3_*/AWS_*)
  https://<url>          pre-signed URL; SSRF-guarded, size-capped
                         (optional ?sha256=<hex> integrity check)
  file://<path> / <path> a bare local path (validated passthrough)

Vendor sources are registered but not yet implemented; they return a precise
"configure X" error naming the required credentials (see docs/INGESTION.md):

  appstoreconnect://<build-id>
  testflight://<build-id>
  xcodecloud://<build-id>
  googleplay://<package>

The download is size-capped (default from MORF_INGEST_MAX_BYTES, else 500 MiB;
override per-call with --max-bytes) and never follows a reference to an internal
host. Pass --scan to scan the fetched artifact in-process instead of printing
its path.

Exit codes: 0 success; 1 operational error (unknown scheme, unconfigured
adapter, download/SSRF/size failure). With --scan the scan's own gate exit code
(0 pass / 4 policy hit / 1 operational) is returned.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			code, err := runFetch(cmd.Context(), opts, args[0], os.Stdout, os.Stderr)
			if err != nil {
				fmt.Fprintln(os.Stderr, "morf fetch:", err)
			}
			os.Exit(code)
		},
	}

	fetchCmd.Flags().StringVar(&opts.out, "out", "", "Directory to download into (default: a temp dir)")
	fetchCmd.Flags().Int64Var(&opts.maxBytes, "max-bytes", 0, "Maximum download size in bytes (0 = default)")
	fetchCmd.Flags().BoolVar(&opts.scan, "scan", false, "Scan the fetched artifact in-process instead of printing its path")
	fetchCmd.Flags().BoolVar(&opts.verify, "verify", false, "With --scan: enable live (read-only) verification of findings")

	return fetchCmd
}
