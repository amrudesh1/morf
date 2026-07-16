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
	"os"

	"morf/benchmark"

	"github.com/spf13/cobra"
)

// GetBenchCmd returns the `morf benchmark` subcommand. It runs the hermetic,
// apktool-free precision/recall benchmark against an embedded labeled corpus and
// prints a per-platform table of detection metrics Before vs After the precision
// engine (detect.ApplyPrecision), including the false-positive drop the engine
// delivers. It needs only ripgrep on PATH — no apktool, JVM, device, database,
// Redis or network — so it doubles as a fast, deterministic regression check for
// the detection core. Pass --json to emit the raw []benchmark.Report as JSON.
func GetBenchCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "benchmark",
		Short: "Run the hermetic precision/recall detection benchmark",
		Long: `Run a self-contained precision/recall benchmark for MORF's detection core.

An embedded, fully-labeled corpus (planted true-positive secrets plus realistic
false-positive bait, laid out across android- and ios-shaped decompiled trees) is
materialized to a temp directory and scanned with the real detection core
(detect.ScanCorpus + ScanCorpusText), then re-scored after detect.ApplyPrecision.
The command reports precision, recall and F1 per platform Before vs After the
precision engine, so the false-positive reduction is measured directly.

The only external dependency is ripgrep (rg); there is no apktool, JVM, device,
database, Redis or network involved, and the corpus is fixed, so the result is
deterministic.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			reports, err := benchmark.RunBenchmark(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				return benchmark.WriteJSON(os.Stdout, reports)
			}
			benchmark.WriteTable(os.Stdout, reports)
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "emit the reports as JSON instead of a table")
	// Silence cobra's automatic usage dump on a runtime error (e.g. rg missing):
	// the returned error message is enough and clearer without the usage wall.
	c.SilenceUsage = true
	return c
}
