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

package benchmark

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// WriteJSON serializes the reports as indented JSON to w.
func WriteJSON(w io.Writer, reports []Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// WriteTable renders a human-readable precision/recall table to w, showing the
// Before vs After (ApplyPrecision) metrics per platform, the false-positive
// drop, raw-vs-kept counts, and the post-precision tier histogram.
func WriteTable(w io.Writer, reports []Report) {
	fmt.Fprintln(w, "MORF detection precision/recall benchmark (apktool-free, hermetic)")
	fmt.Fprintln(w, "Before = raw findings; After = post detect.ApplyPrecision")
	fmt.Fprintln(w, "")

	header := fmt.Sprintf("%-9s | %-6s | %5s %5s %5s | %5s %5s %5s | %s",
		"platform", "stage", "P", "R", "F1", "TP", "FP", "FN", "")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, ruler(len(header)))

	for _, r := range reports {
		fmt.Fprintf(w, "%-9s | %-6s | %5.2f %5.2f %5.2f | %5d %5d %5d |\n",
			r.Platform, "before",
			r.Before.Precision, r.Before.Recall, r.Before.F1,
			r.Before.TP, r.Before.FP, r.Before.FN)
		fmt.Fprintf(w, "%-9s | %-6s | %5.2f %5.2f %5.2f | %5d %5d %5d | FP drop=%d, raw=%d kept=%d, tiers=%s\n",
			"", "after",
			r.After.Precision, r.After.Recall, r.After.F1,
			r.After.TP, r.After.FP, r.After.FN,
			r.FalsePositiveDrop, r.RawFindings, r.KeptFindings, formatTiers(r.TierCounts))
		if len(r.TierMismatches) > 0 {
			for _, mm := range r.TierMismatches {
				fmt.Fprintf(w, "%-9s | %-6s | tier mismatch: %s\n", "", "", mm)
			}
		}
	}

	fmt.Fprintln(w, "")
	agg := aggregate(reports)
	fmt.Fprintf(w, "TOTAL after-precision: P=%.2f R=%.2f F1=%.2f (TP=%d FP=%d FN=%d), total FP drop=%d\n",
		agg.After.Precision, agg.After.Recall, agg.After.F1,
		agg.After.TP, agg.After.FP, agg.After.FN, agg.FalsePositiveDrop)
}

// aggregate sums the confusion matrices across platforms and recomputes the
// pooled precision/recall/F1, so a single headline line summarizes the run.
func aggregate(reports []Report) Report {
	var agg Report
	agg.Platform = "ALL"
	for _, r := range reports {
		agg.Before.TP += r.Before.TP
		agg.Before.FP += r.Before.FP
		agg.Before.FN += r.Before.FN
		agg.After.TP += r.After.TP
		agg.After.FP += r.After.FP
		agg.After.FN += r.After.FN
		agg.FalsePositiveDrop += r.FalsePositiveDrop
		agg.RawFindings += r.RawFindings
		agg.KeptFindings += r.KeptFindings
	}
	agg.Before.Precision = ratio(agg.Before.TP, agg.Before.TP+agg.Before.FP)
	agg.Before.Recall = ratio(agg.Before.TP, agg.Before.TP+agg.Before.FN)
	if agg.Before.Precision+agg.Before.Recall > 0 {
		agg.Before.F1 = 2 * agg.Before.Precision * agg.Before.Recall / (agg.Before.Precision + agg.Before.Recall)
	}
	agg.After.Precision = ratio(agg.After.TP, agg.After.TP+agg.After.FP)
	agg.After.Recall = ratio(agg.After.TP, agg.After.TP+agg.After.FN)
	if agg.After.Precision+agg.After.Recall > 0 {
		agg.After.F1 = 2 * agg.After.Precision * agg.After.Recall / (agg.After.Precision + agg.After.Recall)
	}
	return agg
}

func formatTiers(counts map[string]int) string {
	if len(counts) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := "{"
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s:%d", k, counts[k])
	}
	return out + "}"
}

func ruler(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}
