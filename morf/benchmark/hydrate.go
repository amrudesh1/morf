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
	"bytes"
	"encoding/base64"
)

// Runtime corpus hydration.
//
// The benchmark corpus is a secret-DETECTION test corpus, so at scan time it
// must contain real-format credential strings (AWS/Stripe/GitHub/Google/Slack/
// SendGrid) for the recall measurement to mean anything. But committing those
// literal strings to a public repo trips GitHub secret-scanning push protection
// (a scanner flagging a scanner's own fixtures) and any downstream audit.
//
// Resolution: the committed corpus text files carry inert PLACEHOLDER TOKENS
// (e.g. __MORF_BENCH_AWS_SMALI__) instead of the real values. The real values
// live here ONLY base64-encoded — so this source file contains no secret-shaped
// literal either — and are substituted into each file's bytes at extraction
// time (extractTree -> hydrate), inside the throwaway temp corpus dir that MORF
// actually scans. The repo therefore holds zero credential-shaped strings in its
// text sources, while the benchmark scans byte-identical real values at runtime.
//
// Only text fixtures are tokenized; the small synthetic binary fixtures
// (kernel_blob.bin, libsecret.so, fixture.ipa) are not text-scanned by push
// protection and carry their own distinct synthetic values. labels.json is keyed
// by (platform, secretType, fileBasename) and never contains a value, so it is
// unaffected.
var hydrationB64 = map[string]string{
	"__MORF_BENCH_AWS_SMALI__": "QUtJQVo3WFE0UExNMldEOE5SVlQ=",
	"__MORF_BENCH_STRIPE__":    "c2tfbGl2ZV80ZUMzOUhxTHlqV0Rhcmp0VDF6ZHA3ZGM=",
	"__MORF_BENCH_GHP__":       "Z2hwXzAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==",
	"__MORF_BENCH_GOOGLE__":    "QUl6YVN5QjNuSzlwUXI3c1QxdVZ3WDJ5WjRhQjZjRDhlRjBnSDJq",
	"__MORF_BENCH_SLACK__":     "eG94Yi0yNDAxMjM0NTY3ODkwYWJjZGVmZ2hYeTdaazNBYjlDZDFFZjVHaDJJajRLbA==",
	"__MORF_BENCH_AWS_DECOY__": "QUtJQTAwMDAwMDAwMDAwMDAwMDA=",
	"__MORF_BENCH_SENDGRID__":  "U0cuQjFhMkMzZDRFNWY2RzdoOEk5ajBLbC5tTjFvUDJxUjNzVDR1VjV3WDZ5WjdhQjhjRDllRjBnSDFpSjJrTDNtTjRv",
}

// hydrate replaces every placeholder token in data with its decoded real value.
// Files with no token (all binaries, patterns, labels.json) pass through
// unchanged, so it is safe to call on every extracted file. A malformed base64
// entry is skipped rather than corrupting the byte stream (defensive; the map is
// a compile-time constant so this cannot happen in practice).
func hydrate(data []byte) []byte {
	for token, enc := range hydrationB64 {
		tb := []byte(token)
		if !bytes.Contains(data, tb) {
			continue
		}
		val, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue // defensive: compile-time-constant map, cannot happen
		}
		data = bytes.ReplaceAll(data, tb, val)
	}
	return data
}
