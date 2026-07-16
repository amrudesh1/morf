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

package ios

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// AppendJSONCorpus reads the (JSON) config file at jsonPath and appends its
// lines to the corpus file, each tagged with a provenance prefix so a scanner
// hit is attributable back to the source file.
//
// Unlike the plist path, this treats the file as raw text rather than parsing
// it: embedded JSON config (e.g. Firebase's GoogleService-Info.json,
// google-services.json, or any bundled *.json) stores secrets as plain string
// values, and ripgrep matches on raw text anyway. Reading raw text means a
// malformed / partial / comment-bearing JSON file is still scanned instead of
// being silently dropped on a parse error — matching the "log-and-continue,
// never abort" contract of the plist sweep. A read failure is returned so the
// caller can log-and-continue.
func AppendJSONCorpus(corpusPath, jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("read json %q: %w", jsonPath, err)
	}

	f, err := os.OpenFile(corpusPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open corpus %q: %w", corpusPath, err)
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	for _, line := range strings.Split(string(data), "\n") {
		if _, err := fmt.Fprintf(bw, "[json=%s] %s\n", jsonPath, sanitizeLine(line)); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush corpus %q: %w", corpusPath, err)
	}
	return nil
}
