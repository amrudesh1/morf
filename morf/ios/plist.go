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
	"sort"
	"strconv"

	"howett.net/plist"
)

// IOSPlistData is the decoded, scanner-facing view of an app's Info.plist. It is
// a superset of the thin InfoPlist in foundation.go: in addition to the flat
// identity fields it captures the NSAppTransportSecurity exception map so the
// caller can persist ATS posture. Decoding goes through howett.net/plist, which
// auto-detects binary (bplist00) vs XML plist encodings.
type IOSPlistData struct {
	BundleIdentifier string
	BundleVersion    string
	ExecutableName   string
	MinimumOSVersion string
	URLSchemes       []string
	// ATSExceptions is the NSAppTransportSecurity subtree flattened to a map of
	// dotted keys to string values (e.g. "NSAllowsArbitraryLoads" -> "true",
	// "NSExceptionDomains.example.com.NSExceptionAllowsInsecureHTTPLoads" ->
	// "true"). Stored as-is for JSON persistence on IOSMetadata.ATSExceptions.
	ATSExceptions map[string]string
}

// DecodeInfoPlistFull decodes an Info.plist (binary or XML) into IOSPlistData,
// including URL schemes and the flattened ATS exception map.
func DecodeInfoPlistFull(data []byte) (*IOSPlistData, error) {
	base, err := DecodeInfoPlist(data)
	if err != nil {
		return nil, err
	}

	out := &IOSPlistData{
		BundleIdentifier: base.BundleIdentifier,
		BundleVersion:    base.BundleVersion,
		ExecutableName:   base.ExecutableName,
		MinimumOSVersion: base.MinimumOSVersion,
		URLSchemes:       base.URLSchemes,
		ATSExceptions:    map[string]string{},
	}

	// NSAppTransportSecurity is a nested dictionary of heterogeneous types
	// (bools, nested dicts). Decode it into a generic map and flatten it.
	var atsHolder struct {
		ATS map[string]interface{} `plist:"NSAppTransportSecurity"`
	}
	if _, err := plist.Unmarshal(data, &atsHolder); err == nil && atsHolder.ATS != nil {
		flattenPlistMap("", atsHolder.ATS, out.ATSExceptions)
	}

	return out, nil
}

// flattenPlistMap flattens a nested plist dictionary into dst using dotted keys.
// Scalars are stringified; nested maps recurse; arrays are indexed. This keeps
// the ATS subtree representable as a flat JSON object on IOSMetadata.
func flattenPlistMap(prefix string, m map[string]interface{}, dst map[string]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		flattenPlistValue(key, v, dst)
	}
}

func flattenPlistValue(key string, v interface{}, dst map[string]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		flattenPlistMap(key, t, dst)
	case []interface{}:
		for i, e := range t {
			flattenPlistValue(key+"."+strconv.Itoa(i), e, dst)
		}
	case bool:
		dst[key] = strconv.FormatBool(t)
	case string:
		dst[key] = t
	case uint64:
		dst[key] = strconv.FormatUint(t, 10)
	case int64:
		dst[key] = strconv.FormatInt(t, 10)
	case float64:
		dst[key] = strconv.FormatFloat(t, 'g', -1, 64)
	default:
		dst[key] = fmt.Sprintf("%v", t)
	}
}

// PlistStringValues decodes an arbitrary plist (binary or XML) and returns every
// string scalar found anywhere in it (recursively through dicts and arrays).
// These are appended to the strings corpus so secrets embedded in Info.plist or
// any embedded plist (e.g. a config .plist bundled in the app) are scanned too.
func PlistStringValues(data []byte) ([]string, error) {
	var root interface{}
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode plist: %w", err)
	}
	var out []string
	collectPlistStrings(root, &out)
	// Deterministic ordering aids reproducible corpora and tests.
	sort.Strings(out)
	return out, nil
}

// collectPlistStrings walks a decoded plist value and appends every string
// (both keys and values) it encounters to out.
func collectPlistStrings(v interface{}, out *[]string) {
	switch t := v.(type) {
	case string:
		if len(t) > 0 {
			*out = append(*out, t)
		}
	case map[string]interface{}:
		for k, e := range t {
			if len(k) > 0 {
				*out = append(*out, k)
			}
			collectPlistStrings(e, out)
		}
	case []interface{}:
		for _, e := range t {
			collectPlistStrings(e, out)
		}
	}
}

// AppendPlistCorpus decodes the plist at plistPath (binary or XML) and appends
// its string values to the corpus file, each tagged with a provenance prefix so
// the scanner can attribute a hit back to the source plist. A decode failure is
// returned so the caller can log-and-continue (an embedded plist that fails to
// parse should not abort the whole scan).
func AppendPlistCorpus(corpusPath, plistPath string) error {
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return fmt.Errorf("read plist %q: %w", plistPath, err)
	}
	values, err := PlistStringValues(data)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(corpusPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open corpus %q: %w", corpusPath, err)
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	for _, s := range values {
		if _, err := fmt.Fprintf(bw, "[plist=%s] %s\n", plistPath, sanitizeLine(s)); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush corpus %q: %w", corpusPath, err)
	}
	return nil
}
