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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// FrameworkInfo describes one embedded framework or dylib and the architectures
// its Mach-O binary contains.
type FrameworkInfo struct {
	// Name is the framework/dylib file or bundle name (e.g. "Alamofire.framework"
	// or "libswiftCore.dylib").
	Name string
	// Path is the absolute path to the framework bundle or dylib file.
	Path string
	// BinaryPath is the absolute path to the Mach-O binary inside (for a
	// .framework this is Frameworks/X.framework/X; for a .dylib it is the file
	// itself). Empty if no Mach-O could be located.
	BinaryPath string
	// Architectures are the CPU arch names present in BinaryPath.
	Architectures []string
	// IsEncrypted is true if any slice reports a FairPlay cryptid != 0.
	IsEncrypted bool
}

// EnumerateFrameworks resolves the Mach-O binary for each embedded framework
// and dylib from an UnpackedIPA and records its architectures/encryption. It is
// best-effort: a framework whose binary cannot be parsed is skipped (logged),
// never fatal.
func EnumerateFrameworks(jobID string, up *UnpackedIPA) []FrameworkInfo {
	var out []FrameworkInfo

	for _, fw := range up.Frameworks {
		info := FrameworkInfo{Name: filepath.Base(fw), Path: fw}
		// The framework's binary shares the bundle's base name without the
		// ".framework" suffix, e.g. Alamofire.framework/Alamofire.
		base := strings.TrimSuffix(filepath.Base(fw), ".framework")
		candidate := filepath.Join(fw, base)
		if fileExists(candidate) {
			info.BinaryPath = candidate
		}
		fillArch(jobID, &info)
		out = append(out, info)
	}

	for _, dl := range up.Dylibs {
		info := FrameworkInfo{Name: filepath.Base(dl), Path: dl, BinaryPath: dl}
		fillArch(jobID, &info)
		out = append(out, info)
	}

	return out
}

// fillArch parses the Mach-O at info.BinaryPath (if any) and fills the arch and
// encryption fields. Parse failures are logged and swallowed (best-effort).
func fillArch(jobID string, info *FrameworkInfo) {
	if info.BinaryPath == "" {
		return
	}
	mi, err := InspectMachO(info.BinaryPath)
	if err != nil {
		log.WithFields(log.Fields{
			"job_id": jobID,
			"binary": info.BinaryPath,
			"error":  err.Error(),
		}).Debug("Skipping unparseable embedded binary")
		return
	}
	info.Architectures = mi.Architectures
	info.IsEncrypted = mi.IsEncrypted
}

// FrameworkNames returns just the display names of a FrameworkInfo slice, for
// the JSON list persisted on IOSMetadata.Frameworks.
func FrameworkNames(fws []FrameworkInfo) []string {
	names := make([]string, 0, len(fws))
	for _, fw := range fws {
		names = append(names, fw.Name)
	}
	return names
}

// ParseEntitlements extracts the entitlements dictionary from an
// embedded.mobileprovision file, best-effort. A .mobileprovision is a CMS
// (PKCS#7) signed blob wrapping an XML plist; rather than verifying the
// signature we locate the embedded XML plist between its <?xml ...> prologue and
// the closing </plist> tag and decode it, then read the "Entitlements"
// subtree. Returns a flattened map of dotted keys to string values. Any failure
// (absent file, no plist, decode error) yields (nil, nil) so a scan never fails
// merely because entitlements could not be read.
func ParseEntitlements(mobileProvisionPath string) (map[string]string, error) {
	if mobileProvisionPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(mobileProvisionPath)
	if err != nil {
		return nil, nil // best-effort: absent/unreadable is not an error
	}

	xmlPlist := extractEmbeddedXMLPlist(data)
	if xmlPlist == nil {
		return nil, nil
	}

	var holder struct {
		Entitlements map[string]interface{} `plist:"Entitlements"`
	}
	if err := decodePlistReader(xmlPlist, &holder); err != nil {
		return nil, nil
	}
	if holder.Entitlements == nil {
		return nil, nil
	}

	flat := map[string]string{}
	flattenPlistMap("", holder.Entitlements, flat)
	return flat, nil
}

// extractEmbeddedXMLPlist finds the XML plist embedded inside a CMS-signed
// .mobileprovision blob by slicing from the "<?xml" prologue through the closing
// "</plist>" tag. Returns nil when no such window exists.
func extractEmbeddedXMLPlist(data []byte) []byte {
	start := bytes.Index(data, []byte("<?xml"))
	if start < 0 {
		return nil
	}
	end := bytes.LastIndex(data, []byte("</plist>"))
	if end < 0 || end <= start {
		return nil
	}
	end += len("</plist>")
	return data[start:end]
}

// EntitlementKeys returns the sorted keys of an entitlements map, used for
// non-sensitive logging (never log the values, which can be team identifiers).
func EntitlementKeys(ent map[string]string) []string {
	keys := make([]string, 0, len(ent))
	for k := range ent {
		keys = append(keys, k)
	}
	return keys
}

// summarizeFrameworks builds a short human string of framework names for logs.
func summarizeFrameworks(fws []FrameworkInfo) string {
	if len(fws) == 0 {
		return "none"
	}
	return fmt.Sprintf("%d (%s...)", len(fws), fws[0].Name)
}
