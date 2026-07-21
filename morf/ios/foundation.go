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

// Package ios holds the iOS (IPA / Mach-O / Info.plist) analysis foundation.
//
// This file is intentionally a thin, well-tested foundation for the later iOS
// pipeline steps: it wires up the two external dependencies this module relies
// on (github.com/blacktop/go-macho for Mach-O parsing and howett.net/plist for
// binary+XML plists) with small, self-contained helpers. Higher-level IPA
// unzip / extraction / persistence lands in subsequent steps.
package ios

import (
	"bytes"
	"fmt"

	"github.com/blacktop/go-macho"
	"howett.net/plist"
)

// MachOInfo is the subset of Mach-O binary attributes the scanner records. It
// is populated by InspectMachO and mirrors the columns on models.IOSMetadata.
type MachOInfo struct {
	// Architectures is the list of CPU architecture names present in the
	// binary (a single entry for a thin binary, several for a fat/universal
	// binary). Names come from go-macho's types.CPU.String().
	Architectures []string
	// IsEncrypted is true when any LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
	// load command reports a non-zero cryptid (FairPlay DRM applied).
	IsEncrypted bool
}

// InspectMachO parses the Mach-O executable at path and returns its
// architectures and FairPlay-encryption status. It transparently handles both
// thin binaries (macho.Open) and fat/universal binaries (macho.OpenFat),
// enumerating every contained architecture rather than assuming a fixed slice
// order or index.
func InspectMachO(path string) (*MachOInfo, error) {
	info := &MachOInfo{Architectures: []string{}}

	// Try fat/universal first. Only ErrNotFat (the file is a valid thin
	// binary, not a universal one) falls through to macho.Open; any other
	// error from OpenFat is a genuine parse failure and is surfaced.
	fat, err := macho.OpenFat(path)
	if err == nil {
		defer fat.Close()
		for i := range fat.Arches {
			arch := fat.Arches[i]
			info.Architectures = append(info.Architectures, arch.CPU.String())
			if machoIsEncrypted(arch.File) {
				info.IsEncrypted = true
			}
		}
		return info, nil
	}
	if err != macho.ErrNotFat {
		return nil, fmt.Errorf("open fat Mach-O %s: %w", path, err)
	}

	// Thin binary.
	thin, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open thin Mach-O %s: %w", path, err)
	}
	defer thin.Close()
	info.Architectures = append(info.Architectures, thin.CPU.String())
	info.IsEncrypted = machoIsEncrypted(thin)
	return info, nil
}

// machoIsEncrypted scans a single Mach-O image's load commands for
// LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 and reports whether any carries a
// non-zero cryptid (FairPlay). It never relies on hardcoded load-command
// indices; it type-switches over the parsed loads.
func machoIsEncrypted(f *macho.File) bool {
	if f == nil {
		return false
	}
	for _, l := range f.Loads {
		switch enc := l.(type) {
		case *macho.EncryptionInfo:
			if enc.CryptID != 0 {
				return true
			}
		case *macho.EncryptionInfo64:
			if enc.CryptID != 0 {
				return true
			}
		}
	}
	return false
}

// InfoPlist is the decoded subset of an IPA's Info.plist the scanner records.
// Decoding goes through howett.net/plist, which auto-detects binary vs XML
// plist encodings, so both bplist00 and XML Info.plist files are handled.
type InfoPlist struct {
	BundleIdentifier string `plist:"CFBundleIdentifier"`
	BundleVersion    string `plist:"CFBundleVersion"`
	// ShortVersion is CFBundleShortVersionString, the human-facing marketing
	// version (e.g. "5.9.0"). For an embedded *.framework this is the value the
	// SBOM records as the component version; it is more meaningful than the
	// build-number CFBundleVersion for supply-chain identification.
	ShortVersion     string   `plist:"CFBundleShortVersionString"`
	ExecutableName   string   `plist:"CFBundleExecutable"`
	MinimumOSVersion string   `plist:"MinimumOSVersion"`
	URLSchemes       []string `plist:"-"`
}

// DecodeInfoPlist decodes an Info.plist (binary or XML) from raw bytes into an
// InfoPlist. URL schemes, which are nested under CFBundleURLTypes ->
// CFBundleURLSchemes, are flattened out into InfoPlist.URLSchemes.
func DecodeInfoPlist(data []byte) (*InfoPlist, error) {
	// Decode the flat, top-level scalar keys directly.
	var out InfoPlist
	if _, err := plist.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode Info.plist scalars: %w", err)
	}

	// Decode the nested CFBundleURLTypes separately and flatten the schemes.
	var urlTypesHolder struct {
		URLTypes []struct {
			Schemes []string `plist:"CFBundleURLSchemes"`
		} `plist:"CFBundleURLTypes"`
	}
	if _, err := plist.Unmarshal(data, &urlTypesHolder); err == nil {
		for _, t := range urlTypesHolder.URLTypes {
			out.URLSchemes = append(out.URLSchemes, t.Schemes...)
		}
	}

	return &out, nil
}

// decodePlistReader is a small helper kept to exercise the reader-based plist
// API (plist.NewDecoder) so future streaming callers have a tested entry point.
func decodePlistReader(data []byte, v interface{}) error {
	dec := plist.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode plist from reader: %w", err)
	}
	return nil
}
