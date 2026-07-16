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
	"bytes"
	"fmt"
	"os"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	log "github.com/sirupsen/logrus"
)

// stringMinLen is the minimum length (in bytes) of an extracted C/Swift string
// worth writing to the corpus. Very short fragments are noise for the secret
// scanner and only inflate the corpus.
const stringMinLen = 4

// interestingSectionNames is the set of string-bearing Mach-O section names we
// extract literal strings from. We match by section NAME ONLY (never by index,
// and deliberately NOT by (segment,section) pair): the SAME string-bearing
// section moves between segments across compilers and toolchains — e.g. read-
// only constant data lands in __TEXT.__const/__rodata for some binaries and in
// __DATA_CONST.__rodata/__const for others (notably Go-emitted Mach-O), and
// __cfstring appears under __DATA or __DATA_CONST. A (segment,section) allow-
// list silently misses those, so we key on the section name and let any segment
// match. Covers C strings, read-only constant pools (where most literals live),
// CFStrings, ObjC metadata, and the Swift5 reflection family.
var interestingSectionNames = map[string]bool{
	"__cstring":        true, // C string literals
	"__const":          true, // read-only constant pool (often embedded strings)
	"__rodata":         true, // read-only data (Go and some C/C++ toolchains) — literals live here
	"__oslogstring":    true, // os_log format strings (can embed interpolated secrets)
	"__cfstring":       true, // CFString literal structs (scanned raw / NUL-split)
	"__objc_methname":  true, // ObjC selector/method names
	"__objc_classname": true, // ObjC class names
	"__objc_methtype":  true, // ObjC method type encodings
	"__objc_selrefs":   true, // ObjC selector references
	// The __swift5_* family. __swift5_reflstr holds human-readable reflection
	// strings (field/type names); the others are metadata but can still carry
	// embedded C strings, so we NUL-split them defensively.
	"__swift5_reflstr": true,
	"__swift5_typeref": true,
	"__swift5_fieldmd": true,
	"__swift5_types":   true,
	"__swift5_capture": true,
	"__swift5_builtin": true,
	"__swift5_assocty": true,
	"__swift5_proto":   true,
	"__swift5_protos":  true,
}

// isCStringLiteralSection reports whether a section is flagged S_CSTRING_LITERALS
// in its Mach-O section type bits. This is the authoritative, name-independent
// signal that a section is a C-string pool, so we harvest it even if its name is
// not in interestingSectionNames (defensive catch-all for compiler-specific
// section names).
func isCStringLiteralSection(sec *types.Section) bool {
	if sec == nil {
		return false
	}
	return sec.Flags.IsCstringLiterals()
}

// ArchStrings holds the strings extracted from one architecture slice of a
// Mach-O image, tagged with the arch name so corpus lines carry provenance.
type ArchStrings struct {
	Arch string
	// IsEncrypted records that string extraction was skipped for this slice
	// because a non-zero cryptid (FairPlay) was present. Plists/frameworks are
	// still parsed elsewhere; only string extraction is skipped here.
	IsEncrypted bool
	// Strings maps a "SEG.SECT" section label to the strings found in it.
	Strings map[string][]string
}

// BinaryStrings is the full string-extraction result for a single Mach-O file
// (one entry per architecture slice), plus the aggregate architecture list and
// encryption status used to populate IOSMetadata.
type BinaryStrings struct {
	Path          string
	Architectures []string
	IsEncrypted   bool
	Slices        []ArchStrings
}

// ExtractBinaryStrings opens the Mach-O at path (thin or fat/universal),
// enumerates the interesting sections BY NAME across every architecture slice,
// extracts their literal strings, and records FairPlay cryptid status per slice.
// Encrypted slices (cryptid != 0) are recorded but their string sections are
// skipped, since the section bytes are ciphertext.
func ExtractBinaryStrings(path string) (*BinaryStrings, error) {
	res := &BinaryStrings{Path: path, Architectures: []string{}}

	fat, err := macho.OpenFat(path)
	if err == nil {
		defer fat.Close()
		for i := range fat.Arches {
			arch := fat.Arches[i]
			name := arch.CPU.String()
			res.Architectures = append(res.Architectures, name)
			slice := extractSliceStrings(arch.File, name)
			if slice.IsEncrypted {
				res.IsEncrypted = true
			}
			res.Slices = append(res.Slices, slice)
		}
		return res, nil
	}
	if err != macho.ErrNotFat {
		return nil, fmt.Errorf("open fat Mach-O %q: %w", path, err)
	}

	// Thin binary.
	thin, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open thin Mach-O %q: %w", path, err)
	}
	defer thin.Close()
	name := thin.CPU.String()
	res.Architectures = append(res.Architectures, name)
	slice := extractSliceStrings(thin, name)
	res.IsEncrypted = slice.IsEncrypted
	res.Slices = append(res.Slices, slice)
	return res, nil
}

// extractSliceStrings pulls the strings from a single Mach-O image (one arch).
// If the slice is FairPlay-encrypted it returns early with IsEncrypted set and
// no strings, since the __TEXT bytes are ciphertext.
func extractSliceStrings(f *macho.File, arch string) ArchStrings {
	slice := ArchStrings{Arch: arch, Strings: map[string][]string{}}
	if f == nil {
		return slice
	}

	if machoIsEncrypted(f) {
		slice.IsEncrypted = true
		return slice
	}

	// Prefer go-macho's Swift reflection-string helper for __swift5_reflstr; it
	// walks the VM-address layout correctly. If it fails (some binaries lack the
	// vma converter), we fall back to the raw NUL-split path below.
	swiftReflHandled := false
	if refl, rerr := f.GetSwiftReflectionStrings(); rerr == nil && len(refl) > 0 {
		label := "__TEXT.__swift5_reflstr"
		for _, s := range refl {
			if len(s) >= stringMinLen {
				slice.Strings[label] = append(slice.Strings[label], s)
			}
		}
		swiftReflHandled = true
	}

	// Enumerate sections BY NAME (never by index).
	for _, sec := range f.Sections {
		if sec == nil {
			continue
		}
		// Match by section name (segment-agnostic), OR by the Mach-O section
		// type flag S_CSTRING_LITERALS which definitively marks a C-string pool
		// regardless of its name — a robust catch-all for literals the name set
		// might not enumerate.
		if !interestingSectionNames[sec.Name] && !isCStringLiteralSection(sec) {
			continue
		}
		if swiftReflHandled && sec.Seg == "__TEXT" && sec.Name == "__swift5_reflstr" {
			continue // already captured via the helper.
		}

		data, derr := sec.Data()
		if derr != nil || len(data) == 0 {
			continue
		}
		label := sec.Seg + "." + sec.Name
		for _, s := range splitNulStrings(data) {
			slice.Strings[label] = append(slice.Strings[label], s)
		}
	}

	return slice
}

// splitNulStrings extracts every maximal run of printable-ASCII bytes of at
// least stringMinLen from a byte buffer (the classic strings(1) approach),
// splitting on ANY non-printable byte — not only NUL. This is deliberately
// more aggressive than NUL-splitting: NUL-terminated C strings are captured
// identically (NUL is non-printable), but it ALSO recovers literals that are
// packed without terminators and interleaved with binary data — notably Go's
// __rodata blob (Go strings are length-prefixed, not NUL-terminated) and mixed
// read-only constant pools — where a whole-chunk "mostly printable" test would
// discard the surrounding noise and lose the embedded secret with it.
func splitNulStrings(data []byte) []string {
	var out []string
	start := -1
	for i := 0; i <= len(data); i++ {
		printable := i < len(data) && isPrintableStringByte(data[i])
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= stringMinLen {
				out = append(out, string(data[start:i]))
			}
			start = -1
		}
	}
	return out
}

// isPrintableStringByte reports whether b is a printable ASCII character (or
// tab) suitable for inclusion in an extracted string run.
func isPrintableStringByte(b byte) bool {
	return b == '\t' || (b >= 0x20 && b <= 0x7e)
}

// isMostlyPrintable reports whether every byte of b is printable ASCII or common
// whitespace. Section bytes for metadata families are frequently binary; this
// filter keeps the corpus to genuine text so the ripgrep pass is meaningful.
func isMostlyPrintable(b []byte) bool {
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// WriteCorpus appends every extracted string to the writer, one per line, each
// prefixed with its {arch,section} provenance so a corpus reader (and the
// secret scanner) can attribute a hit back to where it came from. The format is
// stable and greppable:
//
//	[arch=<arch> section=<SEG.SECT>] <string>
//
// Encrypted slices are emitted as a single marker line so the corpus records
// that the slice was skipped rather than silently empty.
func WriteCorpus(w *bufio.Writer, bs *BinaryStrings) error {
	if bs == nil {
		return nil
	}
	for _, sl := range bs.Slices {
		if sl.IsEncrypted {
			if _, err := fmt.Fprintf(w, "[arch=%s section=__ENCRYPTED__] FairPlay cryptid!=0; string extraction skipped\n", sl.Arch); err != nil {
				return err
			}
			continue
		}
		for section, strs := range sl.Strings {
			for _, s := range strs {
				// Guard against embedded newlines corrupting the line-oriented corpus.
				if bytes.ContainsAny([]byte(s), "\n\r") {
					s = sanitizeLine(s)
				}
				if _, err := fmt.Fprintf(w, "[arch=%s section=%s] %s\n", sl.Arch, section, s); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// sanitizeLine replaces CR/LF with spaces so a single extracted string maps to a
// single corpus line.
func sanitizeLine(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '\n' || c == '\r' {
			b[i] = ' '
		}
	}
	return string(b)
}

// AppendBinaryCorpus opens the corpus file for appending and writes the strings
// for a single binary. It is a convenience wrapper for callers that extract one
// binary at a time (the main executable, each framework/dylib).
func AppendBinaryCorpus(corpusPath string, bs *BinaryStrings) error {
	f, err := os.OpenFile(corpusPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open corpus %q: %w", corpusPath, err)
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	if err := WriteCorpus(bw, bs); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush corpus %q: %w", corpusPath, err)
	}
	return nil
}

// logBinaryStrings emits a non-sensitive summary of an extraction result. It
// never logs the extracted strings themselves.
func logBinaryStrings(jobID string, bs *BinaryStrings) {
	if bs == nil {
		return
	}
	var total int
	for _, sl := range bs.Slices {
		for _, strs := range sl.Strings {
			total += len(strs)
		}
	}
	log.WithFields(log.Fields{
		"job_id":        jobID,
		"binary":        bs.Path,
		"architectures": bs.Architectures,
		"encrypted":     bs.IsEncrypted,
		"string_count":  total,
	}).Info("Extracted Mach-O strings")
}
