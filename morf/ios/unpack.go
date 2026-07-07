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
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"morf/utils"

	log "github.com/sirupsen/logrus"
)

// UnpackedIPA is the result of unzipping an .ipa and locating the interesting
// artifacts inside its Payload/*.app bundle. Every path is absolute and points
// inside the job workspace iOS directory (jobCtx.GetIOSDir()).
type UnpackedIPA struct {
	// ExtractRoot is the directory the .ipa was unzipped into.
	ExtractRoot string
	// AppBundlePath is the located Payload/<Name>.app directory. The app name is
	// discovered, never hardcoded.
	AppBundlePath string
	// InfoPlistPath is the Info.plist inside the app bundle (may be empty if the
	// bundle has no Info.plist, though a well-formed .ipa always has one).
	InfoPlistPath string
	// MainBinaryPath is the main executable inside the app bundle, resolved by
	// NAME from Info.plist's CFBundleExecutable. Empty if it could not be
	// resolved (e.g. unreadable Info.plist); callers should treat that as a
	// soft error and continue with whatever metadata is available.
	MainBinaryPath string
	// AppExtensions are embedded .appex bundle directories (PlugIns/*.appex),
	// e.g. widgets, share extensions.
	AppExtensions []string
	// Frameworks are embedded *.framework bundle directories (Frameworks/*).
	Frameworks []string
	// Dylibs are embedded *.dylib files found anywhere under the app bundle.
	Dylibs []string
	// MobileProvisionPath is the embedded.mobileprovision path if present, else "".
	MobileProvisionPath string
}

// StartUnpack gates the .ipa on the shared zip-bomb / zip-slip guard
// (utils.CheckAPKSafe — an .ipa is a zip archive), unzips it into the job
// workspace iOS directory, then locates the Payload/*.app bundle and the
// artifacts of interest. The app bundle name is discovered by scanning
// Payload/ for a *.app directory rather than assuming a fixed name, and the
// main binary is resolved BY NAME from Info.plist's CFBundleExecutable.
func StartUnpack(ipaPath string, jobCtx *utils.JobContext) (*UnpackedIPA, error) {
	// An .ipa is a zip: reuse the exact same pre-extraction safety gate the APK
	// path uses (entry count / total size / ratio / zip-slip) BEFORE we write a
	// single byte to disk.
	if err := utils.CheckAPKSafe(ipaPath); err != nil {
		return nil, fmt.Errorf("ipa failed safety check: %w", err)
	}

	extractRoot := jobCtx.GetIOSDir()
	if err := os.MkdirAll(extractRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create ios extract root %q: %w", extractRoot, err)
	}

	if err := unzipTo(ipaPath, extractRoot); err != nil {
		return nil, fmt.Errorf("unzip ipa %q: %w", ipaPath, err)
	}

	out := &UnpackedIPA{ExtractRoot: extractRoot}

	appBundle, err := locateAppBundle(extractRoot)
	if err != nil {
		return nil, err
	}
	out.AppBundlePath = appBundle

	// Info.plist lives at the top level of the .app bundle.
	infoPlist := filepath.Join(appBundle, "Info.plist")
	if fileExists(infoPlist) {
		out.InfoPlistPath = infoPlist
	}

	// Resolve the main binary BY NAME via CFBundleExecutable. A missing or
	// unreadable Info.plist is a soft error: we still return the bundle so the
	// caller can enumerate frameworks/dylibs and parse whatever plists exist.
	if out.InfoPlistPath != "" {
		if data, readErr := os.ReadFile(out.InfoPlistPath); readErr == nil {
			if ip, decErr := DecodeInfoPlist(data); decErr == nil && ip.ExecutableName != "" {
				candidate := filepath.Join(appBundle, ip.ExecutableName)
				if fileExists(candidate) {
					out.MainBinaryPath = candidate
				} else {
					log.WithFields(log.Fields{
						"job_id":     jobCtx.JobID,
						"executable": ip.ExecutableName,
					}).Warn("CFBundleExecutable does not exist in app bundle")
				}
			} else if decErr != nil {
				log.WithFields(log.Fields{
					"job_id": jobCtx.JobID,
					"error":  decErr.Error(),
				}).Warn("Failed to decode Info.plist to resolve main executable")
			}
		}
	}

	// Collect embedded bundles and libraries.
	out.AppExtensions = collectDirsWithSuffix(filepath.Join(appBundle, "PlugIns"), ".appex")
	out.Frameworks = collectDirsWithSuffix(filepath.Join(appBundle, "Frameworks"), ".framework")
	out.Dylibs = collectFilesWithSuffix(appBundle, ".dylib")

	mp := filepath.Join(appBundle, "embedded.mobileprovision")
	if fileExists(mp) {
		out.MobileProvisionPath = mp
	}

	log.WithFields(log.Fields{
		"job_id":       jobCtx.JobID,
		"app_bundle":   filepath.Base(appBundle),
		"main_binary":  filepath.Base(out.MainBinaryPath),
		"extensions":   len(out.AppExtensions),
		"frameworks":   len(out.Frameworks),
		"dylibs":       len(out.Dylibs),
		"provisioning": out.MobileProvisionPath != "",
	}).Info("Unpacked IPA")

	return out, nil
}

// unzipTo extracts every entry of the zip at src into dst. It re-applies the
// zip-slip sanitization from CheckAPKSafe as defence-in-depth (never trust an
// entry name to build an on-disk path) and preserves the directory layout so
// Payload/<App>.app is reconstructed faithfully.
func unzipTo(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	// Clean destination once so filepath.Rel-style containment checks are stable.
	cleanDst := filepath.Clean(dst)

	for _, f := range r.File {
		// Reject absolute or traversal names defensively.
		if filepath.IsAbs(f.Name) || strings.HasPrefix(f.Name, "/") || strings.HasPrefix(f.Name, "\\") {
			return fmt.Errorf("zip entry %q has an absolute path (zip-slip)", f.Name)
		}
		target := filepath.Join(cleanDst, filepath.FromSlash(f.Name))
		// Ensure the joined target stays within cleanDst.
		if target != cleanDst && !strings.HasPrefix(target, cleanDst+string(os.PathSeparator)) {
			return fmt.Errorf("zip entry %q escapes extraction root (zip-slip)", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("mkdir %q: %w", target, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("mkdir parent of %q: %w", target, err)
		}
		if err := writeZipEntry(f, target); err != nil {
			return err
		}
	}
	return nil
}

// writeZipEntry streams a single zip entry to disk. Kept small and separate so
// the reader/file handles are closed promptly per entry rather than deferred to
// the end of the whole archive.
func writeZipEntry(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %q: %w", target, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, rc); err != nil {
		return fmt.Errorf("write %q: %w", target, err)
	}
	return nil
}

// locateAppBundle finds the single Payload/<Name>.app directory inside an
// extracted .ipa. The app name is NOT hardcoded: it is discovered by listing
// Payload/ and taking the first entry ending in ".app". If Payload/ is absent
// (some tooling drops the wrapper) it falls back to a shallow walk for any
// *.app directory under the extraction root.
func locateAppBundle(extractRoot string) (string, error) {
	payload := filepath.Join(extractRoot, "Payload")
	if entries, err := os.ReadDir(payload); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
				return filepath.Join(payload, e.Name()), nil
			}
		}
	}

	// Fallback: shallow scan for any *.app directory (depth-limited walk).
	var found string
	_ = filepath.WalkDir(extractRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if d.IsDir() && strings.HasSuffix(d.Name(), ".app") {
			found = path
			return filepath.SkipDir
		}
		return nil
	})
	if found != "" {
		return found, nil
	}
	return "", fmt.Errorf("no Payload/*.app bundle found under %q", extractRoot)
}

// collectDirsWithSuffix returns absolute paths of immediate child directories of
// dir whose name ends with suffix. A missing dir yields an empty slice.
func collectDirsWithSuffix(dir, suffix string) []string {
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// collectFilesWithSuffix walks the tree rooted at dir and returns absolute paths
// of regular files whose name ends with suffix (used for .dylib discovery, which
// can be nested under Frameworks/*.framework as well as at the bundle root).
func collectFilesWithSuffix(dir, suffix string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
