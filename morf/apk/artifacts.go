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

package apk

import (
	"morf/utils"
)

// androidBinaryRoots returns the extra search roots that require a binary-safe
// (ripgrep --text) pass over the apktool "-r" output tree (GetSourceDir):
// native libraries (lib/**/*.so), bundled assets (assets/** — Flutter
// flutter_assets/ kernel blobs and React-Native index.android.bundle), the
// apktool "unknown/" bucket (where google-services.json and other unrecognized
// config JSON land), and the tree root itself (which carries resources.arsc and
// any top-level google-services.json).
//
// The root is included so resources.arsc and top-level config are covered by a
// single dir pass; androidBinaryExcludes keeps that root pass from re-scanning
// the smali/res/original trees already covered by the text pass. Existence
// filtering is deliberately deferred to detect.ScanCorpusText (it stat-filters
// roots to existing directories), so this helper stays a pure path computation
// that is unit-testable without an apktool run.
func androidBinaryRoots(jobCtx *utils.JobContext) []string {
	src := jobCtx.GetSourceDir()
	return []string{src}
}

// androidBinaryExcludes are the extra ripgrep "-g","!glob" pairs for the
// binary-safe pass. They exclude the trees already scanned (as text) by the
// primary ScanCorpus pass so the --text pass does not re-scan smali sources,
// decoded resources or apktool's "original/" copies in binary mode (which would
// double the work and duplicate smali findings). What remains under the source
// root for the --text pass: lib/**/*.so, assets/**, unknown/**, resources.arsc
// and any top-level google-services.json.
func androidBinaryExcludes() []string {
	return []string{
		"-g", "!**/smali*/**",
		"-g", "!**/res/**",
		"-g", "!**/original/**",
	}
}
