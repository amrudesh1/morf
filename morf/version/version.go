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

// Package version holds build-time version metadata. The values are overridden
// at link time via -ldflags "-X morf/version.Version=... -X morf/version.Commit=...
// -X morf/version.Date=..." (wired in .goreleaser.yaml and the release
// workflow). They keep their dev defaults for plain `go build`.
package version

import "fmt"

var (
	// Version is the semantic version of the build (e.g. "v1.2.3"), or "dev".
	Version = "dev"
	// Commit is the git commit SHA the binary was built from.
	Commit = "none"
	// Date is the RFC3339 build timestamp.
	Date = "unknown"
)

// String returns a single-line human-readable version banner.
func String() string {
	return fmt.Sprintf("morf %s (commit %s, built %s)", Version, Commit, Date)
}
