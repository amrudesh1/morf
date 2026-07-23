#!/usr/bin/env bash
#
# Copyright [2023] [Amrudesh Balakrishnan]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# gen_fixture.sh
# --------------
# Regenerates the license-clean iOS smoke-test fixtures committed under
# morf/ios/testdata/:
#
#   * Fixture        - a real arm64 Mach-O binary built from ./fixturesrc.
#   * fixture.ipa    - a synthetic .ipa (a plain zip) whose Payload tree
#                      wraps the binary plus a minimal XML Info.plist.
#
# The fixture deliberately contains two FAKE secret strings so the MORF
# scanner has deterministic hits:
#
#   AKIAIOSFODNN7EXAMPLE                  (AWS API Key pattern, AWS's example key)
#   sk_live_…(24-char fabricated body)    (Stripe API Key pattern, fabricated)
#
# Nothing here is a real credential.
#
# Usage:
#   ./gen_fixture.sh
#
# Requirements:
#   * Go toolchain (any host OS; the build cross-targets darwin/arm64).
#   * zip (present on macOS and most Linux distros).
#
# The script is deterministic in layout; re-running it overwrites Fixture and
# fixture.ipa in place. Run it from anywhere - it cd's to its own directory.

set -euo pipefail

# Resolve the directory this script lives in (morf/ios/testdata).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

BIN_NAME="Fixture"
APP_NAME="Fixture.app"
IPA_NAME="fixture.ipa"

echo "[gen_fixture] Building arm64 Mach-O from ./fixturesrc ..."
# Cross-build for iOS's CPU/OS family. This produces a genuine Mach-O
# (Go emits Mach-O for GOOS=darwin), suitable for go-macho parsing tests.
# CGO is disabled so the build is hermetic and reproducible across hosts.
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o "$BIN_NAME" ./fixturesrc

echo "[gen_fixture] Verifying Mach-O magic ..."
# Mach-O arm64 (64-bit little-endian) magic is 0xCFFAEDFE on disk (feedfacf LE).
MAGIC="$(od -An -tx1 -N4 "$BIN_NAME" | tr -d ' \n')"
echo "[gen_fixture]   first 4 bytes: $MAGIC (expect cffaedfe for thin arm64 Mach-O)"

echo "[gen_fixture] Assembling synthetic IPA layout ..."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/Payload/$APP_NAME"
cp "$BIN_NAME" "$WORK/Payload/$APP_NAME/$BIN_NAME"

# Minimal, valid XML Info.plist. Mirrors the fields a real iOS app ships and
# that MORF's iOS metadata path is documented to read (executable, bundle id,
# version, min OS, and a URL scheme for deeplink inspection).
cat > "$WORK/Payload/$APP_NAME/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>Fixture</string>
	<key>CFBundleIdentifier</key>
	<string>com.morf.fixture</string>
	<key>CFBundleName</key>
	<string>Fixture</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>MinimumOSVersion</key>
	<string>15.0</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLName</key>
			<string>com.morf.fixture.deeplink</string>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>morffixture</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
PLIST

echo "[gen_fixture] Zipping $IPA_NAME ..."
rm -f "$SCRIPT_DIR/$IPA_NAME"
# -X strips extra file attributes for a cleaner, more reproducible archive.
( cd "$WORK" && zip -q -r -X "$SCRIPT_DIR/$IPA_NAME" Payload )

echo "[gen_fixture] Done."
echo "[gen_fixture]   $SCRIPT_DIR/$BIN_NAME"
echo "[gen_fixture]   $SCRIPT_DIR/$IPA_NAME"
