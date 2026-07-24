#!/usr/bin/env bash
# Fetch apktool.jar for LOCAL (non-Docker) APK scanning.
# apktool.jar is not committed (downloaded on demand with SHA verification);
# apkanalyzer.jar ships in the repo. The Docker image downloads apktool itself,
# so you only need this for running `morf` directly on your machine.
set -euo pipefail
VER="2.9.3"
SHA="7956eb04194300ce0d0a84ad18771eebc94b89fb8d1ddcce8ea4c056818646f4"
DEST="$(cd "$(dirname "$0")/.." && pwd)/morf/tools"
mkdir -p "$DEST"
echo "Downloading apktool ${VER} -> ${DEST}/apktool.jar"
curl -fL -o "$DEST/apktool.jar" \
  "https://github.com/iBotPeaches/Apktool/releases/download/v${VER}/apktool_${VER}.jar"
echo "${SHA}  ${DEST}/apktool.jar" | sha256sum -c -
echo "apktool.jar ready."
