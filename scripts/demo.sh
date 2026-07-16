#!/usr/bin/env bash
#
# MORF - Mobile Reconnaissance Framework — one-command booth demo.
#
# Offline-safe by design: live verification is OFF (no network calls), and the
# demo target is the bundled iOS fixture so no sample app needs to be sourced.
# The script is idempotent — re-running it reproduces the same output.
#
# Flow:
#   1. morf scan  -> findings summary by precision tier (keep / info)
#   2. morf scan  -> SARIF 2.1.0 (masked, with MASVS ids) at demo-out/demo.sarif
#   3. morf gate  -> clean pass (exit 0) against a freshly-captured baseline
#   4. morf gate  -> new-secret FAIL (exit 4) against an empty baseline
#
# Usage:  bash scripts/demo.sh
#
# Prereqs: `morf` on PATH (cd morf && go build -o morf .) and `rg` (ripgrep).
# Scanning the bundled .ipa needs only ripgrep; scanning an .apk also needs
# java + apktool. See docs/DEMO.md.

set -euo pipefail

# --- Resolve paths relative to the repo root (this script lives in scripts/) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SAMPLE="${MORF_DEMO_ARTIFACT:-${REPO_ROOT}/morf/ios/testdata/fixture.ipa}"
OUT_DIR="${REPO_ROOT}/demo-out"
SARIF_OUT="${OUT_DIR}/demo.sarif"
BASELINE="${OUT_DIR}/demo-baseline.json"
EMPTY_BASELINE="${OUT_DIR}/empty-baseline.json"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
rule() { printf '%s\n' "------------------------------------------------------------"; }

# --- Locate the morf binary (PATH, then a local build in morf/) ---
if command -v morf >/dev/null 2>&1; then
  MORF="morf"
elif [ -x "${REPO_ROOT}/morf/morf" ]; then
  MORF="${REPO_ROOT}/morf/morf"
else
  echo "ERROR: 'morf' binary not found on PATH or at morf/morf." >&2
  echo "Build it first:  (cd '${REPO_ROOT}/morf' && go build -o morf .)" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: ripgrep (rg) is required by the detection core but was not found." >&2
  exit 1
fi

if [ ! -f "${SAMPLE}" ]; then
  echo "ERROR: demo artifact not found: ${SAMPLE}" >&2
  echo "Set MORF_DEMO_ARTIFACT=/path/to/app.(ipa|apk) to use your own sample." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

bold "MORF booth demo"
echo "Binary   : ${MORF}"
echo "Artifact : ${SAMPLE}"
echo "Output   : ${OUT_DIR}"
echo "(verification is OFF — no network calls)"
rule

# --- Step 1: scan, human summary (findings by precision tier) --------------
bold "[1/4] Scan — findings by precision tier"
# --fail-on=none so the summary step never aborts the demo on a policy hit.
"${MORF}" scan "${SAMPLE}" --format=json --fail-on=none > "${OUT_DIR}/demo.json" || true
if command -v jq >/dev/null 2>&1; then
  echo "Findings by tier:"
  jq -r '.data.secrets // [] | group_by(.Tier // .tier // "unknown")
         | map({tier: (.[0].Tier // .[0].tier // "unknown"), count: length})
         | .[] | "  \(.tier): \(.count)"' "${OUT_DIR}/demo.json" 2>/dev/null \
    || echo "  (install jq for a per-tier breakdown; raw JSON at demo-out/demo.json)"
else
  echo "  (install jq for a per-tier breakdown; raw JSON at demo-out/demo.json)"
fi
rule

# --- Step 2: emit SARIF 2.1.0 (masked, MASVS-tagged) -----------------------
bold "[2/4] SARIF 2.1.0 output (masked, MASVS ids)"
"${MORF}" scan "${SAMPLE}" --sarif --out "${SARIF_OUT}" --fail-on=none || true
echo "Wrote: ${SARIF_OUT}"
if command -v jq >/dev/null 2>&1; then
  echo -n "  SARIF version: "; jq -r '.version // "?"' "${SARIF_OUT}" 2>/dev/null || true
  echo -n "  Results:       "; jq -r '[.runs[].results[]?] | length' "${SARIF_OUT}" 2>/dev/null || true
fi
rule

# --- Step 3: gate — clean pass against a captured baseline -----------------
bold "[3/4] Gate — clean pass (exit 0)"
# Snapshot the current findings as the accepted baseline (always exits 0).
"${MORF}" gate "${SAMPLE}" --baseline "${BASELINE}" --update-baseline --fail-on=any
# Re-gate against that baseline: nothing is new, so this passes.
set +e
"${MORF}" gate "${SAMPLE}" --baseline "${BASELINE}" --fail-on=any
PASS_CODE=$?
set -e
echo "gate exit code: ${PASS_CODE} (expected 0 — no new secrets vs baseline)"
rule

# --- Step 4: gate — new-secret FAIL against an empty baseline --------------
bold "[4/4] Gate — new-secret fail (exit 4)"
# An empty baseline means every finding is "new" -> the gate should fail.
printf '{"fingerprints":[],"allowlist":[]}\n' > "${EMPTY_BASELINE}"
set +e
"${MORF}" gate "${SAMPLE}" --baseline "${EMPTY_BASELINE}" --fail-on=any
FAIL_CODE=$?
set -e
echo "gate exit code: ${FAIL_CODE} (expected 4 — every finding is new)"
rule

bold "Demo complete."
echo "Artifacts in ${OUT_DIR}:"
echo "  - demo.json           (raw findings)"
echo "  - demo.sarif          (SARIF 2.1.0, masked, MASVS-tagged)"
echo "  - demo-baseline.json  (accepted fingerprints — clean pass)"
echo "  - empty-baseline.json (empty — forces the new-secret fail)"
echo
echo "To show LIVE verification (needs a real, reachable key + network):"
echo "  ${MORF} scan <artifact> --verify --fail-on=verified"
