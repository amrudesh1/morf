#!/usr/bin/env bash
# =============================================================================
# MORF pre-commit hook script.
#
# Invoked by pre-commit (see .pre-commit-hooks.yaml, id: morf-scan) with the
# list of staged .apk/.ipa files appended as positional arguments.
#
# For each artifact it runs the scan-then-gate contract:
#   morf scan <artifact> --sarif --out <artifact>.sarif --fail-on=<level>
# and exits non-zero on the first policy violation so the commit is blocked.
#
# Configuration (via `args:` in .pre-commit-config.yaml, or env):
#   --fail-on=<level>   minimum tier that blocks the commit (default: verified)
#   --no-verify         disable live secret verification (faster, less precise)
#
# Requirements: `morf` on PATH. Set MORF_IMAGE=ghcr.io/OWNER/REPO:TAG to run
# via a pinned container image instead.
# =============================================================================
set -euo pipefail

FAIL_ON="verified"
VERIFY="true"
FILES=()

# ---- parse args: flags for us, everything else is a filename ---------------
for arg in "$@"; do
  case "$arg" in
    --fail-on=*)  FAIL_ON="${arg#*=}" ;;
    --no-verify)  VERIFY="false" ;;
    --verify=*)   VERIFY="${arg#*=}" ;;
    -*)           echo "morf-scan: unknown flag '$arg'" >&2; exit 2 ;;
    *)            FILES+=("$arg") ;;
  esac
done

if [ "${#FILES[@]}" -eq 0 ]; then
  # No staged artifacts matched — nothing to do.
  exit 0
fi

# ---- resolve how to invoke morf --------------------------------------------
if [ -n "${MORF_IMAGE:-}" ]; then
  run_morf() { docker run --rm -v "${PWD}:/work" -w /work "${MORF_IMAGE}" morf "$@"; }
else
  if ! command -v morf >/dev/null 2>&1; then
    echo "morf-scan: 'morf' not found on PATH. Install it, or set MORF_IMAGE=ghcr.io/OWNER/REPO:TAG." >&2
    exit 127
  fi
  run_morf() { morf "$@"; }
fi

# ---- scan + gate each staged artifact --------------------------------------
status=0
for f in "${FILES[@]}"; do
  sarif="${f}.morf.sarif"
  echo "MORF scanning: ${f} (fail-on=${FAIL_ON}, verify=${VERIFY})"
  if ! run_morf scan "$f" --sarif --out "$sarif" --fail-on="${FAIL_ON}" --verify="${VERIFY}"; then
    echo "MORF: policy violation in ${f} (>= ${FAIL_ON}). Commit blocked." >&2
    status=1
  fi
done

exit "$status"
