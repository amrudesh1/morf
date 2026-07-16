#!/usr/bin/env bash
#
# validate_patterns.sh
#
# Extracts every `regex:` value from morf/patterns/*.yml and asserts that each
# one compiles under ripgrep (rg) -- the exact engine detect.go runs. detect.go
# compiles ALL enabled regexes into ONE combined alternation and also feeds them
# to `rg --file`; a single regex that rg rejects breaks the entire scan. This
# script is the pre-ship guard.
#
# It also builds the wrapped combined union `(p0)|(p1)|...` of every enabled
# regex and compiles THAT under rg, because that is what actually runs at scan
# time and what one bad escape silently breaks.
#
# rg exit codes: 0 = match, 1 = no match (both mean the regex COMPILED);
# 2 (or higher) = the regex failed to compile / other error.
#
# Exits 0 only if every regex and the combined union compile. Non-zero on any
# failure.

set -u

# Resolve the patterns dir relative to this script (scripts/ is a sibling of
# patterns/ under morf/), so the script works from any CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERNS_DIR="$(cd "${SCRIPT_DIR}/../patterns" && pwd)"

if ! command -v rg >/dev/null 2>&1; then
  echo "FATAL: ripgrep (rg) not found on PATH; cannot validate patterns." >&2
  exit 3
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "FATAL: python3 not found on PATH; needed to parse YAML pattern files." >&2
  exit 3
fi

# Extract regexes with a proper YAML parser so escapes are decoded exactly as
# Go's yaml.Unmarshal would decode them (detect.go uses gopkg.in/yaml). We emit
# one NUL-delimited record per regex: "<file>\t<name>\t<enabled>\t<regex>".
# Prefer PyYAML; fall back to a minimal hand parser only if PyYAML is absent.
extract() {
  python3 - "$PATTERNS_DIR" <<'PY'
import glob, os, sys

patterns_dir = sys.argv[1]
files = sorted(glob.glob(os.path.join(patterns_dir, "*.yml")) +
               glob.glob(os.path.join(patterns_dir, "*.yaml")))

try:
    import yaml
    have_yaml = True
except Exception:
    have_yaml = False

def emit(fname, name, enabled, regex):
    if regex is None:
        return
    rec = "\t".join([
        os.path.basename(fname),
        str(name),
        "true" if enabled else "false",
        regex,
    ])
    sys.stdout.write(rec + "\0")

count = 0
for f in files:
    if have_yaml:
        with open(f, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not doc or "patterns" not in doc:
            continue
        for item in doc["patterns"]:
            p = item.get("pattern", item) if isinstance(item, dict) else None
            if not isinstance(p, dict):
                continue
            regex = p.get("regex")
            if regex is None:
                continue
            enabled = p.get("enabled", True)
            emit(f, p.get("name", "?"), enabled, regex)
            count += 1
    else:
        # Minimal fallback: this does NOT decode YAML escapes and is only a
        # last resort. Warn loudly.
        sys.stderr.write("WARNING: PyYAML unavailable; escape decoding may be inexact.\n")
        with open(f, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if not s.startswith("regex:"):
                    continue
                val = s[len("regex:"):].strip()
                if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                    q = val[0]
                    val = val[1:-1]
                    if q == '"':
                        val = val.encode().decode("unicode_escape")
                emit(f, "?", True, val)
                count += 1

if count == 0:
    sys.stderr.write("FATAL: no regex patterns found in %s\n" % patterns_dir)
    sys.exit(4)
PY
}

# Command substitution strips NUL bytes, so write the NUL-delimited records to a
# temp file and read from there.
RECORDS_FILE="$(mktemp "${TMPDIR:-/tmp}/morf_patterns.XXXXXX")"
trap 'rm -f "$RECORDS_FILE"' EXIT
extract > "$RECORDS_FILE"
extract_status=$?
if [ $extract_status -ne 0 ]; then
  echo "FATAL: failed to extract patterns (python exit $extract_status)." >&2
  exit $extract_status
fi

total=0
failed=0
enabled_regexes=()

# Iterate NUL-delimited records.
while IFS= read -r -d '' rec; do
  file="${rec%%$'\t'*}"
  rest="${rec#*$'\t'}"
  name="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  enabled="${rest%%$'\t'*}"
  regex="${rest#*$'\t'}"

  total=$((total + 1))

  # Compile-check the single regex under rg (matching detect.go: --multiline,
  # default engine, no -P/--pcre2). 0/1 = compiled OK; >=2 = compile error.
  printf 'x\n' | rg --no-config --multiline -e "$regex" >/dev/null 2>/tmp/rgerr.$$
  rc=$?
  if [ "$rc" -ge 2 ]; then
    failed=$((failed + 1))
    echo "FAIL [$file] \"$name\": regex does not compile under rg (exit $rc)" >&2
    echo "      regex: $regex" >&2
    sed 's/^/      rg: /' /tmp/rgerr.$$ >&2
  fi
  rm -f /tmp/rgerr.$$

  if [ "$enabled" = "true" ]; then
    enabled_regexes+=("$regex")
  fi
done < "$RECORDS_FILE"

# Build and compile the wrapped combined union of every ENABLED regex -- this is
# what detect.go's BuildCombinedRegex feeds to RE2, and structurally what one
# bad pattern breaks. Wrap each in its own group and join with `|`.
combined=""
for r in ${enabled_regexes[@]+"${enabled_regexes[@]}"}; do
  if [ -z "$combined" ]; then
    combined="($r)"
  else
    combined="$combined|($r)"
  fi
done

combined_ok=1
if [ -n "$combined" ]; then
  printf 'x\n' | rg --no-config --multiline -e "$combined" >/dev/null 2>/tmp/rgcomb.$$
  crc=$?
  if [ "$crc" -ge 2 ]; then
    combined_ok=0
    echo "FAIL: combined enabled-regex union does not compile under rg (exit $crc)" >&2
    sed 's/^/      rg: /' /tmp/rgcomb.$$ >&2
  fi
  rm -f /tmp/rgcomb.$$
fi

echo "---------------------------------------------------------------"
echo "patterns validated: $total   individual failures: $failed   enabled in union: ${#enabled_regexes[@]}"
if [ "$failed" -eq 0 ] && [ "$combined_ok" -eq 1 ]; then
  echo "OK: all regexes compile under rg AND the combined enabled union compiles."
  exit 0
else
  echo "FAILED: at least one regex or the combined union did not compile." >&2
  exit 1
fi
