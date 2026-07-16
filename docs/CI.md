# MORF in CI — reusable recipes

MORF ships reusable CI building blocks so any pipeline can scan a mobile build
artifact (`.apk` / `.ipa`) for secrets, publish the findings as SARIF, and gate
the build on a severity policy — using a single, consistent command contract.

Every recipe follows the same **gate-then-upload** flow, so findings always
reach your security dashboard even when the policy gate fails the build.

---

## Command contract: `morf scan` and `morf gate`

> These subcommands are implemented alongside these recipes. The recipes are
> written against this contract.

### `morf scan <artifact> [flags]`

Scans one artifact, optionally emits SARIF, and returns a **policy exit code**.

| Flag | Meaning | Default |
|------|---------|---------|
| `--sarif` | Emit a SARIF report. | off |
| `--out <path>` | SARIF output path (implies `--sarif`). | — |
| `--format=json\|sarif` | Output format. | `json` |
| `--fail-on=<level>` | Policy level that makes the command exit non-zero: `none \| any \| verified \| keep`. | `verified` |
| `--verify=<bool>` | Live-verify candidate secrets before reporting (sets `MORF_ENABLE_VERIFICATION`). | `true` |

- **Exit `0`** — no findings at or above the `--fail-on` level.
- **Exit `4`** — a policy violation (finding at/above the level). CI gates on this.
- **Exit `1`** — an operational error (bad file, tool missing, etc.).

`--fail-on` levels: `verified` = only secrets confirmed live (VerificationStatus
`active`); `keep` = any precision-kept finding (Tier `keep`); `any` = any
finding; `none` = never fail (report-only). SARIF values are masked.

### `morf gate <artifact> [flags]`

Build-diff gate: scans the artifact and fails on **new** secrets relative to a
committed baseline, keyed on the stable, irreversible `crypto.Fingerprint`
(never the raw value). Use it to fail a build only when it introduces a secret
that wasn't already accepted.

| Flag | Meaning | Default |
|------|---------|---------|
| `--baseline <path>` | JSON baseline of accepted fingerprints/allowlist (missing = first run). | — |
| `--update-baseline` | Snapshot the current findings to the baseline and pass. | off |
| `--fail-on=<level>` | Gate policy: `verified` (new live), `any` (new), `keep`, `none`. | `verified` |
| `--json` | Emit the (masked) gate result as JSON. | off |

### Obtaining the `morf` binary

- **Container image (recommended for CI):** the release pipeline publishes a
  multi-arch image to `ghcr.io/<owner>/<repo>` (see
  `.github/workflows/release.yml`). Pin a released tag.
- **Binary:** GoReleaser publishes signed binaries/archives on each `v*` tag.

---

## The gate-then-upload ordering

All recipes run three steps in this exact order:

1. **Scan** — run `morf scan ... --fail-on=<tier>` and **capture** its exit
   code without aborting the job. (Composite GH Action does this in shell with
   `set +e`; other systems use `|| SCAN_CODE=$?` or `returnStatus`.)
2. **Upload** — publish `morf.sarif` to the platform's security surface,
   best-effort, so it runs regardless of the scan's policy result.
3. **Gate** — honour the captured `morf scan` exit code (4 = policy violation), failing
   the job **last**.

This guarantees findings are always uploaded before a failing gate can stop the
pipeline — the same pattern the repo's `sast` (gosec) job uses in
`.github/workflows/ci.yml`.

---

## GitHub Actions — composite action

Path: `.github/actions/morf-scan/action.yml`

```yaml
jobs:
  morf:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # REQUIRED for the SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/morf-scan
        with:
          artifact: app/build/outputs/apk/release/app-release.apk
          fail-on: verified
          verify: "true"
          # Pin the image that provides `morf` (or put morf on PATH first):
          morf-image: ghcr.io/OWNER/REPO:vX.Y.Z
```

**Inputs:** `artifact` (required), `fail-on` (default `verified`), `verify`
(default `true`), plus `sarif-file`, `category`, `upload-sarif`, `morf-image`.

The calling job **must** grant `security-events: write` (as the repo's `sast`
and `docker` jobs already do) for the SARIF upload to reach the Security tab.

---

## GitLab CI

Path: `ci-recipes/gitlab-ci.morf.yml`

`include` it and set `APK` / pin `MORF_IMAGE`. The job stores `gl-morf.sarif`
as an artifact and feeds it to GitLab's native SAST dashboard via
`artifacts:reports:sast`. Artifacts use `when: always` so the report survives a
failing gate.

## Jenkins

Path: `ci-recipes/Jenkinsfile.morf`

Declarative pipeline on a Docker agent (the MORF image). The scan exit code is
captured with `returnStatus: true`; `post { always { ... } }` archives the SARIF
and publishes it via the Warnings Next Generation plugin's `recordIssues`; a
final `MORF Gate` stage fails the build on violation.

## CircleCI

Path: `ci-recipes/circleci-morf.yml`

Orb-free job on a Docker executor. `store_artifacts` publishes the SARIF; a
final gate step reads the captured scan exit code and fails the job.

---

## Pre-commit hook

Hook definition: `.pre-commit-hooks.yaml` (id: `morf-scan`).
Script: `ci-recipes/pre-commit-morf.sh`.

Consumers reference this repo in their own `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/OWNER/REPO
    rev: vX.Y.Z
    hooks:
      - id: morf-scan
        args: ["--fail-on=verified"]
```

The hook fires only on staged `.apk` / `.ipa` files, scans each one, and blocks
the commit on a policy violation. Set `MORF_IMAGE=ghcr.io/OWNER/REPO:TAG` to run
via a pinned container instead of requiring `morf` on `PATH`; pass `--no-verify`
to skip live secret verification.
