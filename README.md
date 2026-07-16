<div align="center">

# MORF - Mobile Reconnaissance Framework

<img src="https://github.com/amrudesh1/morf/blob/main/frontend/src/assets/morf.png" width="200" alt="MORF Logo"/>

**Dual APK + IPA artifact secret recon — secrets detected *and* verified — with SARIF 2.1.0 / OWASP MASVS output and a CI build gate.**

[![License](https://img.shields.io/github/license/amrudesh1/morf?style=for-the-badge&logo=opensourceinitiative&logoColor=white&color=0080ff)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/amrudesh1/morf?style=for-the-badge&logo=git&logoColor=white&color=0080ff)](https://github.com/amrudesh1/morf/commits/main)
[![Language](https://img.shields.io/github/languages/top/amrudesh1/morf?style=for-the-badge&color=0080ff)](https://github.com/amrudesh1/morf)
[![BlackHat Arsenal](https://img.shields.io/badge/BlackHat-Arsenal%202026-blue?style=for-the-badge&color=0080ff)](https://www.blackhat.com/)

<p><b>Find Secrets. Verify Them. Gate the Build.</b></p>

</div>

## Table of Contents

- [Overview](#overview)
- [Feature Matrix](#feature-matrix)
- [Quick Start](#quick-start)
- [CLI Usage (`morf scan` / `morf gate`)](#cli-usage-morf-scan--morf-gate)
- [MCP Agent Server (`morf mcp`)](#mcp-agent-server-morf-mcp)
- [SARIF & OWASP MASVS Output](#sarif--owasp-masvs-output)
- [Security Posture](#security-posture)
- [Architecture](#architecture)
- [Common Use Cases](#common-use-cases)
- [What's New in v2](#whats-new-in-v2)
- [Conference Recognition](#conference-recognition)
- [Authors](#authors)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview

**MORF - Mobile Reconnaissance Framework** is an offensive-security toolkit that discovers
hardcoded secrets and reconnaissance signal inside mobile application **artifacts** —
Android `.apk` and iOS `.ipa` — from a single shared detection core. Unlike source-level
SAST or repo secret scanners, MORF works on the shipped binary: it decompiles APKs with
apktool and parses Mach-O executables in pure Go, then runs the same secret patterns and
precision engine over both.

What sets MORF apart from a plain regex scanner:

- **Detected *and* verified.** Candidate secrets can be confirmed live against their
  provider (read-only), so a finding is not just "this looks like a Stripe key" but "this
  key is *active*."
- **Deterministic precision engine.** Entropy + structural signals tier every candidate
  into `drop` / `info` / `keep`, cutting false positives with no network calls and no LLM.
- **CI-native output.** SARIF 2.1.0 for GitHub Code Scanning and every SAST dashboard,
  OWASP MASVS control mapping, and a build-diff **gate** that fails a pipeline only on
  *new* secrets.

MORF runs three ways from one binary: as a scalable **service** (Redis-backed job queue +
worker pool, MySQL, Prometheus/Grafana, React web UI), as a **CLI** for CI, and as an
**MCP server** for LLM agents.

## Feature Matrix

| Capability | What MORF does |
|---|---|
| **Dual-platform artifact recon** | Scans Android `.apk` (apktool decompile → smali + resources) and iOS `.ipa` (unzip + pure-Go Mach-O parse of the binary, incl. Swift/Obj-C/C strings, frameworks, entitlements, URL schemes, native `.so`/Flutter/asset/config content). |
| **Shared detection core with platform scoping** | One YAML-pattern engine (`detect/`) compiled to a combined ripgrep regex. Patterns are scoped `android` / `ios` / `any`, so iOS-only rules never fire on Android and vice-versa. |
| **Deterministic precision engine** | `precision.go` computes Shannon entropy + structure per candidate and assigns a tier (`drop` / `info` / `keep`) and a `[0,1]` score. Conservative: only clear false positives are dropped. |
| **Opt-in live verification** | Read-only provider checks (default OFF). 11 providers — GitHub, GitLab, Slack, Stripe, Google/GCP, Twilio, SendGrid, npm, Cloudflare, Mailgun, DigitalOcean — plus **AWS SigV4 STS `GetCallerIdentity`** pairing. Status: `active` / `inactive` / `unknown` / `unchecked`. |
| **SARIF 2.1.0 output** | `report/sarif.go` emits schema-valid SARIF. Tier → level (`keep`=error, `info`=note). Secret values are masked in the report. |
| **OWASP MASVS mapping** | Findings carry a MASVS control id (`MASVS-STORAGE-1`, `-STORAGE-2`, `-CRYPTO-1`, `-NETWORK-1`) surfaced in SARIF rule `tags` + a `masvsId` property. See [docs/MASVS.md](docs/MASVS.md). |
| **`morf scan` / `morf gate` CLI** | CI-friendly contract with policy exit codes (`0` pass, `4` policy hit, `1` operational error) and `--fail-on=none\|any\|verified\|keep`. Full flag/CI reference in [docs/CI.md](docs/CI.md). |
| **`morf mcp` agent server** | Stdio MCP server exposing `scan_file`, `list_patterns`, `verify_secret`, `explain_finding` — all outputs masked, no DB/Redis/HTTP needed. |
| **Scalable service** | Redis reliable queue (DLQ + reaper), worker pool, normalized MySQL (GORM), API-key auth + rate limiting, Prometheus/Grafana, S3 or local storage, K8s/KEDA manifests. |
| **Web UI (React 19)** | React 19 + Vite + Tailwind frontend: drag-and-drop upload, live scan stepper, findings by tier/platform, `/compare` diff, PDF export. |
| **Runtime pattern management** | `/api/patterns` CRUD + UI — add a detection without a code change. |
| **At-rest secret protection** | Discovered values are stored masked by default; optional AES-256-GCM at rest; stable identity via keyed HMAC **fingerprint** (never plaintext). |

## Quick Start

MORF runs as a Docker Compose stack: **MySQL + Redis + Go backend + React frontend**.

> **Apple Silicon (arm64):** the backend Dockerfile defaults to `amd64`; the emulated
> amd64 binary SIGSEGVs under Rosetta. On Apple Silicon you **must** build native arm64
> using an override that sets `platform: linux/arm64` and `TARGETARCH=arm64`.

```bash
git clone https://github.com/amrudesh1/morf && cd morf

# x86-64 hosts:
docker compose up -d --build

# Apple Silicon (arm64) — with a local override that pins the arch:
docker compose -f docker-compose.yml -f <arm64-override>.yml up -d --build morf-backend frontend
```

Then open the UI and upload an `.apk` or `.ipa`:

- **Frontend:** http://localhost/
- **Backend API:** http://localhost:9092/api
- **Health:** http://localhost:9092/api/health

Configuration lives in `.env` (copy from [`.env.example`](.env.example)); every value has a
local-development fallback baked into `docker-compose.yml`, so `docker compose up` works
without one. Any real deployment MUST override the credentials.

## CLI Usage (`morf scan` / `morf gate`)

The same scan + precision + verify pipeline the worker runs is available as a CLI, built
for CI. [docs/CI.md](docs/CI.md) is the canonical command contract and ships reusable
recipes for GitHub Actions, GitLab, Jenkins, CircleCI, and pre-commit.

```bash
# Scan an artifact, emit SARIF, fail (exit 4) only on a live-verified secret:
morf scan app.apk --sarif --out morf.sarif --fail-on=verified --verify

# Report-only JSON, never fail the build:
morf scan app.ipa --format=json --fail-on=none

# Build-diff gate: fail only on NEW secrets vs a committed baseline of accepted fingerprints
morf gate app.apk --baseline morf-baseline.json --fail-on=verified

# First run / accept the current state as the baseline:
morf gate app.apk --baseline morf-baseline.json --update-baseline
```

**Exit codes:** `0` = nothing at/above the `--fail-on` threshold · `4` = policy violation
(CI gates on this) · `1` = operational error (bad file, tool missing). `--fail-on` levels:
`verified` (only confirmed-live secrets), `keep` (any precision-kept finding), `any` (any
finding), `none` (report-only). All SARIF/JSON values are masked.

## MCP Agent Server (`morf mcp`)

`morf mcp` runs a standalone **stdio MCP server** so an LLM agent can scan and reason about
mobile artifacts. It needs no DB, Redis, or HTTP server — it drives the leaf packages
in-process.

```bash
morf mcp   # speaks MCP over stdin/stdout
```

Tools exposed (every output masked):

- `scan_file` — scan an `.apk`/`.ipa` and return tiered findings.
- `list_patterns` — enumerate the loaded detection patterns.
- `verify_secret` — run the opt-in read-only verification on a candidate.
- `explain_finding` — explain a finding, including its MASVS control.

## SARIF & OWASP MASVS Output

MORF emits **SARIF 2.1.0** (`report/sarif.go`, `EncodeSARIF`) targeting the canonical
schema. The precision tier maps to the SARIF result level — `keep` → `error`, `info` →
`note` — and the report masks every secret value.

Detection patterns carry an OWASP **MASVS** control id that flows into each SARIF rule's
`tags` and a `masvsId` property, and into `explain_finding`. Current coverage is grounded
in the live patterns: **MASVS-STORAGE-1** (hardcoded secrets/keys), **MASVS-STORAGE-2**,
**MASVS-CRYPTO-1** (crypto material), **MASVS-NETWORK-1** (cleartext/endpoint exposure).
See [docs/MASVS.md](docs/MASVS.md) for the mapping and an honest "not yet mapped" list.

## Security Posture

MORF is built to be safe to run against real production artifacts:

- **Verification is default-OFF.** Live provider checks only run with `--verify` or
  `MORF_ENABLE_VERIFICATION=true`, and every check is **read-only** (e.g. AWS STS
  `GetCallerIdentity`, never a mutating call).
- **Masking everywhere.** SARIF, the `/results` API, MCP tool outputs, and logs mask
  secret values. `MaskResultJSON` fails **closed** — an unparseable payload errors rather
  than leaking.
- **No plaintext at rest by default.** Discovered values persist masked; set
  `MORF_SECRET_ENCRYPTION_KEY` to store AES-256-GCM ciphertext instead.
- **Fingerprint-only identity.** Dedup and the build-diff gate key on a stable keyed-HMAC
  `crypto.Fingerprint`, never the raw value — a baseline file is committable and a DB
  exfiltration cannot confirm guessed secrets (set `MORF_FINGERPRINT_SALT` in production).
- **Fail-closed auth.** API-key auth is on by default; scan/pattern/results routes require
  a key even when the toggle is relaxed.

The full strategic assessment lives in [docs/SECURITY_ROADMAP.md](docs/SECURITY_ROADMAP.md).

## Architecture

MORF is a **Go 1.24 backend** with a **React 19 + Vite + Tailwind** frontend. The backend
is a scalable service — Redis reliable queue + worker pool, normalized MySQL (GORM),
API-key auth, Prometheus/Grafana, S3/local storage, and K8s/KEDA manifests — and the same
leaf packages (`detect`, `precision`, `verify`, `report`, `gate`) run in-process for the
CLI and MCP modes.

Scan data flow: `upload → Redis queue → worker → decompile/parse → detect → precision →
verify (opt-in) → persist (protected) → results / SARIF`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component map and diagrams, and
[docs/DEMO.md](docs/DEMO.md) for the booth demo.

## Common Use Cases

| Use Case | Description |
|---|---|
| **Pre-release artifact audits** | Scan the exact `.apk`/`.ipa` you ship, not the source tree. |
| **CI/CD secret gate** | `morf gate` fails a build only on new secrets vs an accepted baseline. |
| **GitHub Code Scanning** | Upload MORF SARIF to the Security tab; findings carry MASVS ids. |
| **Agent-driven triage** | Point an LLM agent at `morf mcp` to scan and explain findings. |
| **Competitive / research recon** | Understand secret hygiene and structure of any shipped app. |

## What's New in v2

- Dual **APK + IPA** artifact recon from a shared, platform-scoped detection core.
- Deterministic **precision engine** (entropy/structure tiering) — noise cut from
  hundreds of raw hits to a handful of clean findings.
- Opt-in **live verification** (11 providers + AWS STS).
- **SARIF 2.1.0** + OWASP **MASVS** output.
- `morf scan` / `morf gate` **CLI** with policy exit codes + reusable CI recipes.
- `morf mcp` **agent server**.
- **React 19** web UI, PDF export, `/compare` scan diffing.
- Scalable service: Redis queue + worker pool, normalized MySQL, Prometheus/Grafana,
  K8s/KEDA.

## Conference Recognition

**BlackHat Arsenal 2026** — MORF returns to Arsenal with its v2 posture: dual APK+IPA
binary recon, *verified* (not merely detected) secrets, and SARIF/MASVS CI output.

<details>
<summary>Previous appearances</summary>

- **BlackHat Asia 2023** — Arsenal debut ([link](https://www.blackhat.com/asia-23/arsenal/schedule/#morf---mobile-reconnaissance-framework-31292))
- **BlackHat US 2023** — Arsenal ([link](https://www.blackhat.com/us-23/arsenal/schedule/index.html#morf---mobile-reconnaissance-framework-32370))
- **BlackHat Europe 2024** — Arsenal ([link](https://www.blackhat.com/eu-24/arsenal/schedule/index.html#morf---mobile-reconnaissance-framework-42172))
- **BlackHat Asia 2025** — Arsenal ([link](https://www.blackhat.com/asia-25/arsenal/schedule/#morf---mobile-reconnaissance-framework-43910))

</details>

## Authors

<div align="center">

| <img src="https://github.com/amrudesh1.png" width="100" height="100" style="border-radius:50%"><br>[**@amrudesh1**](https://github.com/amrudesh1) | <img src="https://github.com/abhi-r3v0.png" width="100" height="100" style="border-radius:50%"><br>[**@abhi-r3v0**](https://github.com/abhi-r3v0) | <img src="https://github.com/himanshudas.png" width="100" height="100" style="border-radius:50%"><br>[**@himanshudas**](https://github.com/himanshudas) |
|:---:|:---:|:---:|

</div>

## License

MORF is released under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [**Secrets Patterns Database**](https://github.com/mazen160/secrets-patterns-db) — a curated source of secret detection patterns.
- [**go-macho**](https://github.com/blacktop/go-macho) — pure-Go Mach-O parsing behind the iOS module.
- **Open Source Security Community** — for inspiration, feedback, and support.

---

<div align="center">
  <a href="#morf---mobile-reconnaissance-framework">
    <img src="https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue?style=for-the-badge" alt="Back to top" />
  </a>
</div>
