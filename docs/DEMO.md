# MORF Booth Demo — BlackHat Arsenal 2026

A tight, repeatable demo of what makes MORF different: **dual APK+IPA artifact recon**,
**detected *and* verified** secrets, a **deterministic precision engine**, **SARIF/MASVS**
output, and a **build gate**.

Two ways to run it:

- **Fast path (offline-safe):** [`scripts/demo.sh`](../scripts/demo.sh) runs `morf scan`
  and `morf gate` in-process against the bundled iOS fixture — no Docker, no network, no
  sample app to source. This is the reliable booth default.
- **Full path (UI):** `docker compose up` and drive the React web UI for a visual demo.

## Prerequisites

- The `morf` binary on `PATH` (`cd morf && go build -o morf .`), and `rg` (ripgrep)
  installed — the detection core shells out to ripgrep.
  - Scanning the bundled **`.ipa`** needs only ripgrep. Scanning an **`.apk`** additionally
    needs `java` + `apktool` for decompilation.
- For the UI path: Docker. On **Apple Silicon** build arm64 (see the README quickstart) —
  the default amd64 image crashes under emulation.

## One-command demo (offline-safe)

```bash
bash scripts/demo.sh
```

What it does, in order:

1. **Scan** the bundled fixture (`morf/ios/testdata/fixture.ipa`) and print a findings
   summary **by precision tier** (`keep` / `info`), showing the noise reduction.
2. **Emit SARIF** to `demo-out/demo.sarif` (SARIF 2.1.0, masked values, MASVS ids) — open
   it or upload it to a Code Scanning dashboard.
3. **Gate — clean pass:** create a baseline from the current scan, then re-gate against it.
   No new secrets → **exit 0**.
4. **Gate — new-secret fail:** gate an empty baseline so every finding is "new" →
   **exit 4**. This is the CI story: a build that introduces a secret is failed.

The script is idempotent and **offline-safe**: verification is OFF by default, so it makes
no network calls.

## The 5-minute booth script

1. **The hook (30s).** "MORF scans the *shipped binary* — Android APK and iOS IPA — not
   your source. And it doesn't just say a string *looks* like a secret; it can confirm the
   key is *live*."
2. **Dual platform (45s).** Show that the same engine handles APK and IPA. For iOS, MORF
   parses the Mach-O in pure Go (Swift/Obj-C/C strings, frameworks, entitlements, URL
   schemes) — run the script's scan step on `fixture.ipa`.
3. **Precision (60s).** Point at the tier summary. "A naive regex scan on a real app
   produced hundreds of hits; the precision engine — entropy + structure, deterministic, no
   LLM — tiers them into `keep` / `info` / `drop`. You see the handful that matter."
4. **Detected vs verified (60s).** Explain verification is opt-in and **read-only** (e.g.
   AWS STS `GetCallerIdentity`). *If* you have a disposable live key and network, run
   `morf scan <artifact> --verify` and show a finding flip to `active`. Otherwise say so
   plainly — the offline demo runs `unchecked`.
5. **SARIF + MASVS (45s).** Open `demo-out/demo.sarif`: masked values, `keep`→error, and a
   `masvsId` on each rule (e.g. `MASVS-STORAGE-1`).
6. **The gate (60s).** Show the clean pass, then the new-secret fail (exit 4). "This is the
   CI gate — it fails a build only on secrets that weren't already accepted in the
   committed baseline, and the baseline holds only opaque fingerprints, no plaintext."

## Honest caveats (say these out loud)

- **Live verification needs a real, reachable key.** The offline demo shows `unchecked`.
  Only demo `--verify` with a disposable credential you control and network access.
- **A meaningful APK/IPA demo needs a sample app.** The bundled `fixture.ipa` is a smoke-
  test fixture; for a richer walk-through bring a decrypted `.ipa` or a debug `.apk`.
- **FairPlay-encrypted (App Store) iOS binaries** are detected via `cryptid` and flagged —
  supply a decrypted build for full binary coverage.
- **APK scanning needs java + apktool**; the offline script uses the `.ipa` fixture so it
  runs without them.

## Related docs

- CLI / CI contract: [CI.md](CI.md)
- Architecture + data flow: [ARCHITECTURE.md](ARCHITECTURE.md)
- MASVS mapping: [MASVS.md](MASVS.md)
- Security posture: [SECURITY_ROADMAP.md](SECURITY_ROADMAP.md)
