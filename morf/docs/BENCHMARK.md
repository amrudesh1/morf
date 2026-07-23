# MORF Detection Benchmark

Precision / recall / F1 report for the MORF secret-detection core, measured
against a fully-labeled, hermetic corpus.

Reproduce these numbers at any time:

```
cd morf/
go run . benchmark          # human-readable table
go run . benchmark --json   # machine-readable JSON
```

The only external dependency is `rg` (ripgrep); no apktool, JVM, device,
database, Redis, or network is needed.

---

## Results (as of 2026-07-23)

### Per-platform table

```
MORF detection precision/recall benchmark (apktool-free, hermetic)
Before = raw findings; After = post detect.ApplyPrecision

platform      | stage  |     P     R    F1 |    TP    FP    FN |
----------------------------------------------------------------
android       | before |  0.90  1.00  0.95 |     9     1     0 |
              | after  |  1.00  1.00  1.00 |     9     0     0 | FP drop=1, raw=10 kept=9, tiers={info:1, keep:8}
ios           | before |  0.57  1.00  0.73 |     4     3     0 |
              | after  |  1.00  1.00  1.00 |     4     0     0 | FP drop=3, raw=7  kept=4, tiers={info:3, keep:1}
ipa-container | before |  0.75  1.00  0.86 |     3     1     0 |
              | after  |  1.00  1.00  1.00 |     3     0     0 | FP drop=1, raw=4  kept=3, tiers={keep:3}

TOTAL after-precision: P=1.00 R=1.00 F1=1.00 (TP=16 FP=0 FN=0), total FP drop=5
```

### Headline numbers (after `ApplyPrecision`)

| Platform      | Precision | Recall | F1   | FP drop |
|---------------|-----------|--------|------|---------|
| android       | 1.00      | 1.00   | 1.00 | 1       |
| ios           | 1.00      | 1.00   | 1.00 | 3       |
| ipa-container | 1.00      | 1.00   | 1.00 | 1       |
| **TOTAL**     | **1.00**  | **1.00** | **1.00** | **5** |

---

## Methodology

### Corpus

The benchmark ships a small, fully-labeled corpus embedded in
`benchmark/corpus/` via Go's `go:embed`. It is entirely synthetic — no
real-app binaries, no licensed secrets, no extracted store data — and consists
of:

**Android loose-file tree** (`corpus/android/`):

| File | Planted secrets | Decoys |
|------|----------------|--------|
| `smali/com/app/Config.smali` | AWS key, Stripe key, GitHub PAT | placeholder vars, git SHAs |
| `res/values/strings.xml` | Google API key, Slack token, GCP OAuth client-id (info tier) | UUID strings |
| `unknown/sendgrid.properties` | SendGrid API key | — |
| `assets/flutter_assets/kernel_blob.bin` | AWS key (binary, NUL-padded) | base64 blob |
| `lib/arm64-v8a/libsecret.so` | Google API key (binary, NUL-padded) | — |
| `unknown/keystore.pem` | RSA private-key header (expect=false: body-less) | — |

**iOS loose-file tree** (`corpus/ios/Payload/App.app/`):

| File | Planted secrets | Decoys |
|------|----------------|--------|
| `Info.plist` | JWT (keep), Firebase URL (info), GCP reversed-client-id (info) | — |
| `App.entitlements` | Keychain access group (info tier) | — |
| `config.json` | — | Public-cert JWT (expect=false), benign keychain group (expect=false) |
| `Frameworks/AppCore.bin` | — | Body-less private-key marker (expect=false) |

**IPA archive container** (`corpus/ipa/fixture.ipa`):

A real `.ipa` archive (zip file with `Payload/BenchApp.app/` layout) containing:

| File | Planted secrets | Decoys |
|------|----------------|--------|
| `Info.plist` | AWS key (`AKIA_MASKED_EXAMPLE1`), Stripe key | — |
| `libBench.bin` | AWS key (`AKIA_MASKED_EXAMPLE2`, binary, NUL-padded) | — |
| `config.json` | — | Public-cert JWT (expect=false) |

The `ipa-container` case exercises the full container path: the harness unzips
`fixture.ipa` via Go's `archive/zip` (mirroring `ios.StartUnpack`) into a temp
directory before passing the extracted `Payload/` tree to the detection core.
This is the only ARCHIVE CONTAINER case in the benchmark; Android stays as
loose files because its container path requires apktool (a JVM tool), which
would break hermeticity.

### Detection pipeline

For each platform the harness runs two passes:

1. **Text pass** — `detect.ScanCorpus(ctx, id, roots, platform)`: ripgrep
   with the curated pattern set over the whole tree (normal text mode).
2. **Binary --text pass** — `detect.ScanCorpusText(ctx, id, roots, platform, excludes)`:
   ripgrep with `-a/--text -o/--only-matching` so NUL-laden binary artifacts
   (`.so`, `.bin`, `kernel_blob.bin`) are searched. The excludes (`!**/smali*`,
   `!**/res/**`, `!**/original/**`, `!**/unknown/**`) prevent double-counting
   paths already covered by the text pass.

Findings from both passes are unioned and deduped by
`detect.SanitizeSecrets((SecretType, SecretString) key)`, then the raw result
is scored (the "Before" metrics). `detect.ApplyPrecision` is applied and the
filtered result is scored again (the "After" metrics). The precision engine
eliminates body-less private-key headers, public-cert JWTs, and benign
keychain groups that the raw regex pass surfaces.

### Pattern set

The benchmark uses a deliberately small, curated subset of the production
pattern files (embedded in `benchmark/benchpatterns/`):

- `high-confidence.yml` — cross-platform: AWS, Google API, Stripe, GitHub PAT,
  Slack, SendGrid, GCP OAuth, RSA private-key header.
- `ios-high-confidence.yml` — iOS-only (platform scoping exercised by the `ios-`
  filename prefix): JWT, Private Key Block, Firebase URL, GCP reversed client-id,
  iOS Keychain Access Group.

### Scoring

Each finding is matched to a ground-truth label by `(SecretType, fileBasename)`.
A finding that matches an `expect=true` label is a true positive; one that
matches an `expect=false` label OR matches no label at all is a false positive.
An `expect=true` label with no matching finding is a false negative. Derived
metrics:

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * P * R / (P + R)
```

---

## Caveats (read before citing these numbers)

1. **Synthetic corpus, not store-app data.** All secrets are fake, fabricated
   keys (e.g. `AKIA_MASKED_EXAMPLE1`, `sk_live_MASKED_BENCH`) that
   match the regex syntax of real credentials but are not tied to any real
   account. Precision and recall on real app binaries (with real obfuscated code,
   minified JS bundles, native libraries, and random data that happens to match
   patterns) will differ — typically lower precision pre-ApplyPrecision.

2. **Small corpus, small denominator.** Each platform has fewer than 15 ground-
   truth entries. Headline numbers (P=1.00, R=1.00) sound impressive but are
   derived from small denominators; one FN would drop recall to ~0.93 on the
   android platform. The purpose of the benchmark is regression detection
   (detecting if a code change degrades detection), not absolute benchmarking
   against real-world apps.

3. **No APK container path (apktool-free by design).** The Android case scans
   a pre-decompiled loose-file tree rather than a real `.apk`. The production
   Android pipeline adds an apktool decompilation step before running the same
   `detect.ScanCorpus`; the benchmark intentionally omits apktool to remain
   hermetic and fast (no JVM dependency). The iOS container path IS exercised
   via the `ipa-container` case (archive/zip extraction is pure-Go).

4. **Curated pattern subset.** The benchmark uses a small hand-curated pattern
   subset (13 patterns), not the full production pattern set. Numbers derived
   from the full pattern set may differ due to pattern interactions or false-
   positive rate differences in the breadth/cloud-CI/git-leaks pattern files.

5. **No verification pass.** `MORF_ENABLE_VERIFICATION` is off during the
   benchmark (the harness never sets it). The benchmark measures the detection +
   precision layer only, not the optional verification layer.

6. **Reproducible.** The corpus is fixed and embedded; the harness extracts it
   to a temp dir outside any git repo (so ripgrep's gitignore handling does not
   hide binary artifacts), sets `MORF_PATTERNS_DIR` to the extracted curated
   patterns, runs the scan, then cleans up. There is no randomness, no network,
   no database, and no apktool, so running `morf benchmark` twice produces
   identical numbers.
