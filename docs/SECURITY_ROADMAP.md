# MORF — Security-Engineering Assessment & Forward Roadmap

*Author's lens: a product-security / mobile-security engineer who has lived through the rise of
Mobile AppSec (MASVS/MASTG), the secret-scanning wars (TruffleHog / GitGuardian / GitHub), and
the shift-left/CI era. This document assesses where MORF stands, proves it against a real
head-to-head, and lays out a prioritized, evidence-backed roadmap for its future.*

Status: assessment + roadmap (no production code changed by this document). Evidence comes from
(a) a **live** iOS scan comparison run on 2026-07-08 and (b) a cited deep-research pass
(25 claims adversarially verified, 0 refuted). Uncertain areas are flagged explicitly.

---

## 1. Executive summary

MORF is a queue-backed, horizontally-scalable **mobile secret-scanning & reconnaissance**
service that now scans **both Android APKs and iOS IPAs** from a single shared detection core.
That dual-platform, binary-level recon posture — pure-Go Mach-O parsing, apktool-based Android
decomposition, a Redis/worker pipeline, and integrations (Jira/Slack/webhooks/compare) — is
genuinely differentiated. Most OSS peers are either source-level SAST (MobSF/`mobsfscan`) or
repo/filesystem secret scanners (TruffleHog); few do **artifact-level (APK+IPA) secret recon**
as a service.

Two things are true at once:

1. **MORF's iOS module is dramatically better than the internal Python+radare2 PoC** it is meant
   to replace. On the same App build it found **29 findings across 9 types + full app metadata**
   vs the PoC's **8 (one working regex)**, and it scans arbitrary apps the PoC physically cannot.
   The PoC should be retired. (§3)
2. **MORF is still an early-stage scanner** measured against the community bar. It *detects* but
   does not *verify* secrets; its precision relies on regex + a value-dedup; it has no SARIF/CI
   output, no SBOM/CVE coverage, and no MASVS-mapped checks beyond secrets. These are exactly the
   capabilities the market now expects. (§4)

**The single highest-ROI next move** (best evidence, moderate effort, directly addresses the
"is this real?" question every consumer of the report asks): an **opt-in secret verification
layer** modeled on how TruffleHog/GitGuardian/GitHub already do it — paired with the documented
**entropy + context precision recipe** that kills false positives with no network calls and no
LLM. Everything else sequences behind those two.

Where MORF should *win*: lean into what it uniquely does — **dual APK+IPA binary recon +
*verified* (not merely detected) secrets** — rather than re-implementing MobSF's source-level
semgrep coverage. [MobSF/mobsfscan](https://github.com/MobSF/mobsfscan),
[TruffleHog verification](https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets).

---

## 2. Where MORF stands today

**Architecture strengths (keep leaning on these):**
- Redis reliable queue + worker pool, per-job isolated workspaces, DLQ + retry, webhook delivery
  with SSRF-validated URLs (`worker/worker.go`, `router/routers.go`, `queue/`).
- A **shared, platform-agnostic detection core** (`detect/detect.go`) used by *both* Android and
  iOS: YAML patterns → combined ripgrep regex → attribution → `SanitizeSecrets`.
- **Platform scoping** (patterns tagged `ios`/`android`/`any`) so iOS-only rules don't fire on
  Android and vice-versa (`detect/detect.go`; `detect/platform_scope_test.go`).
- Integrations already present to build on: `/compare` (scan diffing), `/jira`, `/slackscan`,
  `/patterns` CRUD, PDF export, Prometheus metrics.

**Recent wins:** the pure-Go iOS module (below); a detection noise cut (resource-dir filtering +
value-dedup + disabling the loose "Generic Secret"/"Generic API Key" rules) that took a real
Android scan from 548 → ~19 clean findings; and a real-phase processing stepper.

**Honest gaps (what a 2025-26 security team will ask for and MORF lacks):**
- No **verification** — findings are "detected," not proven live/active.
- **Precision** is regex + dedup only; no entropy/context scoring, so generic-secret rules are
  either noisy or disabled.
- No **SARIF** output → cannot plug into GitHub code scanning / most CI security gates.
- No **SBOM / SDK-CVE** (supply-chain) coverage, despite already extracting the framework list.
- No **MASVS/MASTG-mapped** checks beyond secrets (insecure storage, ATS, exported components,
  WebView, cert pinning) — the MobSF baseline.
- iOS is **static-only**: FairPlay-encrypted App Store binaries and runtime-only secrets are out
  of reach; entitlements are extracted but not **risk-scored**.

---

## 3. iOS depth — MORF vs the internal PoC (`Secrets_IPA.zip`), with live evidence

### 3.1 The head-to-head (run 2026-07-08 on identical binaries)

Target: **`reference.ipa`** → `Payload/App.app/App`, 121 MB arm64, **`cryptid 0` (NOT FairPlay-
encrypted)** — a decrypted/dev build, so static extraction works fully for *both* tools (a fair
test; neither is handicapped by encryption).

| Dimension | Internal PoC (`Secrets_IPA`) | MORF iOS |
|---|---|---|
| **Findings on App** | **8 raw matches = only 4 unique keys** (all Google `AIza…`; PoC has no value-dedup) | **29** across 9 types (incl. **8** unique Google keys) |
| Types found | Google API keys only | Google API Key, GCP OAuth, Firebase DB URL, Private Key, Twitter Secret, JWT, iOS Keychain Access Group, Reversed Client-ID scheme, Keychain entitlement |
| Working detectors | **1 of 11** regexes (rest typo'd/broken, e.g. `sk_live_\(…`) | 99 iOS-scoped patterns |
| App metadata | **none** | bundle id, **73 frameworks, 21 entitlements, 12 URL schemes**, arch, encryption flag |
| String handling | dumped **603,671** strings; the hardcoded section indices (`"29.__DATA.__cfstring"`) are a **no-op** — `r2 izzj` just dumps everything | section-scoped by name, deduped |
| Runs on other apps? | **No** — hardcoded to `App.app/App` + a Google-Drive/password ingestion | **Yes** — cleanly scanned DVIA-v2, NOOP, TestFlight (correct bundle ids/frameworks) |

**Verdict: MORF is a strict superset — same keys, plus far more.** Every key the PoC surfaced is
in MORF's set: the PoC's 4 unique Google keys are all present in MORF's 8 unique Google keys
(`PoC-only findings: none`). MORF additionally found **4 more Google keys + 25 non-Google findings
the PoC is blind to**, plus structured metadata the PoC has none of. The PoC even mis-*counts* its
own hits (8 raw matches for 4 real keys — no value-dedup). On any app that isn't App, the PoC
cannot run at all.

### 3.2 Why the PoC must be retired (it is also a security liability)
- **Secrets in the repo**: a Google Drive **service-account key committed as `vm-tenable.json`**
  and a password in `.env` (`Retrive_IPA_file.py`, `.env`).
- **Brittleness**: hardcoded app name `App`, hardcoded Mach-O section indices, ~11 typo-ridden
  regexes, **525 MB of vendored radare2**, no dedup/entropy/confidence, single-app output.
- MORF already does the same job correctly with pure-Go `go-macho` (sections **by name**, FairPlay
  `cryptid` detection, fat/thin, entitlements from `embedded.mobileprovision`, ATS, frameworks),
  feeding the shared detection core. `ios/macho.go`, `ios/foundation.go`, `ios/frameworks.go`,
  `ios/analysis.go`.

### 3.3 But: static string+regex has a recall ceiling (motivation for iOS roadmap)
On **DVIA-v2** (a *deliberately* vulnerable app) MORF found **0 hardcoded secrets** — because
DVIA's issues are runtime/behavioral, not `AIza…`-style embedded keys. This is not a MORF bug (the
PoC would find nothing there too, if it could run); it's the inherent limit of static string
matching. It justifies the iOS depth items below: **FairPlay decryption** (for App Store builds),
**Swift/Obj-C string extraction & deobfuscation**, **entitlement risk scoring**, and **dynamic/
runtime capture**. Evidence for these dimensions is thinner (blog-grade), so treat as directional:
[decrypt methods](https://fadeevab.com/decrypt-ios-applications-3-methods/),
[no-jailbreak iOS pentest](https://www.anvilsecure.com/blog/locked-up-but-not-locked-out-ios-app-pentesting-without-jailbreak.html).

---

## 4. Roadmap items (each an implementation guide)

Format per item: **Problem → Design → MORF seam to reuse → Data/API/config → Safety → Effort →
Verify.** Effort = S/M/L. Confidence reflects the strength of external evidence.

### A. Secret **verification layer** *(user idea #1 — P0, highest ROI, evidence: HIGH)*
**Problem.** MORF reports "detected" secrets; consumers can't tell live from dead/example keys.
The whole industry solved this with **active validity checks**.

**Design (modeled on TruffleHog/GitGuardian/GitHub — all three converge on the same pattern):**
a **detector-specific, stateless, non-mutating** call to the provider's *least-intrusive
read-only* endpoint, classifying each secret **ACTIVE / INACTIVE / UNKNOWN**.
[TruffleHog](https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets),
[GitGuardian](https://blog.gitguardian.com/validity-check-product-update/),
[GitHub](https://docs.github.com/en/code-security/concepts/secret-security/about-validity-checks).
- A `Verifier` interface keyed by `SecretType`; a registry with a per-provider plugin. Start with
  the safest, highest-value probes: **AWS STS `GetCallerIdentity`**, **Slack `auth.test`**,
  **GitHub `GET /user`**, **Stripe** (GET), **Google API-key** probe, **Twilio**. Coverage is a
  deliberate, expanding subset — not every secret is verifiable (GitGuardian verifies 231/515
  patterns).
- Result cached (by secret hash) with a TTL to avoid re-hitting providers.

**MORF seam.** Add a post-scan **enrichment stage** right after `detect.SanitizeSecrets` in
`worker/worker.go` (`scanAPK`/`scanIPA` → before `handleJobSuccess`). Reuse the existing outbound
HTTP + semaphore pattern (the webhook client) and the `MORF_*` env plumbing. No new pipeline.

**Data/API/config.** Add `VerificationStatus` (`active|inactive|unknown|unchecked`) +
`VerifiedAt` to `models.SecretModel`; surface in `/results` and the UI as a badge; add a
`SET FOREIGN_KEY_CHECKS`-free migration for the column. Gate behind `MORF_ENABLE_VERIFICATION`
(default **false**) + per-provider rate limits + a bounded worker pool.

**Safety (non-negotiable, evidence-backed).** Even non-mutating checks have opsec side effects:
the auth attempt **appears in the provider's logs** (a MORF user-agent), and can trip
rate-limits/lockouts. So: **opt-in only**, explicit authorized-use acknowledgement, per-provider
rate limiting, result caching, a clear identifiable user-agent, and **never** an endpoint that
mutates or creates billable resources.
[opsec caveat](https://docs.github.com/en/code-security/concepts/secret-security/about-validity-checks).

**Effort M. Verify:** unit tests per verifier against mocked provider responses; a manual live
test with a throwaway key showing ACTIVE→(revoke)→INACTIVE.

### F. **Detection precision** without LLM/network *(P0, evidence: HIGH)*
**Problem.** Generic-secret rules are either noisy or disabled; precision rests on regex + dedup.

**Design (GitGuardian's fully-documented recipe — implementable today, no LLM, no calls):**
an **assignment model** (`{variable}{assign}{value}` where the variable name matches
`secret|token|api[_.-]?key|credential|auth`) gated by **Shannon entropy ≥ 3** and **≥ 2 digits**,
then **banlists** (placeholders `test/example/fake`, bcrypt `^\$2[abxy]\$`, unicode/ascii escapes)
and **two 30-char context-window checks** (reject near `author/sha/pubkey/key_id/localhost/csrf`).
[GitGuardian generic detector](https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret).

**MORF seam.** Add an entropy/context post-validator in `detect/detect.go` (after match, before
`SanitizeSecrets`); re-introduce a *scored* generic-secret rule to recover recall lost when the
loose ones were disabled. Emit a numeric `score` alongside `confidence`.

**Effort S–M. Verify:** re-scan the App APK/IPA; confirm the count stays low and real keys remain
while punctuation/identifier noise stays gone.

### J1. **SARIF output + MASVS/MASTG IDs** *(P0/P1 — unlocks CI adoption, evidence: HIGH)*
**Problem.** Without SARIF, MORF can't feed GitHub code scanning or most CI security gates.

**Design.** Add a `GET /results/:jobID/export?format=sarif` producing **SARIF 2.1.0** (the version
GitHub requires); annotate every finding with **OWASP Mobile + MASVS/MASTG** IDs. This is exactly
how `mobsfscan` gets CI adoption (`--sarif` → `github/codeql-action/upload-sarif`).
[mobsfscan](https://github.com/MobSF/mobsfscan), [MASVS](https://github.com/OWASP/masvs),
[MASTG](https://github.com/OWASP/mastg).

**MORF seam.** New encoder next to the PDF export path in `router/routers.go`; add a `masvs_id`
field to pattern YAML so mapping is data-driven. **Effort S–M.**

### D. **SDK/framework CVE + SBOM (CycloneDX + VEX)** *(P1, evidence: HIGH)*
**Problem.** MORF already extracts the framework list (73 for App) but does nothing with it.
Third-party SDKs are a top mobile supply-chain risk.

**Design.** Emit a **CycloneDX 1.x** SBOM (JSON) of detected SDKs/frameworks for both APK and IPA;
cross-reference versions against a CVE feed; attach **VEX** so non-exploitable CVEs are suppressed
(only ~10–20% of included-component CVEs are exploitable — VEX keeps it actionable).
[CycloneDX SBOM guide](https://cyclonedx.org/guides/sbom/OWASP_CycloneDX-SBOM-Guide-en.pdf).

**MORF seam.** New post-scan stage consuming the iOS `frameworks` list (`ios/frameworks.go`) and
the Android library list; store an SBOM artifact; expose `GET /results/:jobID/sbom`. Framework
**version** extraction is the hard part (Info.plist `CFBundleShortVersionString` per embedded
framework; Android via dependency metadata). **Effort M–L.**

### E. **CI/CD ingestion + build-over-build diff gating** *(P1, evidence: MED)*
**Problem.** The PoC's Google-Drive-service-account ingestion is an anti-pattern. Teams want the
scanner in the release pipeline, failing builds on *new* problems.

**Design.** First-class artifact hooks — **App Store Connect / TestFlight / Xcode Cloud / Fastlane
/ Play / S3 / generic CI** — replacing ad-hoc Drive polling. Extend the existing **`/compare`**
endpoint into **policy-as-code**: fail the build when a **new, verified** secret (needs Item A)
appears vs the previous build; allow a baseline/allowlist to suppress accepted findings.

**MORF seam.** `/compare/:jobID1/:jobID2` already diffs scans (`router/routers.go`); add a
policy evaluator + exit-code semantics + a thin CI wrapper. **Effort M.**

### G. **MASVS/MASTG coverage expansion (MobSF-parity direction)** *(P1/P2, evidence: HIGH for the bar)*
**Problem.** A "serious" mobile scanner covers more than secrets. The bar is
MASVS → MASWE → MASTG, and MobSF is the concrete OSS reference.

**Design.** Add MASVS-mapped static checks, reusing MORF's existing extraction: **insecure data
storage**, **ATS/insecure comms** (MORF already flattens `NSAppTransportSecurity`), **exported
components** (Android manifest — already parsed), **WebView misconfig**, **cert-pinning presence**.
Differentiate — don't re-implement MobSF's semgrep source coverage; lean on binary/recon + verified
secrets. **Effort L (incremental, check-by-check).**

### iOS depth items *(P1–P2, evidence: MED/blog-grade — flagged uncertain)*
- **Entitlement risk scoring (P1, S):** MORF already extracts 21 entitlements for App — score
  them (e.g., wildcard keychain-access-groups, `get-task-allow` in a release build, associated-
  domains sprawl) and map to MASTG. Pure post-processing on data already in `IOSMetadata`.
- **Swift/Obj-C extraction & deobfuscation (P2, M):** MORF reads `__swift5_*`/`__objc_*` sections;
  add demangling + light deobfuscation to raise recall on Swift apps (DVIA-class).
- **FairPlay decryption (P2, L, needs infra):** App Store binaries are encrypted (`cryptid != 0`);
  static extraction can't read `__TEXT`. This genuinely needs a **jailbroken device / macOS runner**
  (`frida-ios-dump`) — a separate, opt-in worker lane, not the default path. Flag: evidence is
  blog-grade. [decrypt methods](https://fadeevab.com/decrypt-ios-applications-3-methods/).
- **Dynamic/runtime capture (P2/Later, L):** Frida-based keychain/runtime-string capture — biggest
  recall win but heaviest infra; likely a distinct product line.

### B. **AI — LLM triage** *(user idea #2 — P2, assistive only, evidence: MED + a hard warning)*
**Problem.** Even after Item F, some findings need judgment (real vs noise, risk, remediation).

**Design.** An **assistive, human-in-the-loop** enrichment stage that scores a finding real-vs-noise
and drafts risk/remediation — **never an auto-suppressor**. The one rigorous 2026 study shows LLM
FP-filtering cut false positives 92.1% **but suppressed 22.25% of *real* findings** (synthetic Java
SAST, not mobile) — so gains don't transfer blindly and silent suppression is dangerous.
[study](https://arxiv.org/html/2601.22952v1), [Datadog on LLM FP filtering](https://www.datadoghq.com/blog/using-llms-to-filter-out-false-positives/).

**Hard safety rule (treat as unverified-by-research but mandatory):** **never send a raw secret to a
third-party model.** Send **redacted/masked** context only (type, file, surrounding tokens with the
value starred), or run a **local/self-hosted** model. Default off (`MORF_ENABLE_AI_TRIAGE`).

**MORF seam.** Same post-`SanitizeSecrets` enrichment point as Item A; add an `ai_assessment` field
(advisory, never changes `confidence` automatically). If building on Claude, prefer the latest models
and prompt/tool patterns per the Anthropic docs. **Effort M–L.** *Caveat: MORF has no LLM code today.*

### C. **AI — MCP server** *(user idea #2 — P2, evidence: THIN/blog-grade — flagged uncertain)*
**Problem.** Security teams increasingly drive tools from AI agents; MORF should be callable in an
agentic workflow.

**Design.** Expose MORF as an **MCP server** with read-mostly tools — `scan_app(path)`,
`get_results(jobID)`, `list_findings`, `verify_secret` (gated by Item A's opt-in), `list_patterns`
— plus results as MCP *resources*. Keep it **read/scan-only**; never expose destructive or
provider-mutating actions to an agent; require auth (reuse MORF API keys). Prior art exists but is
early: [aws-samples MCP security scanner](https://github.com/aws-samples/sample-mcp-security-scanner),
[Semgrep's security-engineer's guide to MCP](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/).
**Effort M.** *Flag: no verified best-practice corpus yet — build conservatively.*

### H. **Scale & architecture** *(P1/P2, ongoing)*
Large IPAs are slow (the App scan's secret phase is ~145 s). Roadmap: stream ripgrep output (partly
done), cap/parallelize per-section scanning, size-aware worker concurrency, and validate the
horizontal `api`/`worker` split under load. Keep the on-prem/air-gapped posture (a differentiator vs
SaaS scanners). Seam: `worker/pool.go`, `queue/`.

### I. **Platform breadth** *(P2/Later)*
Add **Flutter / React-Native / Xamarin** asset+string extraction (these bundle secrets in JS
bundles / `flutter_assets` / .NET assemblies that current patterns partially miss), and a small
**plugin model** so new package types slot into the shared `detect` core.

### K. **Governance & positioning** *(ongoing)*
Map findings to MASVS for attestation-friendly reporting; publish the differentiation thesis
(**dual APK+IPA binary recon + verified secrets**, OSS, on-prem) vs MobSF (source SAST) and
commercial MAST; steward the community (MORF is a former BlackHat Arsenal project).

---

## 5. Final prioritized table

| # | Item | Solves | Impact | Effort | Risk | Depends on | Evidence | Horizon | Priority |
|---|------|--------|--------|--------|------|-----------|----------|---------|----------|
| A | Secret verification layer | "is it live?" — kills dead/example-key noise | ★★★★★ | M | Opsec (provider logs, rate-limit) → opt-in only | — | HIGH | **Now** | **P0** |
| F | Entropy+context precision (no LLM) | regex false positives | ★★★★☆ | S–M | Low | — | HIGH | **Now** | **P0** |
| J1 | SARIF 2.1.0 + MASVS IDs | CI/GitHub adoption | ★★★★☆ | S–M | Low | — | HIGH | **Now/Next** | **P0/P1** |
| iOS-1 | Entitlement risk scoring | iOS posture from data already extracted | ★★★☆☆ | S | Low | — | MED | **Next** | **P1** |
| D | SDK/framework CVE + CycloneDX SBOM + VEX | supply-chain blind spot | ★★★★☆ | M–L | FP CVEs w/o VEX | version extraction | HIGH | **Next** | **P1** |
| E | CI ingestion + build-diff gating (policy-as-code) | shift-left, replaces Drive-PoC | ★★★★☆ | M | Gate flakiness | A (verified diff) | MED | **Next** | **P1** |
| G | MASVS/MASTG coverage expansion | reach the MobSF bar | ★★★★☆ | L | Scope creep | J1 mapping | HIGH (bar) | **Next/Later** | **P1/P2** |
| H | Scale & large-IPA performance | 145 s scans, throughput | ★★★☆☆ | M | — | — | MED | **Ongoing** | **P1/P2** |
| B | AI LLM triage (assistive) | judgment on residual findings | ★★★☆☆ | M–L | **Suppresses real findings; secret leakage to model** | redaction/local model | MED (+warning) | **Later** | **P2** |
| C | MCP server | agentic security workflows | ★★★☆☆ | M | Agent misuse | A (for verify tool) | THIN | **Later** | **P2** |
| iOS-2 | Swift/Obj-C extraction + deobfuscation | recall on Swift apps | ★★★☆☆ | M | — | — | MED | **Later** | **P2** |
| iOS-3 | FairPlay decryption (device/macOS runner) | App Store encrypted binaries | ★★★☆☆ | L | Infra + legal | separate worker lane | BLOG | **Later** | **P2** |
| iOS-4 | Dynamic/Frida runtime capture | runtime-only secrets | ★★★★☆ | L | Heavy infra | device farm | BLOG | **Later** | **P2** |
| I | Flutter/RN/Xamarin breadth | coverage gaps | ★★★☆☆ | M–L | — | plugin model | — | **Later** | **P2** |
| K | Governance & positioning | adoption, attestation | ★★★☆☆ | S (ongoing) | — | J1/G | HIGH | **Ongoing** | **P1** |

Impact ★ = author judgment; Evidence = strength of external sourcing (HIGH = primary vendor/OWASP;
MED = one study/secondary; BLOG/THIN = blog-grade or no verified claim — build conservatively).

---

## 6. Sequenced roadmap

**Now (0–1 quarter) — make findings trustworthy + CI-ready:**
1. **A. Verification layer** (P0) — the flagship. Start with AWS/Slack/GitHub/Stripe/Google/Twilio.
2. **F. Entropy+context precision** (P0) — recover generic-secret recall without adding noise.
3. **J1. SARIF + MASVS IDs** (P0/P1) — unlock GitHub code scanning / CI gates.
4. Retire the `Secrets_IPA` PoC; rotate the leaked Drive service-account key + `.env` password.

**Next (1–2 quarters) — coverage + shift-left:**
5. iOS entitlement risk scoring (quick win on data already extracted).
6. D. CycloneDX SBOM + SDK-CVE (+VEX); E. CI ingestion + build-diff gating on **verified** deltas.
7. Begin G. MASVS/MASTG checks (ATS, exported components, insecure storage — reuse existing parses).

**Later — depth + AI + reach:**
8. B. AI triage (assistive, redacted/local, human-in-loop) and C. MCP server — both opt-in, both
   built conservatively given thin evidence.
9. iOS Swift/Obj-C deobfuscation, FairPlay decryption (device/macOS runner), dynamic/Frida capture.
10. Flutter/RN/Xamarin breadth; positioning & MASVS attestation reporting.

**Critical path / one-liner:** *Verify what you detect, score what you can't verify, speak SARIF, then
grow coverage.* Verification (A) + precision (F) are the two moves that most raise trust in every
report MORF produces — do them first.

---

## 7. Caveats & what's *not* proven
- Evidence is **strong** for the verification pattern, the entropy/context recipe, and the
  MASVS/MASTG/MobSF/SARIF/CycloneDX baseline (primary vendor + OWASP sources, unanimous verification).
- Evidence is **weak** for LLM triage (one un-replicated 2026 synthetic-Java study; the 92.1% FP-cut
  came with 22.25% real-finding suppression — do not trust auto-suppression), and **thin/absent** for
  MCP-for-security best practices and iOS FairPlay/dynamic specifics (blog-grade). Build those
  conservatively and validate on real mobile data before trusting them.
- The head-to-head numbers are reproducible from the live runs on 2026-07-08 (`reference.ipa` decrypted,
  `cryptid 0`). An App-Store-encrypted App build would limit *both* tools until iOS-3 lands — MORF
  flags the encryption; the PoC degrades silently.
- Verification and AI both carry real safety obligations (authorized-use-only, never mutate, never
  send raw secrets to a third-party model) — these lead each design, not footnote it.
