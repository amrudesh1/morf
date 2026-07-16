# MORF and the OWASP MASVS

MORF maps each secret detection to an **OWASP MASVS** (Mobile Application Security
Verification Standard) control, so findings speak the language security teams already use
and land correctly in MASVS-aware dashboards.

This document is deliberately honest about scope: MORF is an **artifact-level secret &
recon scanner**, so it maps to the MASVS controls that hardcoded-secret findings evidence —
not the full MASVS surface. What MORF does *not* yet check is listed explicitly at the end.

## How the mapping flows

The mapping is data-driven, not hardcoded in Go:

1. **Pattern tag.** A detection pattern (or its pattern file) in `morf/patterns/` carries a
   `masvs:` field. A pattern-level tag overrides the file-level default.
2. **Resolution.** `detect/detect.go` resolves the tag onto the finding
   (`SecretModel.MASVSID` / `SecretFinding.masvs_id`) as it attributes each ripgrep hit
   back to its pattern.
3. **Surfacing.** `report/sarif.go` (`EncodeSARIF`) writes the control id into the SARIF
   rule's `tags` array and a `masvsId` property; the MCP `explain_finding` tool reports it
   too.

Because it is tag-driven, adding or re-mapping a control is a pattern edit — no code change.

## Controls MORF maps today

Grounded in the live pattern set in `morf/patterns/` (counts are the number of patterns
tagged with each control):

| MASVS control | What it covers here | Example detections | Patterns |
|---|---|---|---|
| **MASVS-STORAGE-1** | Sensitive data (secrets, API keys, tokens) hardcoded / stored in the app package. This is MORF's core: a leaked credential shipped in the binary. | Google API keys, cloud/CI tokens, provider keys, iOS-embedded secrets | 56 |
| **MASVS-STORAGE-2** | Additional sensitive-data-at-rest exposure surfaced by specific patterns. | select storage-sensitive credential patterns | 7 |
| **MASVS-CRYPTO-1** | Hardcoded / weak cryptographic material — private keys and key material embedded in the artifact. | RSA/EC private key blocks, embedded key material | 6 |
| **MASVS-NETWORK-1** | Cleartext / endpoint exposure — secrets or endpoints that evidence insecure network configuration. | hardcoded endpoints / cleartext-adjacent credential patterns | 11 |

The default file-level tag for the bulk secret sets (`breadth-cloud-ci.yml`,
`ios-secrets.yml`) is **MASVS-STORAGE-1**, which is why storage is the dominant control;
individual patterns override to `-STORAGE-2`, `-CRYPTO-1`, or `-NETWORK-1` where the finding
evidences that control more precisely.

## In SARIF

Each finding becomes one SARIF result; its rule carries the MASVS id:

```jsonc
{
  "ruleId": "google-api-key",
  "level": "error",                 // precision tier "keep" -> error, "info" -> note
  "properties": { "masvsId": "MASVS-STORAGE-1" },
  "message": { "text": "Hardcoded secret (masked): AIza********…" }
}
```

The rule definition additionally lists the control under `tags`, so MASVS-aware viewers can
filter and group by control. Secret values are always masked in the SARIF output.

## Not yet mapped (roadmap, not claimed coverage)

MORF maps the controls its secret findings *evidence*. It does **not** currently perform the
broader MASVS/MASTG checks below. These are tracked in
[SECURITY_ROADMAP.md](SECURITY_ROADMAP.md) and are stated here so no one over-reads MORF's
coverage:

- Insecure data storage beyond hardcoded secrets (keychain/keystore misuse, cache/log
  leakage).
- App Transport Security (ATS) posture and cleartext-traffic policy analysis.
- Exported-component risk scoring (activities/services/receivers/providers) — MORF
  *extracts* components but does not risk-score them.
- WebView configuration (JS bridges, mixed content).
- Certificate/public-key pinning verification.
- Entitlement risk scoring — iOS entitlements are *extracted* but not scored.
- SBOM / SDK-CVE (supply-chain) coverage.

Treat the mapped controls above as MORF's honest MASVS coverage today; everything in this
list is directional.
