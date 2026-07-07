# MORF UI — "Forensic Dossier" design system

Product name is **always** "MORF - Mobile Reconnaissance Framework" (never rename; "dossier" is a visual treatment only).

**Thesis:** MORF exposes secrets that were meant to stay hidden → the UI presents findings like **declassified evidence**. Spend boldness on ONE signature (the redaction bar); keep everything else quiet and disciplined.

## Tokens (Tailwind — already configured in `tailwind.config.js` + `styles.css`)

**Color** (use these class roots): `ink` (#14110F page) · `ink-800` (raised panel) · `ink-700` (hairline border) · `ink-900` (redaction fill) · `bone` (#EDE6D6 primary text/paper) · `bone-dim` (#B9AC93 secondary) · `signal` / `signal-hi` (#E8A33D amber — the ONLY accent: links, highlights, medium severity) · `oxblood` (#A83232 alerts/high severity).
Do **not** introduce new hues. No blue. No neon. No glow.

**Type**: `font-display` (Anton — statements: MORF wordmark, big counts, screen titles; uppercase) · `font-sans` (Archivo — body/controls/labels) · `font-mono` (Space Mono — evidence: secret values, file paths, timestamps, data).

**Signature + helper classes** (defined globally in `styles.css`, use as-is):
- `.redaction` — the signature. Wrap a leaked secret value; it renders as an ink bar and reveals on hover/focus/tap or when the `revealed` class is added. Example: `<span class="redaction" tabindex="0">AKIA…</span>`.
- `.stamp` (oxblood) / `.stamp--signal` / `.stamp--muted` — rubber-stamp verdict/severity marks (EXPOSED, CONFIRMED). Add `animate-stamp-in` for entrance.
- `.evidence` with `<span class="k">field</span><span class="lead"></span><span class="v">value</span>` — typewritten field⋯value rows with leader dots.
- `.eyebrow` — stenciled mono caption above a section.
- `.dossier` — a raised document panel.
- `.case-rule` — hairline divider. `.sev--high|medium|low` — severity dots.
- Motion: `animate-file-in` (section reveal), `animate-scan-sweep` (processing), `animate-stamp-in`.

## Per-screen intent
- **splash** — the case-file title card: big Anton "MORF", eyebrow "MOBILE RECONNAISSANCE FRAMEWORK", a struck classification bar. Restrained.
- **upload** — "Open a case file": the dropzone is a manila intake slot; verb "Analyze", not "Submit".
- **processing** — "Reconnaissance in progress": a `scan-sweep` over a redacted document; status lines in mono.
- **results** — the hero. A dossier header with a huge Anton `N EXPOSED` count + target bundle id; findings as evidence rows where the **secret value is a `.redaction`** with a severity `.stamp`. iOS metadata (bundle id, deployment target, architectures, `isEncrypted`, url schemes, frameworks) in a `.dossier` panel; keep the existing android metadata panel too.
- **pattern-management** — "Detection rules ledger": patterns as evidence rows; enabled/disabled as stamps.
- **app shell** — ink field + subtle paper grain (already on body); any nav in mono eyebrow style.

## HARD RULES for editing components
1. **Preserve every Angular binding and behavior**: all `*ngIf`, `*ngFor`, `(click)`, `[prop]`, `[(ngModel)]`, template refs, pipe usage, and the component's TS field/method names. Change **presentation only** (markup structure + classes + component CSS). Do NOT rename or remove data fields.
2. **Do not break the secrets or iosMetadata rendering** on results-screen (the "Discovered Secrets" `*ngFor="let secret of secrets"` and the `platform`/`iosMetadata` blocks must keep working).
3. Keep the product name exact: "MORF - Mobile Reconnaissance Framework".
4. Quality floor: responsive to mobile, `:focus-visible` (global), `prefers-reduced-motion` respected (global) — don't fight them; buttons/links reachable by keyboard; alt/aria where relevant.
5. Copy in the interface's voice: active verbs, sentence case for prose, name things by what the user controls. Errors explain what happened + how to fix.
6. Verify with `npm run build` before finishing.
