# MORF React UI — Round 2: usability pass

Applies the frontend-design skill's "writing in design" + "quality floor" on top of the Forensic Dossier system. Goal: friendlier, clearer screens. Product name stays "MORF - Mobile Reconnaissance Framework".

## Shared building blocks (USE THESE — already built)
- **`<AppHeader />` is now rendered globally** in the app shell on every screen EXCEPT splash. So each screen must **remove its own top header / MORF wordmark / nav** — start directly with the screen's content (a page title is fine, but no duplicate wordmark or nav bar).
- **`Button`** from `@/components/ui/Button` — variants `primary` (amber CTA) / `outline` / `ghost` (mono link) / `danger` (oxblood); sizes `sm|md|lg`. Use it for all buttons.
- **`cn`** from `@/lib/cn`; **`useScan`** from `@/store/scanStore` (do not change its API); design tokens `ink/bone/signal/oxblood` + `font-display/sans/mono` + global classes `.eyebrow/.dossier/.evidence/.redaction/.stamp/.sev`.
- **framer-motion** for tasteful entrance + micro-interactions; **respect `useReducedMotion`** (return no-motion variants when true). Keep motion to ONE tasteful moment per screen, not scattered.

## Usability rules (the point of this pass)
1. Every screen opens with a clear **page title** (font-display) + a **one-line plain-language helper** (what this screen is for / what to do).
2. **Active-voice, user-facing copy**: name things by what the user controls; buttons say what happens ("Analyze", "Add rule", "Copy value"); keep the same verb through a flow.
3. **Empty / loading / error states** are explicit and actionable — never a blank area. Errors say what happened + how to fix, in the interface's voice.
4. **Affordances**: obvious clickable/hover/focus states; keyboard reachable; `aria-label`s on icon-only buttons; visible focus (global). Responsive down to mobile.
5. Density with hierarchy: group related info, use the `.evidence` rows and `.dossier` panels, don't wall-of-text.

## Per-screen goals (preserve ALL existing store behavior/fields)
- **Upload** (`src/screens/Upload.tsx`): remove its header (AppHeader covers it). Make the intake obviously interactive: a large dossier dropzone with clear "Drag a .apk/.ipa here or click to browse", the platform choice explained (Android→.apk, iOS→.ipa) with the accepted extension shown, and a friendly note on what happens next + that files are analyzed locally. Keep the extension-mismatch guard but replace `alert()` with an inline message. Keep `processFile`, `setSelectedPlatform`, platform tabs.
- **Processing** (`src/screens/Processing.tsx`): remove header. Reassure the user: a clear "Analyzing <filename>" title, the animated scan-sweep over the redacted doc, a **stepper** of phases (unpack → parse → match rules → compile) with the active one indicated, an honest "this can take a minute for large apps" note, file name + size as evidence, and a clear **Cancel** (danger Button) → `cancelScan()`. Keep `currentFile`, `selectedPlatform`, `cancelScan`.
- **Results** (`src/screens/Results.tsx`): remove its header. Lead with a **scannable summary**: the big `N EXPOSED` count + severity breakdown (high/med/low with `.sev` + counts via `getSecretCountBySeverity`) + target identity + a `.stamp` platform badge. Then **Discovered secrets** as evidence cards — secret value in a `.redaction` (tabindex 0, reveals on hover/focus; keep the reveal), severity stamp, cleaned file path:line, Copy button (Button ghost). Add a simple **search/filter box** to filter secrets by type/value, and a **severity filter** (optional). iOS panel: bundle id/version/deployment target/executable/architectures/encryption stamp/url schemes/frameworks + an **entitlements** table (key → JSON value). Android panel: package/version/sdk + collapsible activities/services/content-providers/broadcast-receivers/permissions (use Radix Collapsible or a simple toggle). Empty state if 0 secrets ("No exposed secrets found — nice."). Keep `secrets`, `resultPlatform`, `iosMetadata`, `metadata`, `getSecretCountBySeverity`, `resetScan`.
- **PatternManagement** (`src/screens/PatternManagement.tsx`): remove its header. Build the **full CRUD** the Angular app had, using `patternsApi` (already imported): list files (left), a file's rules (right) with enabled `.stamp` + `.sev` + regex in mono; **Radix Dialog** modals for: New rule file, Add rule, Edit rule, Test rule (regex against sample text → show matches/count). Toggle enable/disable, delete rule, delete file (confirm). Loading/empty/error states + success toasts (3s). Active-voice copy. Keep it working against the existing endpoints in `@/lib/api` `patternsApi`.

## HARD RULES
- Don't change `@/store/scanStore` or `@/lib/api` signatures; consume them.
- Preserve the redaction reveal on results, the platform-resolution rule (results reads `resultPlatform`), and the polling-driven flow.
- Edit ONLY your screen file (+ optional new components under `src/components/ui/` you clearly own; if you add a shared primitive like Dialog/Collapsible, keep it self-contained). Do not touch other screens, `App.tsx`, `AppHeader.tsx`, `index.css`, `tailwind.config.ts`, or the store/api.
- `npm run build` must pass (run it). Do not run git.
