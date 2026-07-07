# iOS scanning architecture

This document describes how MORF analyses iOS applications (`.ipa` archives and
the Mach-O binaries inside them), how that path maps onto the existing Android
(APK) pipeline, and the known limitations of static Mach-O analysis.

> Status: the Mach-O parsing and iOS-pattern design described here targets the
> `v1.1 — Enhanced iOS Support` roadmap milestone. The committed
> [`ios/testdata/`](../ios/testdata/) fixtures exist so this path can be
> smoke-tested against a real arm64 Mach-O and a synthetic `.ipa`.

## 1. Overview

An `.ipa` is a plain zip archive with the layout:

```
Payload/
  <App>.app/
    <App>            <- the Mach-O executable (CFBundleExecutable)
    Info.plist       <- app metadata (XML or binary plist)
    Frameworks/      <- optional embedded .framework / .dylib Mach-Os
    *.lproj, assets, ...
```

MORF's iOS flow is:

1. **Unzip** the `.ipa` and locate `Payload/<App>.app/`.
2. **Parse `Info.plist`** (XML *or* binary) for metadata: bundle id, version,
   minimum OS, and declared URL schemes (deeplinks).
3. **Open the Mach-O** executable (and, optionally, embedded frameworks) with
   [`go-macho`](https://github.com/blacktop/go-macho).
4. **Enumerate sections by name** and pull candidate strings (Swift reflection,
   ObjC metadata, C strings, CFStrings).
5. **Run the same regex secret patterns** used for Android over those strings.
6. **Emit the same `SecretModel` / metadata shapes** the Android path produces,
   so storage, reporting, and the API are shared.

## 2. Mach-O parsing with go-macho

`go-macho` is pure Go (no cgo, no libmacho), which keeps MORF's build hermetic
and cross-platform. Two entry points matter:

| Function | Use |
|----------|-----|
| `macho.Open(path)` | **Thin** (single-architecture) Mach-O. Returns one `*macho.File`. |
| `macho.OpenFat(path)` | **Fat / universal** Mach-O. Returns a `*macho.FatFile` whose `.Arches` slice holds one `*macho.File` per architecture. |

Because a binary may be either form, the loader must **try fat first, fall back
to thin** (or sniff the magic: `0xCAFEBABE` / `0xBEBAFECA` ⇒ fat, `0xFEEDFACF`
⇒ thin 64-bit). For a fat binary, iterate `fat.Arches` and analyse each
`arch.File` independently, then union the results.

### 2.1 Section enumeration by name (never by index)

Section positions are **not** stable across compilers, Swift versions, or
optimisation levels, so MORF always enumerates by `(segment, section)` name:

```go
for _, s := range f.Sections {
    // s.Seg  -> segment name, e.g. "__TEXT"
    // s.Name -> section name, e.g. "__cstring"
    data, err := s.Data()   // raw section bytes
    if err != nil {
        continue
    }
    scan(s.Seg, s.Name, data)
}
```

or look a specific one up directly with `f.Section("__TEXT", "__cstring")`
(returns `nil` if absent). **Never** address sections by a hardcoded index —
that is brittle and silently wrong on any binary whose layout differs.

### 2.2 Fat binaries

```go
fat, err := macho.OpenFat(path)
if err == nil {
    defer fat.Close()
    for _, arch := range fat.Arches {
        analyse(arch.File)   // arch.File is a *macho.File
    }
    return
}
// not fat — fall back to thin
f, err := macho.Open(path)
```

App Store binaries are frequently thinned to a single slice, but developer
builds and some frameworks ship universal binaries, so both paths must work.

### 2.3 FairPlay / cryptid handling and limitation

App Store apps are DRM-wrapped with **FairPlay**: the `__TEXT` segment is
encrypted, and a load command records the encrypted byte range plus a
`cryptid` flag.

Detect it by scanning load commands for `LC_ENCRYPTION_INFO` (32-bit) or
`LC_ENCRYPTION_INFO_64` (64-bit) and reading `cryptid`:

```go
encrypted := false
for _, l := range f.Loads {
    switch e := l.(type) {
    case *macho.EncryptionInfo:      // LC_ENCRYPTION_INFO
        if e.CryptID != 0 {
            encrypted = true
        }
    case *macho.EncryptionInfo64:    // LC_ENCRYPTION_INFO_64
        if e.CryptID != 0 {
            encrypted = true
        }
    }
}
```

- `cryptid == 0` ⇒ not encrypted (developer build, resigned/decrypted dump, or
  a locally compiled binary). String extraction works normally.
- `cryptid != 0` ⇒ the `__TEXT` payload is **encrypted on disk**. Static string
  scanning of the encrypted range yields ciphertext, not secrets.

**Limitation:** MORF performs *static* analysis only. It **cannot** decrypt a
FairPlay-encrypted binary — that requires running the app on a jailbroken
device (or an equivalent runtime dump) to capture the decrypted `__TEXT`. When
MORF sees `cryptid != 0` it flags the binary as FairPlay-encrypted and reports
that in-binary secret extraction is not meaningful for that slice; `Info.plist`
metadata and unencrypted sections are still processed. Users should feed MORF a
**decrypted** `.ipa` for full binary coverage.

### 2.4 Where iOS strings live

The scanner harvests candidate strings from the sections real iOS apps carry:

| Segment/section | Contents |
|-----------------|----------|
| `__TEXT.__swift5_reflstr` and the `__swift5_*` family (`__swift5_types`, `__swift5_fieldmd`, `__swift5_typeref`, …) | Swift reflection metadata: type/field names and reflection strings. |
| `__TEXT.__objc_methname`, `__objc_classname`, `__DATA.__objc_selrefs` (selref) | Objective-C selector, method, and class names. |
| `__TEXT.__cstring` | NUL-terminated C string literals. |
| `__DATA.__cfstring` | CoreFoundation/`NSString` constant string objects (pointers into `__cstring`). |

`go-macho` already parses Swift runtime info (see its `swift_strings.go` and the
`f.GetSwift*` helpers) — **prefer those helpers** for Swift reflection strings.
For the ObjC/C/CFString sections, read the section bytes via `s.Data()` and
split on NUL (`bytes.Split(data, []byte{0})`), discarding empty/oversized runs.

> Note on the committed fixture: `ios/testdata/Fixture` is built by the **Go**
> toolchain, so its string constants land in `__TEXT.__rodata`, and it has none
> of the `__swift5_*` / `__objc_*` / `__cstring` / `__cfstring` sections above.
> It therefore validates container parsing, section enumeration, and cryptid
> detection, but Swift/ObjC extraction must be validated against a real
> Xcode-built sample. See [`ios/testdata/README.md`](../ios/testdata/README.md).

## 3. Pipeline mapping to the Android path

The iOS path reuses the Android scanning machinery wherever possible. The key
difference is **acquisition of the searchable text**: Android decompiles to
files on disk and greps them; iOS reads strings straight out of the Mach-O.

| Stage | Android (APK) — `morf/apk` | iOS (IPA) — proposed `morf/ios` |
|-------|----------------------------|---------------------------------|
| Container open | `apktool d` unpacks smali + resources | unzip `.ipa`, locate `Payload/*.app/` |
| Metadata | `apkanalyzer` → `MetaDataModel`; `AndroidManifest.xml` parsed for components/permissions/schemes | `Info.plist` (XML **or** binary) → bundle id, version, `MinimumOSVersion`, `CFBundleURLSchemes` |
| Text acquisition | recursive decompiled source tree on disk | Mach-O section bytes via `go-macho` (`__swift5_*`, `__objc_*`, `__cstring`, `__cfstring`) |
| Secret scan | `StartScan()` runs each YAML pattern with `rg` over the file tree | run the **same** `patterns/*.yml` regexes over extracted strings |
| Result model | `[]models.SecretModel` (`type`, `lineNo`, `fileLocation`, `secretString`, `confidence`) | same `[]models.SecretModel`; `fileLocation` becomes `Mach-O:<segment>.<section>`, `lineNo` is the string index/offset |
| Dedupe | `SanitizeSecrets` (unique by `SecretString`) | reuse `SanitizeSecrets` unchanged |
| Persistence / API | `models.Secrets` row; `/upload` + results map | reuse `models.Secrets`; add `platform` + `iosMetadata` fields (see `docs/api/openapi.yaml`) |

Because the `SecretModel` shape and the pattern files are shared, **secret
detection rules are written once and apply to both platforms.** Only the front
half (acquire text) is platform-specific.

## 4. iOS-specific patterns

Beyond the shared cross-platform secret regexes (`patterns/*.yml`), iOS builds
warrant a few platform-flavoured detections:

- **URL scheme / deeplink inventory** from `Info.plist`
  (`CFBundleURLTypes[].CFBundleURLSchemes[]`) — surface custom schemes that
  could be exploited, mirroring the Android deeplink inspection.
- **App Transport Security exceptions** (`NSAppTransportSecurity` →
  `NSAllowsArbitraryLoads`, per-domain exception dicts) — cleartext/allow-all
  network config.
- **Privacy usage strings** (`NS*UsageDescription`) — an inventory of the
  sensitive capabilities the app requests (camera, location, contacts, …).
- **Embedded credentials in Swift/ObjC metadata** — the shared AWS/Stripe/GCP/
  Slack/etc. regexes run over `__swift5_reflstr`, `__objc_methname`,
  `__cstring`, and `__cfstring` strings.
- **Embedded framework/dylib inventory** — enumerate `Payload/*.app/Frameworks`
  and scan each Mach-O, flagging known-risky or outdated third-party SDKs.

These live alongside the existing YAML pattern files so they participate in the
same scan loop.

## 5. macOS-runner future phase

Two capabilities are intentionally **out of scope for static Go analysis** and
are deferred to a future macOS-runner phase:

1. **FairPlay decryption.** Recovering plaintext `__TEXT` from an App Store
   binary (`cryptid != 0`) requires executing the app on Apple hardware / a
   jailbroken device and dumping decrypted memory. A dedicated macOS/iOS runner
   (or an operator supplying a pre-decrypted `.ipa`) is the only path.
2. **Deep Swift/ObjC symbolication & richer metadata** using Apple's own
   toolchain (`otool`, `nm`, `dyld_info`, `plutil`) and, longer term,
   lightweight dynamic instrumentation. These run only where the Apple
   toolchain is available.

Until then MORF's iOS coverage is: full `.ipa`/plist metadata, full Mach-O
container + section analysis, and secret scanning over all **unencrypted**
string sections — with FairPlay-encrypted slices clearly flagged rather than
silently mis-scanned.

## 6. References

- go-macho: <https://github.com/blacktop/go-macho> (see `swift_strings.go`)
- Apple `Info.plist` keys: `CFBundleExecutable`, `CFBundleIdentifier`,
  `CFBundleShortVersionString`, `MinimumOSVersion`, `CFBundleURLTypes`.
- Mach-O load commands: `LC_ENCRYPTION_INFO`, `LC_ENCRYPTION_INFO_64`.
- Test fixtures & regeneration: [`ios/testdata/README.md`](../ios/testdata/README.md).
