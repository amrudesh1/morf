# iOS scanning test fixtures

This directory holds small, **license-clean** fixtures used to smoke-test
MORF's iOS (Mach-O / `.ipa`) parsing path. Nothing here is a real credential
or a redistributed third-party app — everything is generated locally from the
Go source in `fixturesrc/`.

## Files

| File | What it is |
|------|------------|
| `fixturesrc/main.go` | A tiny Go program that embeds two **fake** secret strings. Cross-compiled, it becomes a real arm64 Mach-O. |
| `gen_fixture.sh` | Regenerates `Fixture` and `fixture.ipa` from `fixturesrc/`. |
| `Fixture` | The built arm64 Mach-O binary (thin, `EXECUTE`, CPU `AARCH64`). |
| `fixture.ipa` | A synthetic `.ipa` (a zip) wrapping `Fixture` + a minimal XML `Info.plist`. |

## Planted (fake) secrets

The fixture intentionally contains two well-known, non-functional strings so
that both the regex secret scanner and the Mach-O string-extraction path have
deterministic hits to assert against:

| String | Matches pattern | Notes |
|--------|-----------------|-------|
| `AKIAIOSFODNN7EXAMPLE` | `AWS API Key` (`AKIA[0-9A-Z]{16}`) | AWS's own published, non-functional example access key ID. |
| `sk_live_MASKED_FIXTURE` | `Stripe API Key` (`sk_live_[0-9a-zA-Z]{24}`) | The 24-char body is fabricated; it maps to no real Stripe account. |

Both strings live in the `__TEXT.__rodata` section of the compiled binary
(Go's linker places program string constants there; it does not emit the
`__cstring` / `__objc_*` / `__swift5_*` sections a Clang/Swift toolchain would —
see the limitation note below).

## How it was generated

The binary is produced by a native or cross Go build targeting Apple's
CPU/OS family, and the `.ipa` is just a zip with the canonical
`Payload/<App>.app/` layout:

```bash
# From this directory:
./gen_fixture.sh
```

`gen_fixture.sh` runs, in effect:

```bash
# 1. Real arm64 Mach-O (Go emits Mach-O for GOOS=darwin).
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o Fixture ./fixturesrc

# 2. Synthetic IPA tree:
#      Payload/Fixture.app/Fixture      (the binary)
#      Payload/Fixture.app/Info.plist   (XML plist, see below)
zip -r -X fixture.ipa Payload
```

### `Info.plist` contents

A minimal but valid XML property list carrying the fields MORF's iOS metadata
path is documented to read:

| Key | Value |
|-----|-------|
| `CFBundleExecutable` | `Fixture` |
| `CFBundleIdentifier` | `com.morf.fixture` |
| `CFBundleShortVersionString` | `1.0` |
| `MinimumOSVersion` | `15.0` |
| `CFBundleURLTypes[0].CFBundleURLSchemes[0]` | `morffixture` (for deeplink inspection) |

## Verifying the fixture

The binary is a genuine thin arm64 Mach-O and can be inspected with `go-macho`,
`otool`, or `file`:

```
$ file Fixture
Fixture: Mach-O 64-bit executable arm64

$ strings -a Fixture | grep -E 'AKIA|sk_live_'
AKIAIOSFODNN7EXAMPLE...
sk_live_MASKED_FIXTURE...
```

With `go-macho`: `macho.Open("Fixture")` succeeds, `f.Sections` enumerates the
segments/sections shown above, and iterating the load commands finds **no**
`LC_ENCRYPTION_INFO[_64]` (so `cryptid == 0`, i.e. **not** FairPlay-encrypted).

## Limitations (read before relying on this fixture)

- **Not a Swift/ObjC binary.** It is built by the Go toolchain, so it does not
  contain the `__swift5_reflstr` / `__swift5_*` or `__objc_methname` /
  `__objc_selref` / `__objc_classname` / `__DATA.__cfstring` sections that a
  real Xcode-built app has. It exercises Mach-O container parsing, section
  enumeration, cryptid detection, and generic string scanning — **not**
  Swift-reflection or ObjC-metadata extraction. Those paths need a real
  Xcode-built sample (or a hand-assembled Mach-O) to test end to end.
- **Thin, not fat.** `Fixture` is a single-arch (arm64) Mach-O, so it is opened
  with `macho.Open`. The fat/universal path (`macho.OpenFat` → `.Arches`) is not
  covered by this fixture.
- **Never FairPlay-encrypted.** Locally built binaries are never App Store
  DRM-wrapped, so `cryptid` is always `0` here. The encrypted-`cryptid`
  code path cannot be exercised with a self-generated fixture.

See `../../docs/IOS_SCANNING.md` for the full architecture and how these
limitations map onto the scanning pipeline.
