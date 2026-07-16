# Mobile-artifact ingestion (`morf fetch`)

MORF's scan pipeline consumes a **local filesystem path** to an `.apk`/`.ipa`.
The ingestion framework (`morf/ingest`) fetches an artifact from a remote source
into a local file so the CLI/worker can then scan it. It is exposed as the
`morf fetch <ref>` command and as the programmatic `ingest.Fetch` entry point.

An artifact is named by a **scheme-prefixed reference**. The scheme selects an
`Adapter` from a process-wide registry:

```
s3://<bucket>/<key>        object in the configured S3 store
https://<url>              pre-signed URL (SSRF-guarded, size-capped)
file://<path>  or  <path>  bare local path (validated passthrough)
appstoreconnect://<build>  vendor stub (not implemented)
testflight://<build>       vendor stub (not implemented)
xcodecloud://<build>       vendor stub (not implemented)
googleplay://<package>     vendor stub (not implemented)
```

## Command usage

```bash
# Download to a temp dir, print the local path:
morf fetch s3://my-bucket/builds/app.apk

# Download into a chosen directory:
morf fetch https://signed.example.com/app.ipa --out /tmp/artifacts

# Compose with scan (two ways):
morf scan "$(morf fetch s3://my-bucket/app.apk --out /tmp)"
morf fetch https://signed.example.com/app.apk --scan --verify
```

Flags: `--out <dir>` (destination; default a fresh temp dir), `--max-bytes N`
(per-fetch cap; `0` uses the default), `--scan` (scan the fetched file in-process
instead of printing its path), `--verify` (with `--scan`, enable live
verification).

**Exit codes:** `0` success, `1` operational error (unknown scheme, unconfigured
vendor adapter, download/SSRF/size failure). With `--scan`, the scan's own gate
exit code (`0` pass / `4` policy hit / `1` operational) is returned.

## Safety guarantees (every adapter)

- Writes only inside the destination directory.
- Enforces a byte cap and aborts an over-cap or lying-`Content-Length` download
  mid-stream. Default cap = `MORF_INGEST_MAX_BYTES` (bytes) or `500 MiB`
  (`utils.MaxAPKDownloadSize`).
- Never follows a reference to an internal/non-routable host (SSRF). The HTTPS
  adapter reuses `utils.ValidateWebhookURL` for a fail-fast up-front check and a
  dial-time `Control` hook that re-validates the *connected* IP (defeating DNS
  rebinding), and refuses HTTP 3xx redirects.

## Implemented adapters

### `s3://` — configured S3 store

Reuses the existing `storage.S3Storage` (stdlib-only, AWS SigV4-signed, no AWS
SDK). Configuration is the standard MORF S3 environment:

| Env var | Meaning |
| --- | --- |
| `MORF_S3_BUCKET` | **required** bucket name |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | **required** credentials |
| `AWS_SESSION_TOKEN` | optional session token |
| `MORF_S3_REGION` | region (default `us-east-1`) |
| `MORF_S3_ENDPOINT` | optional; empty ⇒ virtual-host AWS endpoint |
| `MORF_S3_FORCE_PATH_STYLE` | default `true` (MinIO/R2 friendly) |

Reference forms: `s3://bucket/path/app.apk` (the bucket, if present, must match
`MORF_S3_BUCKET`) or `s3://path/app.apk` (bucket taken from env). The key is
validated against path traversal (`..`). The object is `Stat`ed and rejected if
over the cap **before** any bytes are downloaded.

### `https://` (and `http://`) — pre-signed URL

For pre-signed S3/GCS URLs and artifact-store links. `http://` is refused unless
`MORF_INGEST_ALLOW_HTTP=true`. Optional integrity check: append
`?sha256=<hex>` (query) or `#sha256=<hex>` (fragment) — the digest is stripped
from the request URL and verified after download; a mismatch deletes the file
and fails.

### `file://` / bare path — local passthrough

Validates that the path exists, is a regular file, and ends in `.apk`/`.ipa`,
then returns it unchanged. Lets `morf fetch ./app.apk` and existing local-path
callers use the same entry point as remote schemes.

## Vendor stub adapters (not implemented)

These are **registered** so a reference returns a precise, actionable error
(wrapping `ingest.ErrAdapterNotConfigured`) naming the required configuration,
rather than an "unknown scheme" error. The `Adapter` interface, registration,
and error surface exist now; only the vendor auth body is TODO. They are stubs
because their auth (vendor JWT / OAuth2 service accounts) cannot be exercised in
tests without live credentials — half-built, untestable auth is deliberately not
shipped.

### `appstoreconnect://` and `testflight://`

Apple's App Store Connect API authenticates with an **ES256 JWT** signed by a
`.p8` private key issued in App Store Connect. TestFlight builds are fetched
through the same API/JWT and then resolved to a build.

| Env var | Meaning |
| --- | --- |
| `MORF_ASC_ISSUER_ID` | App Store Connect issuer id |
| `MORF_ASC_KEY_ID` | key id of the `.p8` API key |
| `MORF_ASC_PRIVATE_KEY` | the `.p8` ES256 private key (PEM) |

**Intended flow:** mint a short-lived ES256 JWT (`iss`, `iat`, `exp`, `aud:
appstoreconnect-v1`) signed with the `.p8`; call the App Store Connect API to
resolve the build id in the reference to a downloadable artifact; stream it
through the shared size-capped writer.

### `xcodecloud://`

Uses the App Store Connect JWT above **plus** an Xcode Cloud CI product/build
identifier.

| Env var | Meaning |
| --- | --- |
| `MORF_ASC_ISSUER_ID` / `MORF_ASC_KEY_ID` / `MORF_ASC_PRIVATE_KEY` | ASC JWT (as above) |
| `MORF_XCODE_CLOUD_PRODUCT_ID` | Xcode Cloud product id |

**Intended flow:** authenticate as above; query the Xcode Cloud CI endpoints for
the product/build artifacts; download the selected artifact.

### `googleplay://`

The Google Play Developer API authenticates with **OAuth2 using a service-account
JSON key**.

| Env var | Meaning |
| --- | --- |
| `MORF_GOOGLE_PLAY_SA_JSON` | path to (or contents of) the service-account JSON |

**Intended flow:** exchange the service-account key for an OAuth2 access token
(`androidpublisher` scope); resolve the package/track/build in the reference; if
a signed artifact is retrievable, stream it through the shared size-capped
writer.

## Follow-ups (out of scope for the first cut)

- A `POST /ingest {ref}` HTTP endpoint that calls `ingest.Fetch` then
  `store.Put` + enqueue, keeping the API symmetric with `morf fetch`.
- Migrating `utils/slack.go` to a `slack://` adapter (it already has a host
  allowlist + capped writer), retiring its `*gin.Context` coupling.
