-- 010: add a fingerprint column to secret_findings so a stable per-value
-- identity survives AT-REST protection of the secret value.
--
--   fingerprint - keyed HMAC-SHA256 hex digest of the raw secret value
--                 (crypto.Fingerprint). Deterministic per value, so it is a
--                 stable identity for de-duplication and build-diff comparison
--                 WITHOUT storing or revealing the plaintext. The secret_string
--                 column now holds AES-256-GCM ciphertext (when a key is
--                 configured) or a masked preview, never plaintext.
--
-- The column is NULLable so rows written before this migration (and findings
-- not yet re-processed) persist without a value. An index supports fingerprint
-- lookups used by de-dup / comparison.
--
-- MySQL-8 safe: plain ALTER TABLE ADD COLUMN (no "IF NOT EXISTS", which MySQL 8
-- does not support for ADD COLUMN). This matches migrations 008/009 and is
-- idempotent via the loader's isAlreadyExistsErr handling: on a column that
-- already exists MySQL raises a benign "duplicate column name" (Error 1060)
-- which the migration runner treats as already-applied and skips, so the file
-- is safe to re-run.

ALTER TABLE secret_findings ADD COLUMN fingerprint VARCHAR(64) NULL;
CREATE INDEX idx_secret_fingerprint ON secret_findings (fingerprint);
