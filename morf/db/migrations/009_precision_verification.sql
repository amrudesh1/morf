-- 009: add precision / verification / compliance columns to secret_findings so
-- the enriched fields on models.SecretFinding (and models.SecretModel) round-trip
-- to the normalized store.
--
--   score               - deterministic precision score (detect.ApplyPrecision)
--   tier                - precision classification: "keep" | "info"
--   verification_status - live-verification outcome: "active" | "inactive" |
--                         "unknown" | "unchecked" (verify.VerifySecrets)
--   masvs_id            - OWASP MASVS control id attributed from the owning pattern
--
-- All columns are NULLable so rows written before this migration (and findings
-- not yet processed by the precision/verification stages) persist without a value.
--
-- MySQL-8 safe: plain ALTER TABLE ADD COLUMN (no "IF NOT EXISTS", which MySQL 8
-- does not support for ADD COLUMN). This matches migration 008's style and is
-- idempotent via the loader's isAlreadyExistsErr handling: on a column that
-- already exists MySQL raises a benign "duplicate column name" (Error 1060)
-- which the migration runner treats as already-applied and skips, so the file is
-- safe to re-run.

ALTER TABLE secret_findings ADD COLUMN score DOUBLE NULL;
ALTER TABLE secret_findings ADD COLUMN tier VARCHAR(16) NULL;
ALTER TABLE secret_findings ADD COLUMN verification_status VARCHAR(16) NULL;
ALTER TABLE secret_findings ADD COLUMN masvs_id VARCHAR(32) NULL;
