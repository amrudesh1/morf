-- 008: fix a schema/model mismatch that silently discarded ALL scan findings.
--
-- migration 004 created secret_findings and the component tables (activities,
-- services, content_providers, broadcast_receivers) with only a created_at
-- column. But their Go models embed gorm.Model, which carries CreatedAt,
-- UpdatedAt AND DeletedAt. On INSERT, GORM writes updated_at, so every insert
-- failed with "Unknown column 'updated_at' in 'field list'" (Error 1054) and the
-- whole secret-persistence transaction (in db.insertSecretsSync) rolled back —
-- so a scan could detect dozens of secrets yet persist ZERO, and /api/secrets
-- (and the UI's DB-backed views) showed nothing. GORM's soft-delete queries also
-- reference deleted_at.
--
-- Add the missing updated_at + deleted_at columns to those five tables. This is
-- idempotent: on a table/column that already exists MySQL raises a benign
-- "duplicate column name" which the migration runner (isAlreadyExistsErr)
-- treats as already-applied and skips, so the file is safe to re-run and safe on
-- databases created before or after this migration.

ALTER TABLE secret_findings ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER TABLE secret_findings ADD COLUMN deleted_at DATETIME(3) NULL;
ALTER TABLE secret_findings ADD INDEX idx_secret_findings_deleted_at (deleted_at);

ALTER TABLE activities ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER TABLE activities ADD COLUMN deleted_at DATETIME(3) NULL;
ALTER TABLE activities ADD INDEX idx_activities_deleted_at (deleted_at);

ALTER TABLE services ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER TABLE services ADD COLUMN deleted_at DATETIME(3) NULL;
ALTER TABLE services ADD INDEX idx_services_deleted_at (deleted_at);

ALTER TABLE content_providers ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER TABLE content_providers ADD COLUMN deleted_at DATETIME(3) NULL;
ALTER TABLE content_providers ADD INDEX idx_content_providers_deleted_at (deleted_at);

ALTER TABLE broadcast_receivers ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER TABLE broadcast_receivers ADD COLUMN deleted_at DATETIME(3) NULL;
ALTER TABLE broadcast_receivers ADD INDEX idx_broadcast_receivers_deleted_at (deleted_at);
