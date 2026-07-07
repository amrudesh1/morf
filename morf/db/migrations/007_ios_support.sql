-- iOS support: add a platform discriminator to secrets_new and create the
-- ios_metadata table that holds iOS-specific package metadata (the iOS analogue
-- of the Android component tables).
--
-- The ADD COLUMN is made idempotent via an information_schema.columns guard (the
-- same pattern used in 002/003/005/006): it is only issued when the column does
-- not already exist, so re-running the migration is a no-op and does not rely on
-- db.go's isAlreadyExistsErr swallowing of a duplicate-column error.

-- secrets_new.platform: "android" (default, backward-compatible) or "ios".
SET @secrets_platform_exists = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'secrets_new' AND column_name = 'platform');
SET @add_secrets_platform = IF(@secrets_platform_exists = 0,
    'ALTER TABLE secrets_new ADD COLUMN platform VARCHAR(20) NOT NULL DEFAULT ''android''',
    'SELECT 1');
PREPARE stmt FROM @add_secrets_platform;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Index platform so per-platform reads (WHERE platform = 'ios') stay cheap.
-- Guarded on information_schema.statistics so re-runs are a no-op.
SET @secrets_platform_idx_exists = (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'secrets_new' AND index_name = 'idx_platform');
SET @add_secrets_platform_idx = IF(@secrets_platform_idx_exists = 0,
    'ALTER TABLE secrets_new ADD INDEX idx_platform (platform)',
    'SELECT 1');
PREPARE stmt FROM @add_secrets_platform_idx;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ios_metadata: one row per scanned IPA, linked to secrets_new via secret_id.
-- id/secret_id are BIGINT UNSIGNED to match models.IOSMetadata (embeds
-- gorm.Model, uint id) and secrets_new.id, mirroring the activities/services
-- component tables. JSON columns hold the variable-length extracted data
-- (architectures, url_schemes, entitlements, frameworks, ats_exceptions).
CREATE TABLE IF NOT EXISTS ios_metadata (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    secret_id BIGINT UNSIGNED NOT NULL,
    bundle_identifier VARCHAR(255),
    bundle_version VARCHAR(255),
    deployment_target VARCHAR(255),
    executable_name VARCHAR(255),
    architectures JSON,
    is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    url_schemes JSON,
    entitlements JSON,
    frameworks JSON,
    ats_exceptions JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at DATETIME(3) NULL,
    INDEX idx_secret_id (secret_id),
    INDEX idx_bundle_identifier (bundle_identifier),
    INDEX idx_ios_metadata_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
