-- Normalize database schema for better query performance
-- This migration creates normalized tables and migrates data from the flat secrets table

-- Step 1: Create package_data table
-- id is BIGINT UNSIGNED to match models.PackageData (embeds gorm.Model, uint id)
-- and so a future FK from secrets_new.package_data_id can reference it.
CREATE TABLE IF NOT EXISTS package_data (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    apk_hash VARCHAR(64) UNIQUE NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    version_code VARCHAR(50),
    version_name VARCHAR(100),
    compile_sdk_version VARCHAR(50),
    sdk_version VARCHAR(50),
    target_sdk VARCHAR(50),
    min_sdk VARCHAR(50),
    support_screens JSON,
    densities JSON,
    native_code JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_package_name (package_name),
    INDEX idx_created_at (created_at),
    INDEX idx_package_created (package_name, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 2: Create new secrets table structure (temporary name)
-- id/deleted_at match models.Secret (embeds gorm.Model): id is BIGINT UNSIGNED
-- and a soft-delete deleted_at column + index must exist so GORM's soft delete
-- and AutoMigrate reconciliation do not diverge from this DDL.
CREATE TABLE IF NOT EXISTS secrets_new (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    package_data_id BIGINT UNSIGNED NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    apk_hash VARCHAR(64) UNIQUE NOT NULL,
    apk_version VARCHAR(50),
    secret_count INT DEFAULT 0,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at DATETIME(3) NULL,
    INDEX idx_apk_hash (apk_hash),
    INDEX idx_file_name (file_name),
    INDEX idx_created_at (created_at),
    INDEX idx_package_data_id (package_data_id),
    INDEX idx_secrets_new_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 3: Create secret_findings table
CREATE TABLE IF NOT EXISTS secret_findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    secret_id BIGINT UNSIGNED NOT NULL,
    type VARCHAR(100) NOT NULL,
    line_no INT NOT NULL,
    file_location VARCHAR(500) NOT NULL,
    secret_type VARCHAR(100) NOT NULL,
    secret_string TEXT NOT NULL,
    secret_confidence ENUM('high', 'medium', 'low') NOT NULL DEFAULT 'low',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_secret_id (secret_id),
    INDEX idx_secret_type (secret_type),
    INDEX idx_secret_confidence (secret_confidence),
    INDEX idx_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 4: Create activities table
CREATE TABLE IF NOT EXISTS activities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    secret_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    intent_filters JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 5: Create services table
CREATE TABLE IF NOT EXISTS services (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    secret_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 6: Create content_providers table
CREATE TABLE IF NOT EXISTS content_providers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    secret_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 7: Create broadcast_receivers table
CREATE TABLE IF NOT EXISTS broadcast_receivers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    secret_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Note: Data migration will be handled by migrate_data.go script
-- Foreign keys will be added after data migration is complete

