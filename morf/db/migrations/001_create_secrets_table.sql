-- Bootstrap the legacy "secrets" table for fresh databases that run the SQL-file
-- migration path WITHOUT GORM AutoMigrate (MORF_DISABLE_AUTO_MIGRATE=true or the
-- standalone `morf migrate` command). Migrations 002 (ADD COLUMN ...) and 003
-- (dedup + UNIQUE INDEX on apk_hash) ALTER this table, so it must exist first.
--
-- Columns mirror models.Secrets and its embedded structs (gorm.Model,
-- MetaDataModel [embeddedPrefix meta_], PackageDataModel [embeddedPrefix pkg_]).
-- id/deleted_at follow gorm.Model (id BIGINT UNSIGNED, soft-delete deleted_at).
-- apk_hash is created WITHOUT a unique index here on purpose — migration 003 owns
-- the dedup-then-UNIQUE-INDEX step. CREATE TABLE IF NOT EXISTS keeps this idempotent
-- and a no-op when AutoMigrate already created the table.
CREATE TABLE IF NOT EXISTS secrets (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME(3) NULL,
    updated_at DATETIME(3) NULL,
    deleted_at DATETIME(3) NULL,

    file_name VARCHAR(255),
    apk_hash VARCHAR(64),
    apk_version VARCHAR(50),
    secret_model JSON,

    -- Embedded MetaDataModel (prefix meta_)
    meta_file_name VARCHAR(255),
    meta_file_size INT,
    meta_dex_size INT,
    meta_arsc_size INT,

    -- Embedded MetaDataModel.AndroidManifest (still under meta_)
    meta_package_name VARCHAR(255),
    meta_version_code VARCHAR(50),
    meta_number_of_activities INT,
    meta_number_of_services INT,
    meta_number_of_content_providers INT,
    meta_number_of_broadcast_receivers INT,
    meta_activities JSON,
    meta_services JSON,
    meta_content_providers JSON,
    meta_broadcast_receivers JSON,
    meta_uses_permissions JSON,
    meta_uses_library JSON,
    meta_uses_feature JSON,
    meta_permissions JSON,
    meta_permissions_protection_level JSON,
    meta_uses_min_sdk_version VARCHAR(50),
    meta_uses_target_sdk_version VARCHAR(50),
    meta_uses_max_sdk_version VARCHAR(50),

    -- Embedded MetaDataModel.CertificateDatas (prefix cert_ -> meta_cert_)
    meta_cert_file_name VARCHAR(255),
    meta_cert_sign_algorithm VARCHAR(100),
    meta_cert_sign_algorithm_oid VARCHAR(100),
    meta_cert_start_date VARCHAR(100),
    meta_cert_end_date VARCHAR(100),
    meta_cert_public_key_md5 VARCHAR(64),
    meta_cert_cert_base64_md5 VARCHAR(64),
    meta_cert_cert_md5 VARCHAR(64),
    meta_cert_version INT,
    meta_cert_issuer_name VARCHAR(255),
    meta_cert_subject_name VARCHAR(255),

    -- Embedded MetaDataModel.ResourceData (still under meta_)
    meta_locale JSON,
    meta_number_of_string_resource INT,
    meta_png_drawables INT,
    meta_nine_patch_drawables INT,
    meta_jpg_drawables INT,
    meta_gif_drawables INT,
    meta_xml_drawables INT,
    meta_different_drawables INT,
    meta_ldpi_drawables INT,
    meta_mdpi_drawables INT,
    meta_hdpi_drawables INT,
    meta_xhdpi_drawables INT,
    meta_xxhdpi_drawables INT,
    meta_xxxhdpi_drawables INT,
    meta_nodpi_drawables INT,
    meta_tvdpi_drawables INT,
    meta_unspecified_dpi_drawables INT,
    meta_raw_resources INT,
    meta_menu INT,
    meta_layouts INT,
    meta_different_layouts INT,

    -- Embedded MetaDataModel.FileDigest (still under meta_)
    meta_sha256 VARCHAR(64),
    meta_sha1 VARCHAR(40),
    meta_md5 VARCHAR(32),

    -- Embedded PackageDataModel (prefix pkg_)
    pkg_package_data_id INT,
    pkg_apk_hash VARCHAR(64),
    pkg_package_name VARCHAR(255),
    pkg_version_code VARCHAR(50),
    pkg_version_name VARCHAR(100),
    pkg_compile_sdk_version VARCHAR(50),
    pkg_sdk_version VARCHAR(50),
    pkg_target_sdk VARCHAR(50),
    pkg_min_sdk VARCHAR(50),
    pkg_support_screens JSON,
    pkg_densities JSON,
    pkg_native_code JSON,

    -- Top-level component JSON columns (also reconciled by migration 002)
    activities JSON,
    services JSON,
    content_providers JSON,
    broadcast_receivers JSON,

    INDEX idx_secrets_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
