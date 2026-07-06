-- Add indexes for optimized query performance
-- This migration adds indexes on common query patterns

-- Check if indexes already exist before creating
SET @idx_package_name_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'package_data' AND index_name = 'idx_package_name');
SET @idx_package_created_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'package_data' AND index_name = 'idx_package_created');
SET @idx_secret_type_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secret_findings' AND index_name = 'idx_secret_type');
SET @idx_secret_confidence_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secret_findings' AND index_name = 'idx_secret_confidence');
SET @idx_type_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secret_findings' AND index_name = 'idx_type');
SET @idx_file_name_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secrets_new' AND index_name = 'idx_file_name');
SET @idx_package_data_id_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secrets_new' AND index_name = 'idx_package_data_id');

-- Add indexes on package_data table
SET @add_idx_package_name = IF(@idx_package_name_exists = 0,
    'ALTER TABLE package_data ADD INDEX idx_package_name (package_name)',
    'SELECT 1');
SET @add_idx_package_created = IF(@idx_package_created_exists = 0,
    'ALTER TABLE package_data ADD INDEX idx_package_created (package_name, created_at DESC)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_package_name;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_package_created;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add indexes on secret_findings table
SET @add_idx_secret_type = IF(@idx_secret_type_exists = 0,
    'ALTER TABLE secret_findings ADD INDEX idx_secret_type (secret_type)',
    'SELECT 1');
SET @add_idx_secret_confidence = IF(@idx_secret_confidence_exists = 0,
    'ALTER TABLE secret_findings ADD INDEX idx_secret_confidence (secret_confidence)',
    'SELECT 1');
SET @add_idx_type = IF(@idx_type_exists = 0,
    'ALTER TABLE secret_findings ADD INDEX idx_type (type)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_secret_type;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_secret_confidence;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_type;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add full-text index on secret_string (MySQL 8.0+)
SET @ft_idx_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secret_findings' AND index_name = 'idx_secret_string_ft');
SET @add_ft_idx = IF(@ft_idx_exists = 0,
    'ALTER TABLE secret_findings ADD FULLTEXT INDEX idx_secret_string_ft (secret_string)',
    'SELECT 1');

PREPARE stmt FROM @add_ft_idx;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add indexes on secrets_new table
SET @add_idx_file_name = IF(@idx_file_name_exists = 0,
    'ALTER TABLE secrets_new ADD INDEX idx_file_name (file_name)',
    'SELECT 1');
SET @add_idx_package_data_id = IF(@idx_package_data_id_exists = 0,
    'ALTER TABLE secrets_new ADD INDEX idx_package_data_id (package_data_id)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_file_name;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_package_data_id;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add indexes on component tables
-- Activities
SET @idx_activities_name_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'activities' AND index_name = 'idx_name');
SET @idx_activities_exported_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'activities' AND index_name = 'idx_exported');

SET @add_idx_activities_name = IF(@idx_activities_name_exists = 0,
    'ALTER TABLE activities ADD INDEX idx_name (name(255))',
    'SELECT 1');
SET @add_idx_activities_exported = IF(@idx_activities_exported_exists = 0,
    'ALTER TABLE activities ADD INDEX idx_exported (exported)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_activities_name;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_activities_exported;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Services
SET @idx_services_name_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'services' AND index_name = 'idx_name');
SET @idx_services_exported_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'services' AND index_name = 'idx_exported');

SET @add_idx_services_name = IF(@idx_services_name_exists = 0,
    'ALTER TABLE services ADD INDEX idx_name (name(255))',
    'SELECT 1');
SET @add_idx_services_exported = IF(@idx_services_exported_exists = 0,
    'ALTER TABLE services ADD INDEX idx_exported (exported)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_services_name;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_services_exported;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Content Providers
SET @idx_providers_name_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'content_providers' AND index_name = 'idx_name');
SET @idx_providers_exported_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'content_providers' AND index_name = 'idx_exported');

SET @add_idx_providers_name = IF(@idx_providers_name_exists = 0,
    'ALTER TABLE content_providers ADD INDEX idx_name (name(255))',
    'SELECT 1');
SET @add_idx_providers_exported = IF(@idx_providers_exported_exists = 0,
    'ALTER TABLE content_providers ADD INDEX idx_exported (exported)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_providers_name;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_providers_exported;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Broadcast Receivers
SET @idx_receivers_name_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'broadcast_receivers' AND index_name = 'idx_name');
SET @idx_receivers_exported_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'broadcast_receivers' AND index_name = 'idx_exported');

SET @add_idx_receivers_name = IF(@idx_receivers_name_exists = 0,
    'ALTER TABLE broadcast_receivers ADD INDEX idx_name (name(255))',
    'SELECT 1');
SET @add_idx_receivers_exported = IF(@idx_receivers_exported_exists = 0,
    'ALTER TABLE broadcast_receivers ADD INDEX idx_exported (exported)',
    'SELECT 1');

PREPARE stmt FROM @add_idx_receivers_name;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_receivers_exported;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

