-- Add new JSON columns for components with their full data including deeplinks
SET @activities_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'activities');
SET @services_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'services');
SET @providers_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'content_providers');
SET @receivers_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'broadcast_receivers');

SET @activities_old_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'names_of_activities');
SET @services_old_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'names_of_services');
SET @providers_old_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'names_of_content_providers');
SET @receivers_old_exists = (SELECT COUNT(*) FROM information_schema.columns 
    WHERE table_name = 'secrets' AND column_name = 'names_of_broadcast_receivers');

SET @idx_activities_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secrets' AND index_name = 'idx_activities');
SET @idx_activities_host_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secrets' AND index_name = 'idx_activities_host');

-- Add new columns if they don't exist
SET @add_activities = IF(@activities_exists = 0, 
    'ALTER TABLE secrets ADD COLUMN activities JSON NOT NULL CHECK (JSON_VALID(activities)) DEFAULT (\'[]\')',
    'SELECT 1');
SET @add_services = IF(@services_exists = 0,
    'ALTER TABLE secrets ADD COLUMN services JSON NOT NULL CHECK (JSON_VALID(services)) DEFAULT (\'[]\')',
    'SELECT 1');
SET @add_providers = IF(@providers_exists = 0,
    'ALTER TABLE secrets ADD COLUMN content_providers JSON NOT NULL CHECK (JSON_VALID(content_providers)) DEFAULT (\'[]\')',
    'SELECT 1');
SET @add_receivers = IF(@receivers_exists = 0,
    'ALTER TABLE secrets ADD COLUMN broadcast_receivers JSON NOT NULL CHECK (JSON_VALID(broadcast_receivers)) DEFAULT (\'[]\')',
    'SELECT 1');

PREPARE stmt FROM @add_activities;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_services;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_providers;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_receivers;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Drop old columns if they exist
SET @drop_activities = IF(@activities_old_exists = 1,
    'ALTER TABLE secrets DROP COLUMN names_of_activities',
    'SELECT 1');
SET @drop_services = IF(@services_old_exists = 1,
    'ALTER TABLE secrets DROP COLUMN names_of_services',
    'SELECT 1');
SET @drop_providers = IF(@providers_old_exists = 1,
    'ALTER TABLE secrets DROP COLUMN names_of_content_providers',
    'SELECT 1');
SET @drop_receivers = IF(@receivers_old_exists = 1,
    'ALTER TABLE secrets DROP COLUMN names_of_broadcast_receivers',
    'SELECT 1');

PREPARE stmt FROM @drop_activities;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @drop_services;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @drop_providers;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @drop_receivers;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add indexes if they don't exist
SET @add_idx_activities = IF(@idx_activities_exists = 0,
    'ALTER TABLE secrets ADD INDEX idx_activities ((CAST(activities->>\'$[*].intentFilters[*].data[*].scheme\' AS CHAR(36))))',
    'SELECT 1');
SET @add_idx_activities_host = IF(@idx_activities_host_exists = 0,
    'ALTER TABLE secrets ADD INDEX idx_activities_host ((CAST(activities->>\'$[*].intentFilters[*].data[*].host\' AS CHAR(36))))',
    'SELECT 1');

PREPARE stmt FROM @add_idx_activities;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

PREPARE stmt FROM @add_idx_activities_host;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
