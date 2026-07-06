-- Add lossless component security fields so services, broadcast_receivers, and
-- content_providers round-trip their manifest data the same way activities do
-- (which already has intent_filters). Mirrors models.Service / models.BroadcastReceiver /
-- models.ContentProvider gorm tags.
--
-- Idempotent via an information_schema.columns guard (the pattern used in
-- 002/003/005): each ADD COLUMN is only issued when the column does not already
-- exist, so re-running the migration is a no-op. This does not rely on the
-- isAlreadyExistsErr swallowing of a duplicate-column error in db.go.

-- Existence checks for every column this migration adds.
SET @services_intent_filters_exists = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'services' AND column_name = 'intent_filters');
SET @receivers_intent_filters_exists = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'broadcast_receivers' AND column_name = 'intent_filters');
SET @providers_intent_filters_exists = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'content_providers' AND column_name = 'intent_filters');
SET @providers_authorities_exists = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'content_providers' AND column_name = 'authorities');
SET @providers_grant_uri_exists = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'content_providers' AND column_name = 'grant_uri_permissions');

-- services.intent_filters
SET @add_services_intent_filters = IF(@services_intent_filters_exists = 0,
    'ALTER TABLE services ADD COLUMN intent_filters JSON',
    'SELECT 1');
PREPARE stmt FROM @add_services_intent_filters;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- broadcast_receivers.intent_filters
SET @add_receivers_intent_filters = IF(@receivers_intent_filters_exists = 0,
    'ALTER TABLE broadcast_receivers ADD COLUMN intent_filters JSON',
    'SELECT 1');
PREPARE stmt FROM @add_receivers_intent_filters;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- content_providers.intent_filters
SET @add_providers_intent_filters = IF(@providers_intent_filters_exists = 0,
    'ALTER TABLE content_providers ADD COLUMN intent_filters JSON',
    'SELECT 1');
PREPARE stmt FROM @add_providers_intent_filters;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- content_providers.authorities
SET @add_providers_authorities = IF(@providers_authorities_exists = 0,
    'ALTER TABLE content_providers ADD COLUMN authorities JSON',
    'SELECT 1');
PREPARE stmt FROM @add_providers_authorities;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- content_providers.grant_uri_permissions
SET @add_providers_grant_uri = IF(@providers_grant_uri_exists = 0,
    'ALTER TABLE content_providers ADD COLUMN grant_uri_permissions BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt FROM @add_providers_grant_uri;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
