-- Add unique index on apk_hash to prevent duplicate scans
-- This migration ensures that duplicate detection works correctly by APK hash, not filename

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.statistics 
    WHERE table_name = 'secrets' AND index_name = 'idx_apk_hash');

-- Add unique index if it doesn't exist
SET @add_idx = IF(@idx_exists = 0,
    'ALTER TABLE secrets ADD UNIQUE INDEX idx_apk_hash (apk_hash)',
    'SELECT 1');

PREPARE stmt FROM @add_idx;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

