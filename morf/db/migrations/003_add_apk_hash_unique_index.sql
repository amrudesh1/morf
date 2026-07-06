-- Add unique index on apk_hash to prevent duplicate scans
-- This migration ensures that duplicate detection works correctly by APK hash, not filename

SET @idx_exists = (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_name = 'secrets' AND index_name = 'idx_apk_hash');

-- De-duplicate existing rows on apk_hash BEFORE adding the unique index.
-- The pre-dedup state this migration targets can contain duplicate apk_hash rows;
-- without this step `ADD UNIQUE INDEX` fails with a duplicate-entry error, and
-- because db.go swallows per-statement migration errors with a Warnf the dedup
-- index would silently never be created. Keep the lowest id per apk_hash and drop
-- the later duplicates. Self-join DELETE is naturally idempotent; it is additionally
-- guarded to run only when the unique index is not yet present.
SET @dedup = IF(@idx_exists = 0,
    'DELETE s1 FROM secrets s1 INNER JOIN secrets s2 ON s1.apk_hash = s2.apk_hash AND s1.id > s2.id',
    'SELECT 1');

PREPARE stmt FROM @dedup;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add unique index if it doesn't exist
SET @add_idx = IF(@idx_exists = 0,
    'ALTER TABLE secrets ADD UNIQUE INDEX idx_apk_hash (apk_hash)',
    'SELECT 1');

PREPARE stmt FROM @add_idx;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

