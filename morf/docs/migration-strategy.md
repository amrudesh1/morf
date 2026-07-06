# Zero-Downtime Database Migration Strategy

## Overview
This document outlines the strategy for migrating from the flat `secrets` table schema to the normalized schema without downtime.

## Migration Phases

### Phase 1: Preparation (Pre-Migration)
1. **Backup Production Database**
   - Create full database backup
   - Verify backup integrity
   - Store backup in secure location

2. **Run Migration on Staging**
   - Copy production data to staging
   - Run migration scripts
   - Validate data integrity
   - Test application with new schema
   - Measure performance improvements

3. **Prepare Rollback Plan**
   - Document rollback procedure
   - Test rollback on staging
   - Prepare rollback scripts

### Phase 2: Schema Creation (Low-Traffic Window)
1. **Create New Tables**
   - Run `004_normalize_schema.sql` to create new tables
   - This does not affect existing tables
   - No downtime required

2. **Add Indexes**
   - Run `005_add_indexes.sql` to add indexes
   - Indexes created in background (non-blocking)
   - No downtime required

### Phase 3: Data Migration (Low-Traffic Window)
1. **Migrate Existing Data**
   - Run `migrate_data.go` script
   - Migrates data in batches
   - Can be run during low-traffic hours
   - Application continues to use old schema

2. **Validate Migration**
   - `BackfillNormalized()` (in `db/migrations/migrate_data.go`) is idempotent —
     re-running it after the migration backfills any rows that were missed and is
     the canonical integrity check (it surfaces gaps between the flat `secrets`
     table and the normalized tables).
   - Validate with direct SQL count comparisons, e.g. confirm the number of source
     rows in `secrets` matches the number of backfilled rows in the normalized
     tables (`package_data` / `metadata` / per-secret rows).
   - Verify foreign key relationships are intact (no orphaned child rows).
   - Test query performance against the new indexes (`005_add_indexes.sql`).

### Phase 4: Application Update (Blue-Green Deployment)
1. **Deploy New Application Code**
   - Deploy application with normalized schema support
   - Application writes to both old and new tables (dual-write)
   - Application reads from new tables
   - Monitor for errors

2. **Gradual Cutover**
   - Start with 10% of traffic to new code
   - Monitor metrics and errors
   - Gradually increase to 100%
   - Keep old code ready for rollback

### Phase 5: Verification (Post-Migration)
1. **Monitor Application**
   - Monitor error rates
   - Check query performance
   - Verify data consistency
   - Monitor database performance

2. **Validate Data**
   - Compare record counts
   - Spot-check data accuracy
   - Run performance tests
   - Verify all queries work correctly

### Phase 6: Cleanup (After Validation Period)
1. **Remove Old Schema Support**
   - After 7 days of successful operation
   - Remove dual-write code
   - Remove old table access code
   - Keep old table for 30 days as backup

2. **Archive Old Table**
   - After 30 days, archive old `secrets` table
   - Store archive for compliance
   - Remove from active database

## Rollback Procedure

If issues are detected during migration:

1. **Immediate Rollback**
   - Switch traffic back to old application code
   - Application reads from old `secrets` table
   - New tables remain but are not used

2. **Data Rollback** (if needed)
   - There is no automated rollback function; rollback is performed by manually
     running the inverse SQL. Drop the normalized tables created by
     `004_normalize_schema.sql` (child tables first to respect foreign keys):
     ```sql
     DROP TABLE IF EXISTS broadcast_receivers;
     DROP TABLE IF EXISTS content_providers;
     DROP TABLE IF EXISTS services;
     DROP TABLE IF EXISTS activities;
     DROP TABLE IF EXISTS secret_findings;
     DROP TABLE IF EXISTS secrets_new;
     DROP TABLE IF EXISTS package_data;
     ```
   - Because the migration is additive (backfill into new tables only) and the flat
     `secrets` table is never mutated by the migration, dropping the normalized
     tables fully reverts the schema. The original `secrets` table remains intact
     and authoritative.

3. **Investigation**
   - Investigate root cause
   - Fix issues
   - Retry migration after fixes

## Performance Targets

- **Query by APK hash**: < 10ms (from ~100ms)
- **Query by package name**: < 50ms (from ~500ms)
- **Query by secret type**: < 100ms (from ~1000ms)
- **Full-text search**: < 200ms (new capability)

## Monitoring

During migration, monitor:
- Database connection pool usage
- Query execution times
- Error rates
- Application latency
- Database CPU and memory usage
- Disk I/O

## Success Criteria

Migration is considered successful when:
- All data migrated successfully
- No data loss or corruption
- Query performance meets targets
- Application functions correctly
- No increase in error rates
- All tests pass

## Timeline

- **Preparation**: 1 day
- **Schema Creation**: 1 hour (during low-traffic window)
- **Data Migration**: 2-4 hours (depending on data size)
- **Application Update**: 1 day (blue-green deployment)
- **Verification**: 7 days (monitoring period)
- **Cleanup**: 1 day (after validation period)

**Total Estimated Time**: 10-12 days

## Risk Mitigation

1. **Data Loss**: Full backup before migration
2. **Performance Degradation**: Test on staging first
3. **Application Errors**: Blue-green deployment with gradual rollout
4. **Migration Failure**: Rollback procedure ready
5. **Data Corruption**: Validation tests after migration

## Communication Plan

1. Notify team 1 week before migration
2. Schedule migration during low-traffic window
3. Provide status updates during migration
4. Post-migration summary report

