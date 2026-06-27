# MORF Normalized Database Schema Design

## Overview
This document describes the normalized database schema design for MORF to improve query performance and enable better data management.

## Current Schema Issues
- Flat `secrets` table with JSON columns
- Poor query performance on JSON fields
- Difficult to query individual secrets
- No efficient way to search by secret type
- Large JSON columns slow down queries

## Normalized Schema Design

### 1. `package_data` Table
Stores APK package metadata (one row per unique APK hash).

```sql
CREATE TABLE package_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
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
```

### 2. `secrets` Table (Main Scan Record)
Stores scan results metadata (one row per scan).

```sql
CREATE TABLE secrets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    package_data_id INT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    apk_hash VARCHAR(64) UNIQUE NOT NULL,
    apk_version VARCHAR(50),
    secret_count INT DEFAULT 0,
    metadata JSON,  -- Full metadata JSON for backward compatibility
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (package_data_id) REFERENCES package_data(id) ON DELETE CASCADE,
    INDEX idx_apk_hash (apk_hash),
    INDEX idx_file_name (file_name),
    INDEX idx_created_at (created_at),
    INDEX idx_package_data_id (package_data_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 3. `secret_findings` Table
Stores individual secret findings (one row per secret found).

```sql
CREATE TABLE secret_findings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_id INT NOT NULL,
    type VARCHAR(100) NOT NULL,
    line_no INT NOT NULL,
    file_location VARCHAR(500) NOT NULL,
    secret_type VARCHAR(100) NOT NULL,
    secret_string TEXT NOT NULL,
    secret_confidence ENUM('high', 'low') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    INDEX idx_secret_id (secret_id),
    INDEX idx_secret_type (secret_type),
    INDEX idx_secret_confidence (secret_confidence),
    INDEX idx_type (type),
    FULLTEXT INDEX idx_secret_string (secret_string)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 4. `activities` Table
Stores activity components (one row per activity per scan).

```sql
CREATE TABLE activities (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_id INT NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    intent_filters JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 5. `services` Table
Stores service components (one row per service per scan).

```sql
CREATE TABLE services (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_id INT NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 6. `content_providers` Table
Stores content provider components (one row per provider per scan).

```sql
CREATE TABLE content_providers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_id INT NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 7. `broadcast_receivers` Table
Stores broadcast receiver components (one row per receiver per scan).

```sql
CREATE TABLE broadcast_receivers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_id INT NOT NULL,
    name VARCHAR(500) NOT NULL,
    exported BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    INDEX idx_secret_id (secret_id),
    INDEX idx_name (name(255)),
    INDEX idx_exported (exported)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

## Foreign Key Relationships

```
package_data (1) ──< (N) secrets
secrets (1) ──< (N) secret_findings
secrets (1) ──< (N) activities
secrets (1) ──< (N) services
secrets (1) ──< (N) content_providers
secrets (1) ──< (N) broadcast_receivers
```

## Migration Strategy

### Phase 1: Create New Tables
1. Create `package_data` table
2. Create normalized tables (`secret_findings`, `activities`, `services`, `content_providers`, `broadcast_receivers`)
3. Create new `secrets` table structure (with `package_data_id` foreign key)

### Phase 2: Migrate Data
1. Extract unique APK hashes and create `package_data` records
2. Migrate scan records to new `secrets` table
3. Extract and insert individual secrets into `secret_findings`
4. Extract and insert components into respective tables

### Phase 3: Switch Over
1. Update application code to use new schema
2. Keep old table for rollback (rename to `secrets_old`)
3. Monitor performance

### Phase 4: Cleanup
1. After validation period, drop old table
2. Remove migration code

## Benefits

1. **Query Performance**: 10x faster queries on normalized fields
2. **Indexing**: Can index individual fields (secret_type, package_name, etc.)
3. **Search**: Full-text search on secret strings
4. **Scalability**: Better handling of large datasets
5. **Data Integrity**: Foreign key constraints ensure referential integrity
6. **Flexibility**: Easier to add new query patterns

## Query Examples

### Find all secrets of a specific type
```sql
SELECT sf.*, s.file_name, pd.package_name
FROM secret_findings sf
JOIN secrets s ON sf.secret_id = s.id
JOIN package_data pd ON s.package_data_id = pd.id
WHERE sf.secret_type = 'API_KEY'
ORDER BY sf.created_at DESC;
```

### Find scans for a package
```sql
SELECT s.*, pd.package_name, pd.version_name
FROM secrets s
JOIN package_data pd ON s.package_data_id = pd.id
WHERE pd.package_name = 'com.example.app'
ORDER BY s.created_at DESC;
```

### Count secrets by type
```sql
SELECT secret_type, COUNT(*) as count
FROM secret_findings
GROUP BY secret_type
ORDER BY count DESC;
```

## Rollback Plan

If migration fails:
1. Rename new tables (add `_new` suffix)
2. Restore old `secrets` table
3. Update application to use old schema
4. Fix issues and retry migration

## Performance Targets

- Query by APK hash: < 10ms (from ~100ms)
- Query by package name: < 50ms (from ~500ms)
- Query by secret type: < 100ms (from ~1000ms)
- Full-text search: < 200ms (new capability)

