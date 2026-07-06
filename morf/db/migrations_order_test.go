/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package db

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestMigrationNamesAscending guards MT-1 / DB-1..3: the loader applies SQL
// migrations in the order of migrationNames, and the order is load-bearing (001
// creates the legacy table 002/003 ALTER). An out-of-order entry would silently
// mis-sequence schema changes.
func TestMigrationNamesAscending(t *testing.T) {
	sorted := make([]string, len(migrationNames))
	copy(sorted, migrationNames)
	sort.Strings(sorted)
	for i := range migrationNames {
		if migrationNames[i] != sorted[i] {
			t.Fatalf("migrationNames not ascending at index %d: %q (sorted would be %q)", i, migrationNames[i], sorted[i])
		}
	}
}

// TestMigrationFilesExist asserts every registered migration has a backing file
// on disk, so a typo'd or missing file is caught in CI rather than at deploy.
func TestMigrationFilesExist(t *testing.T) {
	for _, name := range migrationNames {
		p := filepath.Join("migrations", name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("migration %q is registered but its file is missing: %v", name, err)
		}
	}
}

// TestMigrationsIncludeBaseAndComponentFields pins the two migrations added by
// this remediation: 001 (fresh-DB base table for the DISABLE_AUTO_MIGRATE path,
// DB-3) and 006 (lossless component-security columns, M-1).
func TestMigrationsIncludeBaseAndComponentFields(t *testing.T) {
	required := []string{
		"001_create_secrets_table.sql",
		"006_component_security_fields.sql",
	}
	for _, want := range required {
		found := false
		for _, name := range migrationNames {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected migration %q to be registered in migrationNames", want)
		}
	}
}
