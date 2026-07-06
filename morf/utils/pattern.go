/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	alf "github.com/spf13/afero"
	"gopkg.in/yaml.v2"
)

// Pattern represents a single pattern
type Pattern struct {
	Name       string `json:"name" yaml:"name"`
	Regex      string `json:"regex" yaml:"regex"`
	Confidence string `json:"confidence" yaml:"confidence"`
	Enabled    bool   `json:"enabled" yaml:"enabled"`
}

// PatternFile represents a pattern file
type PatternFile struct {
	Filename string    `json:"filename"`
	Patterns []Pattern `json:"patterns"`
}

// PatternListResponse represents the response for listing patterns
type PatternListResponse struct {
	Files []PatternFile `json:"files"`
	Total int           `json:"total"`
}

// GetPatternsDir returns the patterns directory path. It honours the
// MORF_PATTERNS_DIR environment variable (the same name used by the apk track)
// and falls back to the historical "/app/patterns" default.
func GetPatternsDir() string {
	if dir := strings.TrimSpace(os.Getenv("MORF_PATTERNS_DIR")); dir != "" {
		return dir
	}
	return "/app/patterns"
}

// resolvePatternPath validates a user-supplied pattern filename and returns the
// absolute on-disk path inside GetPatternsDir(). It strips any directory
// components (filepath.Base), enforces a .yaml/.yml extension allowlist, and
// verifies the cleaned path cannot escape the patterns directory, defeating
// path-traversal (e.g. "../../etc/passwd"). All pattern CRUD must route the
// caller-supplied filename through this resolver before touching the FS.
func resolvePatternPath(filename string) (string, error) {
	base := filepath.Base(filename)
	if base == "." || base == ".." || base == string(filepath.Separator) || strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("invalid pattern filename: %q", filename)
	}

	lower := strings.ToLower(base)
	if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return "", fmt.Errorf("pattern filename must have a .yaml or .yml extension: %q", filename)
	}

	dir, err := filepath.Abs(GetPatternsDir())
	if err != nil {
		return "", fmt.Errorf("failed to resolve patterns directory: %w", err)
	}

	full := filepath.Join(dir, base)
	rel, err := filepath.Rel(dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("pattern filename escapes patterns directory: %q", filename)
	}

	return full, nil
}

// ListPatternFiles lists all pattern files
func ListPatternFiles() ([]PatternFile, error) {
	patternsDir := GetPatternsDir()
	files := ReadDir(GetAppFS(), patternsDir)

	var patternFiles []PatternFile

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			filePath := filepath.Join(patternsDir, file.Name())
			patterns, err := LoadPatternsFromFile(filePath)
			if err != nil {
				log.WithFields(log.Fields{
					"file":  file.Name(),
					"error": err.Error(),
				}).Warn("Failed to load pattern file")
				continue
			}

			patternFiles = append(patternFiles, PatternFile{
				Filename: file.Name(),
				Patterns: patterns,
			})
		}
	}

	return patternFiles, nil
}

// LoadPatternsFromFile loads patterns from a YAML file
func LoadPatternsFromFile(filePath string) ([]Pattern, error) {
	// Row 078: fail loudly when the underlying read errors. Previously the read
	// error was swallowed and nil bytes were unmarshalled into an empty slice,
	// which let callers (Add/Update/Delete/EnablePattern) save an empty file back
	// over a transiently-unreadable one, destroying the existing patterns.
	yamlFile, err := ReadFile(GetAppFS(), filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pattern file %s: %w", filePath, err)
	}

	var secretPatterns struct {
		Patterns []struct {
			Pattern struct {
				Name       string `yaml:"name"`
				Regex      string `yaml:"regex"`
				Confidence string `yaml:"confidence"`
				// Row 069: decode Enabled as a pointer so an explicit
				// `enabled: false` survives the load/save round-trip; only a
				// truly-absent (nil) value defaults to enabled.
				Enabled *bool `yaml:"enabled"`
			} `yaml:"pattern"`
		} `yaml:"patterns"`
	}

	if err := yaml.Unmarshal(yamlFile, &secretPatterns); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	patterns := make([]Pattern, 0, len(secretPatterns.Patterns))
	for _, p := range secretPatterns.Patterns {
		// Default to enabled only when the flag was omitted (nil); preserve an
		// explicit false.
		enabled := true
		if p.Pattern.Enabled != nil {
			enabled = *p.Pattern.Enabled
		}
		patterns = append(patterns, Pattern{
			Name:       p.Pattern.Name,
			Regex:      p.Pattern.Regex,
			Confidence: p.Pattern.Confidence,
			Enabled:    enabled,
		})
	}

	return patterns, nil
}

// SavePatternsToFile saves patterns to a YAML file and invalidates metadata cache
func SavePatternsToFile(filePath string, patterns []Pattern) error {
	// Convert to YAML structure
	yamlPatterns := struct {
		Patterns []struct {
			Pattern Pattern `yaml:"pattern"`
		} `yaml:"patterns"`
	}{
		Patterns: make([]struct {
			Pattern Pattern `yaml:"pattern"`
		}, len(patterns)),
	}

	for i, pattern := range patterns {
		yamlPatterns.Patterns[i].Pattern = pattern
	}

	data, err := yaml.Marshal(&yamlPatterns)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}

	// Write to file via the same afero FS used for reads (Row 090). Route the
	// caller-supplied name through resolvePatternPath to contain path traversal.
	fullPath, err := resolvePatternPath(filePath)
	if err != nil {
		return err
	}
	if err := alf.WriteFile(GetAppFS(), fullPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	// Invalidate metadata cache when patterns are updated
	// This ensures cached metadata doesn't use outdated patterns
	if err := InvalidateAllMetadataCache(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to invalidate metadata cache after pattern update")
		// Don't fail the operation if cache invalidation fails
	}

	return nil
}

// ValidatePattern validates a pattern regex
func ValidatePattern(pattern Pattern) error {
	if pattern.Name == "" {
		return fmt.Errorf("pattern name is required")
	}

	if pattern.Regex == "" {
		return fmt.Errorf("pattern regex is required")
	}

	// Validate regex
	if _, err := regexp.Compile(pattern.Regex); err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}

	if pattern.Confidence != "high" && pattern.Confidence != "low" && pattern.Confidence != "medium" {
		return fmt.Errorf("confidence must be 'high', 'medium', or 'low'")
	}

	return nil
}

// TestPattern tests a pattern against sample text
func TestPattern(pattern Pattern, sampleText string) (bool, []string, error) {
	regex, err := regexp.Compile(pattern.Regex)
	if err != nil {
		return false, nil, fmt.Errorf("invalid regex: %v", err)
	}

	matches := regex.FindAllString(sampleText, -1)
	return len(matches) > 0, matches, nil
}

// GetPatternFileContent returns the raw content of a pattern file
func GetPatternFileContent(filename string) ([]byte, error) {
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return nil, err
	}
	return ReadFile(GetAppFS(), fullPath)
}

// UpdatePatternFile updates a pattern file
func UpdatePatternFile(filename string, patterns []Pattern) error {
	// Validate all patterns
	for _, pattern := range patterns {
		if err := ValidatePattern(pattern); err != nil {
			return fmt.Errorf("invalid pattern %s: %v", pattern.Name, err)
		}
	}

	return SavePatternsToFile(filename, patterns)
}

// DeletePatternFile deletes a pattern file
func DeletePatternFile(filename string) error {
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return err
	}
	// Route the remove through the same afero FS used for reads (Row 090)
	return GetAppFS().Remove(fullPath)
}

// CreatePatternFile creates a new pattern file
func CreatePatternFile(filename string, patterns []Pattern) error {
	// Validate filename
	if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
		filename = filename + ".yaml"
	}

	// Check if file exists via the same afero FS used for reads (Row 090).
	// resolvePatternPath also contains any path-traversal in the filename.
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return err
	}
	if exists, _ := alf.Exists(GetAppFS(), fullPath); exists {
		return fmt.Errorf("file already exists: %s", filename)
	}

	// Validate all patterns
	for _, pattern := range patterns {
		if err := ValidatePattern(pattern); err != nil {
			return fmt.Errorf("invalid pattern %s: %v", pattern.Name, err)
		}
	}

	return SavePatternsToFile(filename, patterns)
}

// AddPatternToFile adds a pattern to an existing file
func AddPatternToFile(filename string, pattern Pattern) error {
	// Validate pattern
	if err := ValidatePattern(pattern); err != nil {
		return err
	}

	// Load existing patterns
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return err
	}
	existingPatterns, err := LoadPatternsFromFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to load existing patterns: %v", err)
	}

	// Check if pattern already exists
	for _, p := range existingPatterns {
		if p.Name == pattern.Name {
			return fmt.Errorf("pattern with name '%s' already exists", pattern.Name)
		}
	}

	// Add new pattern
	existingPatterns = append(existingPatterns, pattern)

	// Save back
	return SavePatternsToFile(filename, existingPatterns)
}

// UpdatePatternInFile updates a pattern in an existing file
func UpdatePatternInFile(filename string, patternName string, updatedPattern Pattern) error {
	// Validate updated pattern
	if err := ValidatePattern(updatedPattern); err != nil {
		return err
	}

	// Load existing patterns
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return err
	}
	existingPatterns, err := LoadPatternsFromFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to load existing patterns: %v", err)
	}

	// Find and update pattern
	found := false
	for i, p := range existingPatterns {
		if p.Name == patternName {
			existingPatterns[i] = updatedPattern
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("pattern '%s' not found", patternName)
	}

	// Save back
	return SavePatternsToFile(filename, existingPatterns)
}

// DeletePatternFromFile deletes a pattern from an existing file
func DeletePatternFromFile(filename string, patternName string) error {
	// Load existing patterns
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return err
	}
	existingPatterns, err := LoadPatternsFromFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to load existing patterns: %v", err)
	}

	// Remove pattern
	newPatterns := make([]Pattern, 0, len(existingPatterns))
	for _, p := range existingPatterns {
		if p.Name != patternName {
			newPatterns = append(newPatterns, p)
		}
	}

	if len(newPatterns) == len(existingPatterns) {
		return fmt.Errorf("pattern '%s' not found", patternName)
	}

	// Save back
	return SavePatternsToFile(filename, newPatterns)
}

// EnableDisablePattern enables or disables a pattern
func EnableDisablePattern(filename string, patternName string, enabled bool) error {
	// Load existing patterns
	fullPath, err := resolvePatternPath(filename)
	if err != nil {
		return err
	}
	existingPatterns, err := LoadPatternsFromFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to load existing patterns: %v", err)
	}

	// Find and update pattern
	found := false
	for i, p := range existingPatterns {
		if p.Name == patternName {
			existingPatterns[i].Enabled = enabled
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("pattern '%s' not found", patternName)
	}

	// Save back
	return SavePatternsToFile(filename, existingPatterns)
}
