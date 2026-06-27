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

// GetPatternsDir returns the patterns directory path
func GetPatternsDir() string {
	return "/app/patterns"
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
	yamlFile := ReadFile(GetAppFS(), filePath)

	var secretPatterns struct {
		Patterns []struct {
			Pattern Pattern `yaml:"pattern"`
		} `yaml:"patterns"`
	}

	if err := yaml.Unmarshal(yamlFile, &secretPatterns); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	patterns := make([]Pattern, 0, len(secretPatterns.Patterns))
	for _, p := range secretPatterns.Patterns {
		pattern := p.Pattern
		// Default to enabled if not specified
		if !pattern.Enabled && pattern.Name != "" {
			pattern.Enabled = true
		}
		patterns = append(patterns, pattern)
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

	// Write to file
	fullPath := filepath.Join(GetPatternsDir(), filePath)
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
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
	fullPath := filepath.Join(GetPatternsDir(), filename)
	return ReadFile(GetAppFS(), fullPath), nil
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
	fullPath := filepath.Join(GetPatternsDir(), filename)
	return os.Remove(fullPath)
}

// CreatePatternFile creates a new pattern file
func CreatePatternFile(filename string, patterns []Pattern) error {
	// Validate filename
	if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
		filename = filename + ".yaml"
	}

	// Check if file exists
	fullPath := filepath.Join(GetPatternsDir(), filename)
	if _, err := os.Stat(fullPath); err == nil {
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
	fullPath := filepath.Join(GetPatternsDir(), filename)
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
	fullPath := filepath.Join(GetPatternsDir(), filename)
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
	fullPath := filepath.Join(GetPatternsDir(), filename)
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
	fullPath := filepath.Join(GetPatternsDir(), filename)
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
