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

// Package config centralises MORF's runtime configuration. Historically each
// package read its own os.Getenv values and re-implemented the same env
// parsers (envFloat/envInt/envDuration/...) locally, producing config sprawl
// and subtly divergent parsing rules.
//
// This package provides:
//   - a single Config struct describing every MORF_* / DATABASE_URL /
//     REDIS_URL / AWS_* / JIRA_* / SLACK_* value the backend consumes,
//   - Load(), which reads the environment once into that struct,
//   - Validate(), which fails fast on missing REQUIRED values, and
//   - one shared set of env helpers (float/int/int64/duration/bool/string)
//     that the rest of the codebase can point its local helpers at, so the
//     duplicated parsers can be deleted without changing behaviour.
//
// Migration to this package is intentionally incremental: leaf packages may
// keep reading os.Getenv for now, but they MUST route their parsing through
// the shared helpers here rather than re-implementing them.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Config is the effective runtime configuration, loaded once from the
// environment. Zero values mean "unset" for string fields; numeric/bool/
// duration fields carry their documented defaults after Load().
type Config struct {
	// --- Core datastores (REQUIRED when the relevant subsystem is enabled) ---

	// DatabaseURL is the MySQL DSN/URL (env DATABASE_URL). Empty disables the DB layer.
	DatabaseURL string
	// RedisURL is the Redis connection URL (env REDIS_URL). Used by both the
	// job queue and the cache; when empty, callers fall back to their own
	// localhost default (behaviour preserved for now).
	RedisURL string

	// --- HTTP / Gin server (main.go) ---

	// GinMode mirrors MORF_GIN_MODE ("debug" enables gin.DebugMode).
	GinMode string
	// TrustedProxies is the raw MORF_TRUSTED_PROXIES value (comma-separated CIDRs).
	TrustedProxies string
	// CORSAllowedOrigins is the raw MORF_CORS_ALLOWED_ORIGINS value.
	CORSAllowedOrigins string

	// --- Auth / routing (router/) ---

	// RequireAPIKey mirrors MORF_REQUIRE_API_KEY (default true; only "false" disables).
	RequireAPIKey bool
	// EnforceScopes mirrors MORF_ENFORCE_SCOPES ("true" enables).
	EnforceScopes bool

	// --- Storage (storage/, MORF_S3_* + AWS_*) ---

	StorageBackend  string // MORF_STORAGE_BACKEND (local/s3)
	UploadDir       string // MORF_UPLOAD_DIR
	S3Endpoint      string // MORF_S3_ENDPOINT
	S3Bucket        string // MORF_S3_BUCKET
	S3Region        string // MORF_S3_REGION
	AWSAccessKeyID  string // AWS_ACCESS_KEY_ID
	AWSSecretKey    string // AWS_SECRET_ACCESS_KEY
	AWSSessionToken string // AWS_SESSION_TOKEN

	// --- Scanner / tools (apk/, utils/) ---

	ToolsDir    string // MORF_TOOLS_DIR
	PatternsDir string // MORF_PATTERNS_DIR

	// --- Integrations ---

	JiraLink     string // JIRA_LINK
	SlackChannel string // SLACK_CHANNEL
}

// Load reads the environment once and returns the effective Config. It does
// not mutate global state and does not validate; call Validate() afterwards.
func Load() *Config {
	return &Config{
		DatabaseURL:        StringDefault("DATABASE_URL", ""),
		RedisURL:           StringDefault("REDIS_URL", ""),
		GinMode:            StringDefault("MORF_GIN_MODE", ""),
		TrustedProxies:     StringDefault("MORF_TRUSTED_PROXIES", ""),
		CORSAllowedOrigins: StringDefault("MORF_CORS_ALLOWED_ORIGINS", ""),
		// Default true, fail-closed: only the literal "false" disables it.
		RequireAPIKey:   os.Getenv("MORF_REQUIRE_API_KEY") != "false",
		EnforceScopes:   os.Getenv("MORF_ENFORCE_SCOPES") == "true",
		StorageBackend:  StringDefault("MORF_STORAGE_BACKEND", ""),
		UploadDir:       StringDefault("MORF_UPLOAD_DIR", ""),
		S3Endpoint:      StringDefault("MORF_S3_ENDPOINT", ""),
		S3Bucket:        StringDefault("MORF_S3_BUCKET", ""),
		S3Region:        StringDefault("MORF_S3_REGION", ""),
		AWSAccessKeyID:  StringDefault("AWS_ACCESS_KEY_ID", ""),
		AWSSecretKey:    StringDefault("AWS_SECRET_ACCESS_KEY", ""),
		AWSSessionToken: StringDefault("AWS_SESSION_TOKEN", ""),
		ToolsDir:        StringDefault("MORF_TOOLS_DIR", ""),
		PatternsDir:     StringDefault("MORF_PATTERNS_DIR", ""),
		JiraLink:        StringDefault("JIRA_LINK", ""),
		SlackChannel:    StringDefault("SLACK_CHANNEL", ""),
	}
}

// Validate fails fast on missing REQUIRED values for the requested subsystems.
//
//	requireDB    - DATABASE_URL must be set (persistence-backed modes).
//	requireQueue - REDIS_URL must be set (queue/cache-backed modes: api, worker,
//	               server). Callers that can degrade gracefully pass false.
//
// It returns a non-nil error describing all missing values, or nil when the
// configuration is usable.
func (c *Config) Validate(requireDB, requireQueue bool) error {
	var missing []string
	if requireDB && strings.TrimSpace(c.DatabaseURL) == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if requireQueue && strings.TrimSpace(c.RedisURL) == "" {
		missing = append(missing, "REDIS_URL")
	}
	if len(missing) == 0 {
		return nil
	}
	return &ValidationError{Missing: missing}
}

// ValidationError describes required configuration values that were not set.
type ValidationError struct {
	Missing []string
}

func (e *ValidationError) Error() string {
	return "config: missing required environment variables: " + strings.Join(e.Missing, ", ")
}

// LogSummary logs a single effective-config summary line at startup with
// secrets masked. It never prints raw credentials or connection strings.
func (c *Config) LogSummary() {
	log.WithFields(log.Fields{
		"database_url":         maskURL(c.DatabaseURL),
		"redis_url":            maskURL(c.RedisURL),
		"gin_mode":             defaultStr(c.GinMode, "release"),
		"cors_allowed_origins": defaultStr(c.CORSAllowedOrigins, "(default)"),
		"require_api_key":      c.RequireAPIKey,
		"enforce_scopes":       c.EnforceScopes,
		"storage_backend":      defaultStr(c.StorageBackend, "local"),
		"s3_bucket":            defaultStr(c.S3Bucket, "-"),
		"s3_region":            defaultStr(c.S3Region, "-"),
		"aws_access_key_id":    maskSecret(c.AWSAccessKeyID),
		"aws_secret":           maskSecret(c.AWSSecretKey),
		"tools_dir":            defaultStr(c.ToolsDir, "(default)"),
		"patterns_dir":         defaultStr(c.PatternsDir, "(default)"),
		"jira_link":            defaultStr(c.JiraLink, "-"),
		"slack_channel":        defaultStr(c.SlackChannel, "-"),
	}).Info("Effective MORF configuration")
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// maskSecret redacts a secret value, keeping only a hint that it is set.
func maskSecret(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return "***set***"
}

// maskURL masks credentials in a URL-like connection string. If a userinfo
// section ("user:pass@") is present its password is redacted; otherwise the
// whole value is treated as sensitive and reported only as set/unset.
func maskURL(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	// Redact any password in a scheme://user:pass@host form.
	if at := strings.LastIndex(v, "@"); at > 0 {
		prefix := v[:at]
		host := v[at:]
		if schemeSep := strings.Index(prefix, "://"); schemeSep >= 0 {
			scheme := prefix[:schemeSep+3]
			creds := prefix[schemeSep+3:]
			if colon := strings.Index(creds, ":"); colon >= 0 {
				return scheme + creds[:colon] + ":***" + host
			}
			return scheme + creds + host
		}
		// No scheme; user:pass@host (e.g. some MySQL DSNs).
		if colon := strings.Index(prefix, ":"); colon >= 0 {
			return prefix[:colon] + ":***" + host
		}
	}
	return "***set***"
}

// ---------------------------------------------------------------------------
// Shared env helpers.
//
// These are the single source of truth for env parsing. Two families exist to
// preserve the historically divergent behaviours across packages:
//   - the plain helpers (Float/Int/Int64/Duration) accept any parseable value,
//   - the *Positive variants additionally require a value > 0, matching the
//     worker/ and storage/ helpers that rejected non-positive input.
//
// All helpers TrimSpace the raw value and fall back to def on unset/invalid.
// ---------------------------------------------------------------------------

// StringDefault returns the env var (untrimmed) or def when it is unset.
// It preserves os.Getenv semantics for callers that expect the raw value.
func StringDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

// Float parses a float from env, returning def when unset/blank/invalid.
func Float(name string, def float64) float64 {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			return v
		}
	}
	return def
}

// FloatPositive parses a float from env, returning def unless the value parses
// and is strictly positive.
func FloatPositive(name string, def float64) float64 {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && v > 0 {
			return v
		}
	}
	return def
}

// Int parses an int from env, returning def when unset/blank/invalid.
func Int(name string, def int) int {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return v
		}
	}
	return def
}

// IntPositive parses an int from env, returning def unless the value parses and
// is strictly positive.
func IntPositive(name string, def int) int {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 {
			return v
		}
	}
	return def
}

// Int64Positive parses an int64 from env, returning def unless the value parses
// and is strictly positive.
func Int64Positive(name string, def int64) int64 {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && v > 0 {
			return v
		}
	}
	return def
}

// Duration parses a Go duration from env, returning def when unset/blank/invalid.
func Duration(name string, def time.Duration) time.Duration {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
			return v
		}
	}
	return def
}

// DurationPositive parses a Go duration from env, returning def unless the value
// parses and is strictly positive.
func DurationPositive(name string, def time.Duration) time.Duration {
	if s, ok := os.LookupEnv(name); ok {
		if v, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && v > 0 {
			return v
		}
	}
	return def
}

// LogFormat returns the desired logrus output format, read from MORF_LOG_FORMAT
// and normalized (trimmed + lowercased). It returns def when the var is unset or
// blank. Callers (main.go) map "json" to a JSONFormatter and anything else to the
// default text formatter, so structured JSON logging can be turned on in
// production (log aggregators) without a code change while local runs stay text.
func LogFormat(def string) string {
	if s, ok := os.LookupEnv("MORF_LOG_FORMAT"); ok {
		if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
			return v
		}
	}
	return def
}

// Bool parses a boolean from env, returning def when unset/blank/invalid.
func Bool(name string, def bool) bool {
	if s, ok := os.LookupEnv(name); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return def
		}
		if v, err := strconv.ParseBool(s); err == nil {
			return v
		}
	}
	return def
}
