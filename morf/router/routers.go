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

package router

import (
	"encoding/json"
	goerrors "errors"
	"fmt"
	"morf/apk"
	"morf/auth"
	"morf/db"
	"morf/metrics"
	"morf/models"
	"morf/queue"
	"morf/report"
	"morf/storage"
	"morf/utils"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// queueDepthThreshold is read once at init from MORF_QUEUE_DEPTH_THRESHOLD,
// falling back to 1000. This makes adaptive backpressure tunable without code
// changes.
var queueDepthThreshold = envIntDefault("MORF_QUEUE_DEPTH_THRESHOLD", 1000)

// maxUploadSize bounds a single uploaded APK (500 MiB). It is enforced up front
// via Content-Length and a MaxBytesReader on the request body so an over-large
// upload is aborted mid-read instead of after fully spooling to disk (UPLOAD-1).
const maxUploadSize = 500 << 20

// maxBulkUploadSize bounds the TOTAL request body of a bulk upload. Individual
// files are still capped at maxUploadSize; this just keeps the multipart parse
// from spooling an unbounded body to disk.
const maxBulkUploadSize = 2 << 30

// maxDLQPageSize caps the DLQ listing page. Each listed job costs one serial
// HGETALL (the queue package exposes no batch/pipeline fetch), so this bounds
// the number of Redis round-trips per /dlq request (DLQ-1).
const maxDLQPageSize = 100

// uploadStore is the lazily-initialised artifact store for uploaded APKs.
// getUploadStore initialises it once from the environment; on failure it logs
// and returns nil so handlers can fail the request rather than crash.
var (
	uploadStoreOnce sync.Once
	uploadStore     storage.Storage
)

// isSupportedPackageExt reports whether a filename carries a supported mobile
// package extension. Android (.apk) and iOS (.ipa) are both accepted; the check
// is case-insensitive so "App.IPA" is admitted the same as "app.ipa".
func isSupportedPackageExt(filename string) bool {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".apk", ".ipa":
		return true
	default:
		return false
	}
}

// packageFileType maps an uploaded package's extension to the ScanJob.FileType
// platform discriminator ("apk"/"ipa"). It assumes the extension has already
// passed isSupportedPackageExt; an unrecognised extension falls back to "apk"
// so a job is never enqueued with an empty platform.
func packageFileType(filename string) string {
	if strings.ToLower(filepath.Ext(filename)) == ".ipa" {
		return "ipa"
	}
	return "apk"
}

func getUploadStore() storage.Storage {
	uploadStoreOnce.Do(func() {
		if s, err := storage.NewFromEnv(); err == nil {
			uploadStore = s
		} else {
			log.Errorf("storage init failed: %v", err)
		}
	})
	return uploadStore
}

// checkDatabaseStatus verifies database connection and configuration
func checkDatabaseStatus() error {
	if !db.DatabaseRequired {
		return fmt.Errorf("database operations are disabled - please check DATABASE_URL environment variable")
	}

	if db.GormDB == nil {
		return fmt.Errorf("database connection is not initialized - please check your database configuration")
	}

	// Verify database connection is still alive
	sqlDB, err := db.GormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %v", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("database connection lost: %v", err)
	}

	return nil
}

// toolsHealthCache memoizes the result of checkExternalToolsHealth so /health
// doesn't fork java/aapt/ripgrep subprocesses on every probe (4× exec per
// request was visibly slow under k8s-style polling).
var (
	toolsHealthMu     sync.Mutex
	toolsHealthCached gin.H
	toolsHealthAt     time.Time
	toolsHealthTTL    = 60 * time.Second
)

// checkExternalToolsHealth checks if external tools are available and working.
// Result is cached for toolsHealthTTL to avoid spawning subprocesses on every
// /health probe.
func checkExternalToolsHealth() gin.H {
	toolsHealthMu.Lock()
	if toolsHealthCached != nil && time.Since(toolsHealthAt) < toolsHealthTTL {
		// Clone the cached payload so we can stamp cached=true (and the age)
		// without mutating the shared map, which was built on the miss path
		// with "cached": false hard-coded.
		out := make(gin.H, len(toolsHealthCached)+1)
		for k, v := range toolsHealthCached {
			out[k] = v
		}
		out["cached"] = true
		out["age"] = time.Since(toolsHealthAt).String()
		toolsHealthMu.Unlock()
		return out
	}
	toolsHealthMu.Unlock()

	tools := gin.H{
		"status": "healthy",
		"checks": make(map[string]string),
		"cached": false,
		"ttl":    toolsHealthTTL.String(),
	}

	checks := make(map[string]string)

	check := func(name string, args ...string) {
		_, err := utils.ExecuteCommandWithTimeout(5*time.Second, args[0], args[1:]...)
		if err != nil {
			tools["status"] = "degraded"
			checks[name] = "unavailable: " + err.Error()
		} else {
			checks[name] = "available"
		}
	}

	toolsDir := os.Getenv("MORF_TOOLS_DIR")
	if toolsDir == "" {
		toolsDir = "/app/tools"
	}
	check("java", "java", "-version")
	check("apktool", "java", "-jar", filepath.Join(toolsDir, "apktool.jar"), "--version")
	check("aapt", "aapt", "version")
	check("ripgrep", "rg", "--version")

	tools["checks"] = checks

	toolsHealthMu.Lock()
	toolsHealthCached = tools
	toolsHealthAt = time.Now()
	toolsHealthMu.Unlock()

	return tools
}

func InitRouters(router *gin.RouterGroup) *gin.RouterGroup {
	// Add correlation ID middleware for request tracing.
	// CORS is governed exclusively by the engine-level gin-contrib/cors
	// allow-list configured in main.go (cors.New(config)).
	router.Use(CorrelationIDMiddleware())

	// Add metrics middleware for HTTP request tracking
	router.Use(MetricsMiddleware())

	// Prometheus metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		health := gin.H{
			"message":   "ok",
			"timestamp": time.Now().Unix(),
			"status":    "healthy",
		}

		// Check database
		if err := checkDatabaseStatus(); err != nil {
			health["database"] = "unhealthy"
			health["status"] = "degraded"
			health["database_error"] = err.Error()
		} else {
			health["database"] = "healthy"
		}

		// Check Redis
		if queue.GetQueue() == nil {
			health["redis"] = "unavailable"
			health["status"] = "degraded"
		} else if utils.IsBreakerOpen("redis") {
			// SC-1: the "redis" circuit breaker is open — Redis has been failing
			// repeatedly and is being shed. Report degraded regardless of a
			// single probe outcome.
			health["redis"] = "unhealthy"
			health["status"] = "degraded"
			health["redis_error"] = "circuit breaker open"
		} else {
			// Test Redis connection by getting queue depth
			_, err := queue.GetQueue().GetQueueDepth()
			if err != nil {
				health["redis"] = "unhealthy"
				health["status"] = "degraded"
				health["redis_error"] = err.Error()
			} else {
				health["redis"] = "healthy"
			}
		}

		// Check external tools (apktool, java, aapt, ripgrep)
		toolsHealth := checkExternalToolsHealth()
		health["tools"] = toolsHealth
		if toolsHealth["status"] != "healthy" {
			health["status"] = "degraded"
		}

		statusCode := http.StatusOK
		if health["status"] == "degraded" {
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, health)
	})

	// Readiness probe endpoint
	router.GET("/ready", func(c *gin.Context) {
		// Check if system is ready to accept requests
		ready := true
		checks := gin.H{}

		// Check Redis. SC-1: readiness reflects BOTH a live probe (GetQueueDepth)
		// AND the "redis" circuit breaker state. If the breaker is open, Redis has
		// been failing repeatedly and this pod should stop receiving traffic even
		// if a single probe happens to succeed — so K8s routes around a pod whose
		// Redis is effectively down.
		if queue.GetQueue() == nil {
			ready = false
			checks["redis"] = "not initialized"
		} else if utils.IsBreakerOpen("redis") {
			ready = false
			checks["redis"] = "circuit breaker open"
		} else if _, err := queue.GetQueue().GetQueueDepth(); err != nil {
			ready = false
			checks["redis"] = "unhealthy"
		} else {
			checks["redis"] = "ready"
		}

		// Check database. READINESS-DB: if a DB was CONFIGURED (DATABASE_URL set),
		// it MUST be reachable for this pod to be ready — otherwise K8s routes
		// traffic to a pod that silently drops every persist (scan results never
		// saved). checkDatabaseStatus() returns an error when the DB is disabled,
		// uninitialized, or unreachable (covering the degraded-boot case where a
		// configured DB failed at startup, DatabaseRequired=false). A deployment
		// with NO DATABASE_URL at all treats the DB as optional and stays ready.
		if db.DatabaseConfigured {
			if err := checkDatabaseStatus(); err != nil {
				ready = false
				checks["database"] = "unhealthy: " + err.Error()
			} else {
				checks["database"] = "ready"
			}
		}

		if ready {
			c.JSON(http.StatusOK, gin.H{
				"status": "ready",
				"checks": checks,
			})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not ready",
				"checks": checks,
			})
		}
	})

	// Liveness probe endpoint
	router.GET("/live", func(c *gin.Context) {
		// Simple liveness check - just verify the service is running
		c.JSON(http.StatusOK, gin.H{
			"status":    "alive",
			"timestamp": time.Now().Unix(),
		})
	})

	// Per-IP rate limiter; defaults are conservative (5 rps, burst 10) and tunable
	// via MORF_RATE_LIMIT_RPS / MORF_RATE_LIMIT_BURST. Setting RPS=0 disables it.
	// Registered AFTER the probe/metrics endpoints above so kubelet liveness/
	// readiness probes and the Prometheus scrape are never throttled to 429; the
	// limiter applies only to the data routes registered below.
	rateLimiter := NewRateLimiter()
	router.Use(rateLimiter.Middleware())

	// S-2: API-key auth is FAIL-CLOSED by default. The probe/observability
	// endpoints above (/metrics, /health, /ready, /live) intentionally stay
	// public, but every data route is authenticated unless the operator
	// explicitly opts out with MORF_REQUIRE_API_KEY=false. Even when opted out,
	// APIKeyAuthSelective still authenticates the high-risk SSRF integration
	// (/jira, /slackscan) and pattern-mutation routes, so that surface is never
	// exposed unauthenticated. The middleware caches valid keys (TTL) and flushes
	// last-used updates async/batched, so it adds no synchronous DB write/request.
	requireAPIKey := os.Getenv("MORF_REQUIRE_API_KEY") != "false"
	router.Use(auth.APIKeyAuthSelective(requireAPIKey))
	// AUTH-1 (row 061): enforce the per-API-key rate limiter that APIKeyAuth
	// feeds via the "api_key_id"/"rate_limit" context values. Registered AFTER
	// auth so the limiter sees the authenticated key. Mounted unconditionally:
	// when requireAPIKey is false, APIKeyAuthSelective still authenticates the
	// protected data paths (/results, /secrets, /compare) so those routes still
	// carry api_key_id in context, and per-key throttling applies. For routes
	// where no key is present (unauthenticated open routes), RateLimitMiddleware
	// skips gracefully (api_key_id absent → c.Next()). Per-IP limiting above
	// still applies to all routes.
	router.Use(auth.RateLimitMiddleware())
	if requireAPIKey {
		log.Info("API key auth ENABLED on /api data routes (default; set MORF_REQUIRE_API_KEY=false to disable)")
	} else {
		log.Warn("API key auth DISABLED globally (MORF_REQUIRE_API_KEY=false); /jira, /slackscan, pattern-mutation routes AND the result-reading routes (/results, /secrets, /compare) still require a key")
	}

	// MED-scopes: scope enforcement is wired but OFF by default. There is no
	// key-management surface yet to assign scopes to keys, so enabling it
	// unconditionally would deny every key. Operators who provision scoped keys
	// can turn it on with MORF_ENFORCE_SCOPES=true to require "scan:write" on the
	// sensitive SSRF/pattern-mutation routes.
	if os.Getenv("MORF_ENFORCE_SCOPES") == "true" {
		router.Use(auth.RequireScopeForSensitive("scan:write"))
		log.Info("Scope enforcement ENABLED (MORF_ENFORCE_SCOPES=true): sensitive routes require scope scan:write")
	}

	// Results endpoint - job ID based
	router.GET("/results/:jobID", func(c *gin.Context) {
		jobID := c.Param("jobID")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobID,
		}).Info("Getting job results")

		// Get job from queue
		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not initialized",
			})
			return
		}

		job, err := queue.GetQueue().GetJob(jobID)
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobID,
				"error":      err.Error(),
			}).Warn("Job not found")
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Job not found",
			})
			return
		}

		// Return job status and result if available
		response := gin.H{
			"job_id":     job.ID,
			"status":     string(job.Status),
			"created_at": job.CreatedAt.Format(time.RFC3339),
		}

		if job.StartedAt != nil {
			response["started_at"] = job.StartedAt.Format(time.RFC3339)
		}
		if job.CompletedAt != nil {
			response["completed_at"] = job.CompletedAt.Format(time.RFC3339)
		}
		if job.FailedAt != nil {
			response["failed_at"] = job.FailedAt.Format(time.RFC3339)
			response["error"] = job.Error
		}

		// Surface the coarse in-progress stage so the client can drive a real
		// step indicator instead of a timer, while the job is still running.
		if (job.Status == models.JobStatusQueued || job.Status == models.JobStatusProcessing) && job.Phase != "" {
			response["phase"] = job.Phase
		}

		// SEC: mask secret values in the result envelope by default. The stored
		// job.Result carries raw secretString values (needed by the worker's
		// verification pass), but the read API must not hand them back verbatim to
		// every caller. Masking is on unless an operator explicitly opts out with
		// MORF_MASK_RESULTS=false (e.g. a trusted internal deployment). On a mask
		// failure we fail closed: drop the result field rather than leak raw values.
		if job.Status == models.JobStatusCompleted && job.Result != "" {
			if os.Getenv("MORF_MASK_RESULTS") == "false" {
				response["result"] = json.RawMessage(job.Result)
			} else if masked, err := report.MaskResultJSON([]byte(job.Result)); err == nil {
				response["result"] = json.RawMessage(masked)
			} else {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id":     jobID,
					"error":      err.Error(),
				}).Error("Failed to mask result payload; withholding result to avoid leaking raw secrets")
				response["result_error"] = "result unavailable (masking failed)"
			}
		}

		statusCode := http.StatusOK
		if job.Status == models.JobStatusQueued || job.Status == models.JobStatusProcessing {
			statusCode = http.StatusAccepted
		} else if job.Status == models.JobStatusFailed {
			statusCode = http.StatusInternalServerError
		}

		c.JSON(statusCode, response)
	})

	// Export results endpoint
	router.GET("/results/:jobID/export", func(c *gin.Context) {
		jobID := c.Param("jobID")
		format := c.DefaultQuery("format", "json")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobID,
			"format":     format,
		}).Info("Exporting job results")

		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not initialized",
			})
			return
		}

		job, err := queue.GetQueue().GetJob(jobID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Job not found",
			})
			return
		}

		if job.Status != models.JobStatusCompleted {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Job is not completed yet",
			})
			return
		}

		// SARIF export branch: decode the same job.Result envelope the other
		// export formats read, pull the findings/target/platform out of it, and
		// hand them to report.EncodeSARIF. If the result payload is missing or the
		// findings cannot be recovered, behave like the not-ready path above
		// (400) rather than emitting an empty report.
		if format == "sarif" {
			var payload struct {
				Data struct {
					FileName         string                   `json:"fileName"`
					PackageName      string                   `json:"packageName"`
					Secrets          []models.SecretModel     `json:"secrets"`
					PlatformFindings []models.PlatformFinding `json:"platformFindings"`
				} `json:"data"`
			}
			if job.Result == "" || json.Unmarshal([]byte(job.Result), &payload) != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Job is not completed yet",
				})
				return
			}

			// target: prefer the scanned bundle's package id, else its file name,
			// else the job's original upload name. platform: derived from the job's
			// FileType discriminator ("ipa" -> ios, else android).
			target := payload.Data.PackageName
			if target == "" {
				target = payload.Data.FileName
			}
			if target == "" {
				target = job.OriginalFilename
			}
			platform := "android"
			if strings.EqualFold(job.FileType, "ipa") {
				platform = "ios"
			}

			// Include platform findings (exported components, deeplinks, Firebase
			// misconfig) persisted in the result envelope so server-side SARIF
			// export matches the CLI `morf scan --sarif` output.
			sarifData, sarifErr := report.EncodeSARIFWithFindings(target, platform, payload.Data.Secrets, payload.Data.PlatformFindings)
			if sarifErr != nil {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id":     jobID,
					"error":      sarifErr.Error(),
				}).Error("Failed to encode SARIF report")
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to export: %s", sarifErr.Error()),
				})
				return
			}
			filename := fmt.Sprintf("morf-scan-%s.sarif", jobID)
			c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
			c.Data(http.StatusOK, "application/sarif+json", sarifData)
			return
		}

		// SEC: mask secret values in the exported json/csv/pdf/cyclonedx output
		// the same way /results and the SARIF branch do. Export is an
		// authenticated download but must not hand back RAW secrets by default;
		// ExportResult reads job.Result for every format, so masking that JSON
		// masks all of them. Opt out with MORF_MASK_RESULTS=false. Fail closed:
		// on a mask error we refuse to export rather than leak.
		exportJob := job
		if os.Getenv("MORF_MASK_RESULTS") != "false" && job.Result != "" {
			masked, mErr := report.MaskResultJSON([]byte(job.Result))
			if mErr != nil {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id":     jobID,
					"error":      mErr.Error(),
				}).Error("Failed to mask result for export; refusing to export raw secrets")
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "result unavailable (masking failed)",
				})
				return
			}
			jobCopy := *job
			jobCopy.Result = string(masked)
			exportJob = &jobCopy
		}

		// Export results
		exportData, contentType, err := utils.ExportResult(exportJob, utils.ExportFormat(format))
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobID,
				"error":      err.Error(),
			}).Error("Failed to export results")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to export: %s", err.Error()),
			})
			return
		}

		// Set headers
		filename := fmt.Sprintf("morf-scan-%s.%s", jobID, format)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Data(http.StatusOK, contentType, exportData)
	})

	// Compare scans endpoint
	router.GET("/compare/:jobID1/:jobID2", func(c *gin.Context) {
		jobID1 := c.Param("jobID1")
		jobID2 := c.Param("jobID2")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id_1":   jobID1,
			"job_id_2":   jobID2,
		}).Info("Comparing scan results")

		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not initialized",
			})
			return
		}

		job1, err := queue.GetQueue().GetJob(jobID1)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("Job %s not found", jobID1),
			})
			return
		}

		job2, err := queue.GetQueue().GetJob(jobID2)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("Job %s not found", jobID2),
			})
			return
		}

		if job1.Status != models.JobStatusCompleted || job2.Status != models.JobStatusCompleted {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Both jobs must be completed to compare",
			})
			return
		}

		// Compare scans
		comparison, err := utils.CompareScans(job1, job2)
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id_1":   jobID1,
				"job_id_2":   jobID2,
				"error":      err.Error(),
			}).Error("Failed to compare scans")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to compare: %s", err.Error()),
			})
			return
		}

		// SEC: mask secret values in the comparison result by default. The stored
		// job Results carry raw secretString values, but the read API must not hand
		// them back verbatim. Masking is on unless MORF_MASK_RESULTS=false. On a
		// mask failure we fail closed: return a result_error rather than leaking raw
		// values (mirrors the /results handler behaviour).
		if os.Getenv("MORF_MASK_RESULTS") == "false" {
			c.JSON(http.StatusOK, comparison)
		} else {
			raw, marshalErr := json.Marshal(comparison)
			if marshalErr != nil {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id_1":   jobID1,
					"job_id_2":   jobID2,
					"error":      marshalErr.Error(),
				}).Error("Failed to marshal comparison for masking")
				c.JSON(http.StatusInternalServerError, gin.H{
					"result_error": "result unavailable (masking failed)",
				})
				return
			}
			masked, maskErr := report.MaskComparisonJSON(raw)
			if maskErr != nil {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id_1":   jobID1,
					"job_id_2":   jobID2,
					"error":      maskErr.Error(),
				}).Error("Failed to mask comparison payload; withholding result to avoid leaking raw secrets")
				c.JSON(http.StatusInternalServerError, gin.H{
					"result_error": "result unavailable (masking failed)",
				})
				return
			}
			c.Data(http.StatusOK, "application/json; charset=utf-8", masked)
		}
	})

	// Job cancellation endpoint
	router.POST("/jobs/:jobID/cancel", func(c *gin.Context) {
		jobID := c.Param("jobID")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobID,
		}).Info("Cancelling job")

		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not initialized",
			})
			return
		}

		if err := queue.GetQueue().CancelJob(jobID); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobID,
				"error":      err.Error(),
			}).Error("Failed to cancel job")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Job cancelled successfully",
			"job_id":  jobID,
		})
	})

	// Dead letter queue management endpoints. Pagination uses ?offset=&limit=
	// (default offset=0, limit=50, max maxDLQPageSize). The cap bounds both
	// memory and the number of per-job Redis round-trips on large DLQs (DLQ-1).
	router.GET("/dlq", func(c *gin.Context) {
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
		}).Info("Getting DLQ jobs")

		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not initialized",
			})
			return
		}

		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
		if offset < 0 {
			offset = 0
		}
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		if limit <= 0 {
			limit = 50
		}
		// DLQ-1: each listed job below costs one serial HGETALL (GetJob); the
		// queue package exposes no batch/pipeline fetch we can call from here, so
		// cap the page to bound Redis round-trips per request rather than fetch
		// unbounded.
		if limit > maxDLQPageSize {
			limit = maxDLQPageSize
		}

		dlqDepth, err := queue.GetQueue().GetDLQDepth()
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Failed to get DLQ depth")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get DLQ depth",
			})
			return
		}

		jobIDs, err := queue.GetQueue().GetDLQJobsPage(offset, limit)
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Failed to get DLQ jobs")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get DLQ jobs",
			})
			return
		}

		// Get job details for each DLQ job
		jobs := make([]gin.H, 0, len(jobIDs))
		for _, jobID := range jobIDs {
			job, err := queue.GetQueue().GetJob(jobID)
			if err != nil {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id":     jobID,
					"error":      err.Error(),
				}).Warn("Failed to get job details")
				continue
			}

			jobs = append(jobs, gin.H{
				"job_id":      job.ID,
				"status":      string(job.Status),
				"error":       job.Error,
				"retry_count": job.RetryCount,
				"failed_at":   job.FailedAt,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"depth":  dlqDepth,
			"offset": offset,
			"limit":  limit,
			"jobs":   jobs,
		})
	})

	// MED-webhook-dlq: inspect webhook deliveries that exhausted their retries.
	// Records are durable (capped Redis list) so failed callbacks are not lost.
	router.GET("/webhook-dlq", func(c *gin.Context) {
		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Queue not available"})
			return
		}
		offset := 0
		limit := 50
		if v := c.Query("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		if v := c.Query("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		depth, err := queue.GetQueue().GetWebhookDLQDepth()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to read webhook DLQ depth: %s", err.Error())})
			return
		}
		raw, err := queue.GetQueue().GetWebhookDLQPage(offset, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to read webhook DLQ: %s", err.Error())})
			return
		}
		records := make([]json.RawMessage, 0, len(raw))
		for _, r := range raw {
			records = append(records, json.RawMessage(r))
		}
		c.JSON(http.StatusOK, gin.H{
			"depth":   depth,
			"offset":  offset,
			"limit":   limit,
			"records": records,
		})
	})

	// Retry DLQ job endpoint
	router.POST("/dlq/:jobID/retry", func(c *gin.Context) {
		jobID := c.Param("jobID")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobID,
		}).Info("Retrying DLQ job")

		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not initialized",
			})
			return
		}

		if err := queue.GetQueue().RetryDLQJob(jobID); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobID,
				"error":      err.Error(),
			}).Error("Failed to retry DLQ job")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Job requeued successfully",
			"job_id":  jobID,
		})
	})

	// Secrets read endpoint (normalized schema). Paginated via ?limit=&offset=.
	// db.GetSecretsPage clamps limit to [1, 1000] (default 100) and floors offset
	// at 0, so the query can never load an unbounded number of rows. This is the
	// live reader over the normalized tables written by insertSecretsSync, making
	// write-correctness observable. Registered behind the same auth/rate-limit
	// stack as the other data routes above.
	router.GET("/secrets", func(c *gin.Context) {
		requestID := c.GetString("request_id")

		// Only genuinely-parseable numbers override the defaults; anything else
		// falls through to GetSecretsPage's own clamping (limit<=0 -> default).
		limit := 0
		if v := c.Query("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = n
			}
		}
		offset := 0
		if v := c.Query("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				offset = n
			}
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"limit":      limit,
			"offset":     offset,
		}).Info("Listing secrets from normalized schema")

		if err := checkDatabaseStatus(); err != nil {
			metrics.RecordError("database")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": err.Error(),
			})
			return
		}

		secrets := db.GetSecretsPage(limit, offset)

		c.JSON(http.StatusOK, gin.H{
			"secrets": secrets,
			"count":   len(secrets),
			"limit":   limit,
			"offset":  offset,
		})
	})

	router.POST("/upload", func(c *gin.Context) {
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id":   requestID,
			"method":       c.Request.Method,
			"content_type": c.GetHeader("Content-Type"),
		}).Info("Received upload request")

		// UPLOAD-1: reject oversized uploads before the whole body is spooled to
		// disk. The Content-Length check rejects honest clients up front; the
		// MaxBytesReader aborts the read mid-stream for clients that lie about (or
		// omit) Content-Length, instead of fully spooling first. This must be set
		// before c.FormFile triggers the multipart parse.
		if c.Request.ContentLength > maxUploadSize {
			metrics.RecordError("validation")
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":    "File too large",
				"max_size": maxUploadSize,
				"size":     c.Request.ContentLength,
			})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadSize)

		file, err := c.FormFile("file")
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("File upload error")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("File upload error: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   file.Filename,
			"size":       file.Size,
		}).Info("File received")

		// Record file upload size metric
		metrics.RecordFileUploadSize(float64(file.Size))

		// --- UPLOAD-2: validate EVERYTHING before touching storage. Nothing is
		// written until every check below passes, so a rejected upload never
		// leaks bytes (and never writes to the working directory). ---

		// Backstop size check (413) in case Content-Length was absent/understated.
		if file.Size > maxUploadSize {
			metrics.RecordError("validation")
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":    "File too large",
				"max_size": maxUploadSize,
				"size":     file.Size,
			})
			return
		}

		// Validate file extension. Both Android (.apk) and iOS (.ipa) packages
		// are accepted; the platform is derived from the extension at enqueue.
		if !isSupportedPackageExt(file.Filename) {
			metrics.RecordError("validation")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Only APK or IPA files are allowed",
			})
			return
		}

		// Validate filename for path traversal (security)
		if strings.Contains(file.Filename, "..") || strings.Contains(file.Filename, "/") || strings.Contains(file.Filename, "\\") {
			metrics.RecordError("validation")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid filename: path traversal detected",
			})
			return
		}

		// Check database status
		if err := checkDatabaseStatus(); err != nil {
			metrics.RecordError("database")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Check if job queue is available
		if queue.GetQueue() == nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
			}).Error("Job queue not initialized")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not available",
			})
			return
		}

		// Check queue depth for backpressure (cheap upfront reject before we spend
		// I/O storing the upload). FAIL-CLOSED: if the depth probe errors, reject
		// with 429 rather than admitting blindly — an admit-on-error path lets an
		// unbounded flood in exactly when Redis is unhealthy. The AUTHORITATIVE,
		// race-free admission happens atomically at enqueue time below via
		// EnqueueJobAtomicWithLimit; this is just an early-out.
		queueDepth, err := queue.GetQueue().GetQueueDepth()
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to get queue depth; rejecting (fail-closed)")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Queue backpressure check unavailable, please try again later",
				"retry_after": 60,
			})
			return
		}
		metrics.SetQueueDepth(float64(queueDepth))
		if int(queueDepth) > queueDepthThreshold {
			log.WithFields(log.Fields{
				"request_id":  requestID,
				"queue_depth": queueDepth,
			}).Warn("Queue depth exceeded threshold")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Queue is full, please try again later",
				"retry_after": 60,
			})
			return
		}

		// Get webhook URL and secret from form (optional)
		webhookURL := c.PostForm("webhook_url")
		webhookSecret := c.PostForm("webhook_secret")

		// S-1: reject SSRF webhook targets at intake (fail-fast). Delivery also
		// enforces this DNS-rebind-safely at dial time, but rejecting here returns
		// a clear 400 and avoids persisting a poisoned job.
		if webhookURL != "" {
			if err := utils.ValidateWebhookURL(c.Request.Context(), webhookURL); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid webhook_url: " + err.Error()})
				return
			}
		}

		// Get scan timeout from form (optional, default 30 minutes)
		scanTimeout := 0 // 0 means use default
		if timeoutStr := c.PostForm("scan_timeout"); timeoutStr != "" {
			if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
				scanTimeout = timeout
			}
		}

		// --- Validation passed: stream the upload into object storage.
		// UPLOAD-3: file.Open() -> store.Put copies through the storage backend
		// exactly once (no second write to the working directory, no 32MB ReadAll
		// into the heap — Put streams via io.Copy). ---
		store := getUploadStore()
		if store == nil {
			metrics.RecordError("storage")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Storage backend not available",
			})
			return
		}

		// Storage key: a fresh UUID plus the validated .apk extension — no
		// directory component, no CWD write. The worker resolves the APK from
		// job.StorageKey.
		storageKey := uuid.New().String() + filepath.Ext(file.Filename)

		src, err := file.Open()
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Failed to open uploaded file")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to read uploaded file",
			})
			return
		}
		defer src.Close()

		ctx := c.Request.Context()
		if err := store.Put(ctx, storageKey, src, file.Size); err != nil {
			// Put failed: nothing was committed, so there is nothing to clean up.
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Failed to store uploaded file")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to store uploaded file",
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id":    requestID,
			"original_name": file.Filename,
			"storage_key":   storageKey,
		}).Info("File stored in object storage")

		// Create job. Both StorageKey and APKPath are set to the storage key per
		// the upload storage contract the worker relies on.
		jobID := uuid.New().String()
		job := &models.ScanJob{
			ID:               jobID,
			Status:           models.JobStatusQueued,
			StorageKey:       storageKey,
			APKPath:          storageKey,
			FileType:         packageFileType(file.Filename),
			OriginalFilename: file.Filename,
			CreatedAt:        time.Now(),
			RetryCount:       0,
			ScanTimeout:      scanTimeout,
			WebhookURL:       webhookURL,
			WebhookSecret:    webhookSecret,
			// Persist the correlation ID so the async worker can re-attach it to
			// its scan logs, tracing this upload across the queue boundary.
			RequestID: requestID,
		}

		// R-3 + fail-closed admission: publish the job atomically with an ATOMIC
		// queue-depth admission check — the LLEN check and the HSet+SAdd+Expire+
		// RPush run as ONE Lua unit, so a crash can never orphan the job AND two
		// producers can no longer both slip past the depth limit (the
		// check-then-enqueue race the upfront GetQueueDepth alone cannot close).
		// On any failure (after a successful Put) delete the stored object so
		// nothing leaks. ErrQueueFull maps to 429; anything else is a 500.
		if err := queue.GetQueue().EnqueueJobAtomicWithLimit(job, queueDepthThreshold, 1); err != nil {
			if delErr := store.Delete(ctx, storageKey); delErr != nil {
				log.WithFields(log.Fields{
					"request_id":  requestID,
					"storage_key": storageKey,
					"error":       delErr.Error(),
				}).Warn("Failed to clean up stored object after enqueue error")
			}
			if goerrors.Is(err, queue.ErrQueueFull) {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"job_id":     jobID,
				}).Warn("Queue full at atomic admission; rejecting upload")
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error":       "Queue is full, please try again later",
					"retry_after": 60,
				})
				return
			}
			log.WithFields(log.Fields{
				"request_id": requestID,
				"job_id":     jobID,
				"error":      err.Error(),
			}).Error("Failed to enqueue job")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to queue job",
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"job_id":     jobID,
		}).Info("Job created and queued")

		// Return job ID (202 Accepted)
		c.JSON(http.StatusAccepted, gin.H{
			"message": "File uploaded successfully. Processing started.",
			"job_id":  jobID,
		})
	})

	// Bulk upload endpoint
	router.POST("/bulk-upload", func(c *gin.Context) {
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
		}).Info("Received bulk upload request")

		// UPLOAD-4 (body bound): reject and cap the TOTAL request body before the
		// multipart parse spools it. Individual files are size-checked again in
		// the loop below; this just keeps an unbounded body from being written to
		// the temp dir during parsing.
		if c.Request.ContentLength > maxBulkUploadSize {
			metrics.RecordError("validation")
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":    "Bulk upload too large",
				"max_size": maxBulkUploadSize,
				"size":     c.Request.ContentLength,
			})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBulkUploadSize)

		// Get form
		form, err := c.MultipartForm()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to parse form: %s", err.Error()),
			})
			return
		}

		files := form.File["files"]
		if len(files) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "No files provided",
			})
			return
		}

		// Limit bulk uploads to 50 files
		if len(files) > 50 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Maximum 50 files allowed per bulk upload",
			})
			return
		}

		// Get webhook URL and secret from form (optional, applies to all jobs)
		webhookURL := c.PostForm("webhook_url")
		webhookSecret := c.PostForm("webhook_secret")

		// S-1: reject SSRF webhook targets at intake (fail-fast) for the bulk path too.
		if webhookURL != "" {
			if err := utils.ValidateWebhookURL(c.Request.Context(), webhookURL); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid webhook_url: " + err.Error()})
				return
			}
		}

		// Check database status
		if err := checkDatabaseStatus(); err != nil {
			metrics.RecordError("database")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Check if job queue is available
		if queue.GetQueue() == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Job queue not available",
			})
			return
		}

		// Check queue depth for backpressure (cheap upfront reject). FAIL-CLOSED:
		// a depth-probe error rejects the whole batch with 429 rather than
		// admitting blindly. Per-file admission below is race-free/atomic via
		// EnqueueJobAtomicWithLimit, which re-checks the live depth for each file.
		queueDepth, err := queue.GetQueue().GetQueueDepth()
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to get queue depth; rejecting bulk upload (fail-closed)")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Queue backpressure check unavailable, please try again later",
				"retry_after": 60,
			})
			return
		}
		metrics.SetQueueDepth(float64(queueDepth))
		// For bulk uploads, check if queue has room for all files
		if int(queueDepth)+len(files) > queueDepthThreshold {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Queue is too full for bulk upload, please try again later",
				"retry_after": 60,
			})
			return
		}

		// UPLOAD-4: the storage backend must be available before we accept any
		// file in the batch.
		store := getUploadStore()
		if store == nil {
			metrics.RecordError("storage")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Storage backend not available",
			})
			return
		}

		ctx := c.Request.Context()
		jobIDs := make([]string, 0, len(files))
		errors := make([]string, 0)

		// Process each file. Bad files are rejected individually with a clear
		// per-file error; any object already stored for a file that then fails to
		// enqueue is deleted so nothing leaks.
		for _, file := range files {
			// UPLOAD-4: apply the SAME per-file validation as single upload.

			// Validate file extension. Both Android (.apk) and iOS (.ipa)
			// packages are accepted; the platform is derived per file at enqueue.
			if !isSupportedPackageExt(file.Filename) {
				errors = append(errors, fmt.Sprintf("%s: Only APK or IPA files are allowed", file.Filename))
				continue
			}

			// Validate per-file size
			if file.Size > maxUploadSize {
				metrics.RecordError("validation")
				errors = append(errors, fmt.Sprintf("%s: File too large (max %d bytes)", file.Filename, int64(maxUploadSize)))
				continue
			}

			// Validate filename for path traversal (security)
			if strings.Contains(file.Filename, "..") || strings.Contains(file.Filename, "/") || strings.Contains(file.Filename, "\\") {
				metrics.RecordError("validation")
				errors = append(errors, fmt.Sprintf("%s: Invalid filename: path traversal detected", file.Filename))
				continue
			}

			// Stream the file into object storage under a fresh key (no CWD write).
			storageKey := uuid.New().String() + filepath.Ext(file.Filename)
			src, err := file.Open()
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: Failed to read file: %s", file.Filename, err.Error()))
				continue
			}
			if err := store.Put(ctx, storageKey, src, file.Size); err != nil {
				src.Close()
				errors = append(errors, fmt.Sprintf("%s: Failed to store file: %s", file.Filename, err.Error()))
				continue
			}
			src.Close()

			// Create job. Both StorageKey and APKPath are set to the storage key.
			jobID := uuid.New().String()
			job := &models.ScanJob{
				ID:               jobID,
				Status:           models.JobStatusQueued,
				StorageKey:       storageKey,
				APKPath:          storageKey,
				FileType:         packageFileType(file.Filename),
				OriginalFilename: file.Filename,
				CreatedAt:        time.Now(),
				RetryCount:       0,
				WebhookURL:       webhookURL,
				WebhookSecret:    webhookSecret,
				// Persist the correlation ID so the async worker can re-attach it
				// to its scan logs, tracing this upload across the queue boundary.
				RequestID: requestID,
			}

			// R-3 + fail-closed admission: atomic publish with an atomic depth
			// check (HSet+SAdd+Expire+RPush guarded by LLEN, as one unit) so a
			// crash cannot orphan the job AND a burst of concurrent bulk uploads
			// cannot collectively overrun the depth limit. A rejected file is
			// reported individually; its stored object is deleted so nothing leaks.
			if err := queue.GetQueue().EnqueueJobAtomicWithLimit(job, queueDepthThreshold, 1); err != nil {
				_ = store.Delete(ctx, storageKey)
				if goerrors.Is(err, queue.ErrQueueFull) {
					errors = append(errors, fmt.Sprintf("%s: Queue is full, rejected", file.Filename))
				} else {
					errors = append(errors, fmt.Sprintf("%s: Failed to queue job: %s", file.Filename, err.Error()))
				}
				continue
			}

			jobIDs = append(jobIDs, jobID)
		}

		log.WithFields(log.Fields{
			"request_id":  requestID,
			"total_files": len(files),
			"successful":  len(jobIDs),
			"errors":      len(errors),
		}).Info("Bulk upload completed")

		// Return results
		response := gin.H{
			"message":     fmt.Sprintf("Processed %d files", len(files)),
			"total_files": len(files),
			"successful":  len(jobIDs),
			"failed":      len(errors),
			"job_ids":     jobIDs,
		}

		if len(errors) > 0 {
			response["errors"] = errors
		}

		statusCode := http.StatusAccepted
		if len(jobIDs) == 0 {
			statusCode = http.StatusBadRequest
		}

		c.JSON(statusCode, response)
	})

	router.POST("/jira", MaxBodyBytesMiddleware(maxBodyBytes()), func(ctx *gin.Context) {
		requestID := ctx.GetString("request_id")
		requestBody := models.JiraModel{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Error binding JIRA request body")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if !db.DatabaseRequired {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Database is required for JIRA integration"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})
		// MED-jira-goroutine: copy the request-scoped context before detaching.
		// The live *gin.Context is recycled once the handler returns; reading it
		// from a goroutine that outlives the request is a use-after-recycle race.
		// The recover() guards against a panic in the detached work crashing the
		// whole process (this goroutine runs outside gin.Recovery()).
		cctx := ctx.Copy()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("recovered panic in detached /jira goroutine: %v", r)
				}
			}()
			apk.StartJiraProcess(requestBody, db.GormDB, cctx)
		}()
	})

	router.POST("/slackscan", MaxBodyBytesMiddleware(maxBodyBytes()), func(ctx *gin.Context) {
		requestID := ctx.GetString("request_id")
		requestBody := models.SlackData{}
		if err := ctx.ShouldBindBodyWith(&requestBody, binding.JSON); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Error binding Slack request body")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check database status
		if err := checkDatabaseStatus(); err != nil {
			ctx.JSON(http.StatusServiceUnavailable, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Send initial response
		ctx.JSON(http.StatusOK, gin.H{"message": "Sit Back and Relax! We are working on it!"})

		// MED-jira-goroutine: copy the request context before detaching (the live
		// *gin.Context is recycled after the handler returns) and recover() so a
		// panic in this goroutine — which runs outside gin.Recovery() — cannot
		// crash the process.
		cctx := ctx.Copy()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("recovered panic in detached /slackscan goroutine: %v", r)
				}
			}()
			download_url := utils.GetDownloadUrlFromSlack(requestBody, cctx)
			if download_url == "" {
				log.Error("Failed to get download URL from Slack")
				return
			}

			// Start the extraction process
			if result := apk.StartExtractProcess(download_url, db.GormDB, cctx, true, requestBody); result != nil {
				if result["error"] != nil {
					log.Error("Error in extraction process:", result["error"])
					return
				}
			}
		}()
	})

	// Pattern management endpoints
	router.GET("/patterns", func(c *gin.Context) {
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
		}).Info("Listing pattern files")

		patternFiles, err := utils.ListPatternFiles()
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Failed to list pattern files")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to list patterns: %s", err.Error()),
			})
			return
		}

		total := 0
		for _, file := range patternFiles {
			total += len(file.Patterns)
		}

		c.JSON(http.StatusOK, gin.H{
			"files": patternFiles,
			"total": total,
		})
	})

	router.GET("/patterns/:filename", func(c *gin.Context) {
		filename := c.Param("filename")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
		}).Info("Getting pattern file")

		patterns, err := utils.LoadPatternsByFilename(filename)
		if err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to load pattern file")
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("Pattern file not found: %s", err.Error()),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"filename": filename,
			"patterns": patterns,
		})
	})

	router.POST("/patterns/:filename/test", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		requestID := c.GetString("request_id")

		var requestBody struct {
			PatternName string `json:"pattern_name"`
			SampleText  string `json:"sample_text"`
		}

		if err := c.ShouldBindJSON(&requestBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid request: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id":   requestID,
			"filename":     filename,
			"pattern_name": requestBody.PatternName,
		}).Info("Testing pattern")

		// Load patterns
		patterns, err := utils.LoadPatternsByFilename(filename)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("Pattern file not found: %s", err.Error()),
			})
			return
		}

		// Find pattern
		var pattern *utils.Pattern
		for _, p := range patterns {
			if p.Name == requestBody.PatternName {
				pattern = &p
				break
			}
		}

		if pattern == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("Pattern '%s' not found", requestBody.PatternName),
			})
			return
		}

		// Test pattern
		matched, matches, err := utils.TestPattern(*pattern, requestBody.SampleText)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to test pattern: %s", err.Error()),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"matched": matched,
			"matches": matches,
			"count":   len(matches),
		})
	})

	router.POST("/patterns/:filename", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		requestID := c.GetString("request_id")

		var requestBody struct {
			Patterns []utils.Pattern `json:"patterns"`
		}

		if err := c.ShouldBindJSON(&requestBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid request: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
		}).Info("Updating pattern file")

		if err := utils.UpdatePatternFile(filename, requestBody.Patterns); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to update pattern file")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to update pattern file: %s", err.Error()),
			})
			return
		}

		// Invalidate metadata cache since patterns have changed
		if err := utils.InvalidateAllMetadataCache(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to invalidate metadata cache after pattern update")
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Pattern file updated successfully",
		})
	})

	router.PUT("/patterns/:filename/patterns", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		requestID := c.GetString("request_id")

		var pattern utils.Pattern
		if err := c.ShouldBindJSON(&pattern); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid request: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
			"pattern":    pattern.Name,
		}).Info("Adding pattern to file")

		if err := utils.AddPatternToFile(filename, pattern); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to add pattern")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to add pattern: %s", err.Error()),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Pattern added successfully",
		})
	})

	router.PATCH("/patterns/:filename/patterns/:patternName", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		patternName := c.Param("patternName")
		requestID := c.GetString("request_id")

		var pattern utils.Pattern
		if err := c.ShouldBindJSON(&pattern); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid request: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
			"pattern":    patternName,
		}).Info("Updating pattern in file")

		if err := utils.UpdatePatternInFile(filename, patternName, pattern); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to update pattern")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to update pattern: %s", err.Error()),
			})
			return
		}

		// Invalidate metadata cache since patterns have changed
		if err := utils.InvalidateAllMetadataCache(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to invalidate metadata cache after pattern update")
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Pattern updated successfully",
		})
	})

	router.DELETE("/patterns/:filename/patterns/:patternName", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		patternName := c.Param("patternName")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
			"pattern":    patternName,
		}).Info("Deleting pattern from file")

		if err := utils.DeletePatternFromFile(filename, patternName); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to delete pattern")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to delete pattern: %s", err.Error()),
			})
			return
		}

		// Invalidate metadata cache since patterns have changed
		if err := utils.InvalidateAllMetadataCache(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to invalidate metadata cache after pattern deletion")
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Pattern deleted successfully",
		})
	})

	router.PATCH("/patterns/:filename/patterns/:patternName/enable", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		patternName := c.Param("patternName")
		requestID := c.GetString("request_id")

		var requestBody struct {
			Enabled bool `json:"enabled"`
		}

		if err := c.ShouldBindJSON(&requestBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid request: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
			"pattern":    patternName,
			"enabled":    requestBody.Enabled,
		}).Info("Enabling/disabling pattern")

		if err := utils.EnableDisablePattern(filename, patternName, requestBody.Enabled); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to enable/disable pattern")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to enable/disable pattern: %s", err.Error()),
			})
			return
		}

		// Invalidate metadata cache since pattern status has changed
		if err := utils.InvalidateAllMetadataCache(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to invalidate metadata cache after pattern status update")
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Pattern status updated successfully",
		})
	})

	router.POST("/patterns", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		requestID := c.GetString("request_id")

		var requestBody struct {
			Filename string          `json:"filename"`
			Patterns []utils.Pattern `json:"patterns"`
		}

		if err := c.ShouldBindJSON(&requestBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid request: %s", err.Error()),
			})
			return
		}

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   requestBody.Filename,
		}).Info("Creating new pattern file")

		if err := utils.CreatePatternFile(requestBody.Filename, requestBody.Patterns); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   requestBody.Filename,
				"error":      err.Error(),
			}).Error("Failed to create pattern file")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to create pattern file: %s", err.Error()),
			})
			return
		}

		// Invalidate metadata cache since new patterns have been added
		if err := utils.InvalidateAllMetadataCache(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to invalidate metadata cache after pattern file creation")
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "Pattern file created successfully",
		})
	})

	router.DELETE("/patterns/:filename", MaxBodyBytesMiddleware(maxBodyBytes()), func(c *gin.Context) {
		filename := c.Param("filename")
		requestID := c.GetString("request_id")

		log.WithFields(log.Fields{
			"request_id": requestID,
			"filename":   filename,
		}).Info("Deleting pattern file")

		if err := utils.DeletePatternFile(filename); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"filename":   filename,
				"error":      err.Error(),
			}).Error("Failed to delete pattern file")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to delete pattern file: %s", err.Error()),
			})
			return
		}

		// Invalidate metadata cache since patterns have been removed
		if err := utils.InvalidateAllMetadataCache(); err != nil {
			log.WithFields(log.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Warn("Failed to invalidate metadata cache after pattern file deletion")
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Pattern file deleted successfully",
		})
	})

	return router
}
