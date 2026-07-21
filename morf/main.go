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

package main

import (
	"context"
	"database/sql"
	"fmt"
	"morf/auth"
	"morf/cmd"
	"morf/config"
	"morf/db"
	"morf/db/migrations"
	"morf/metrics"
	"morf/queue"
	"morf/router"
	"morf/storage"
	"morf/utils"
	"morf/version"
	"morf/worker"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// configureGin sets the Gin runtime mode and trusted-proxy policy from the
// environment. It is shared by runServer and runAPIOnly so both surfaces stay
// in lockstep.
//
//	API-2: default to ReleaseMode in production; opt into DebugMode only when
//	       MORF_GIN_MODE=debug.
//	API-3: derive trusted proxies from MORF_TRUSTED_PROXIES (comma-separated
//	       CIDRs). When unset, trust NONE so ClientIP() resolves to the direct
//	       peer and X-Forwarded-For cannot be spoofed.
func configureGin() {
	if os.Getenv("MORF_GIN_MODE") == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
}

// validateStorageOrExit fails fast when an explicitly-configured storage backend
// (MORF_STORAGE_BACKEND=s3) is misconfigured. Without this the upload store is
// built lazily on the first /upload and its error is swallowed, so a bad S3
// config boots green then 500s every upload. A misconfig is not runtime-
// recoverable (it needs an env fix), so failing fast with a clear message —
// surfaced as a pod crashloop reason — is the correct signal. STORAGE-startup.
func validateStorageOrExit() {
	if err := storage.ValidateConfiguredBackend(); err != nil {
		log.Fatalf("Storage backend misconfigured: %v", err)
	}
}

// applyTrustedProxies implements API-3 for a freshly created engine.
func applyTrustedProxies(r *gin.Engine) {
	if raw := os.Getenv("MORF_TRUSTED_PROXIES"); strings.TrimSpace(raw) != "" {
		proxies := make([]string, 0)
		for _, p := range strings.Split(raw, ",") {
			if t := strings.TrimSpace(p); t != "" {
				proxies = append(proxies, t)
			}
		}
		if err := r.SetTrustedProxies(proxies); err != nil {
			log.Warnf("Failed to set trusted proxies %v: %v", proxies, err)
		} else {
			log.Infof("Trusted proxies set to %v", proxies)
		}
		return
	}
	// Trust none: ClientIP() is the direct peer, not a spoofable header.
	if err := r.SetTrustedProxies(nil); err != nil {
		log.Warnf("Failed to disable trusted proxies: %v", err)
	} else {
		log.Info("MORF_TRUSTED_PROXIES unset; trusting no proxies (ClientIP = direct peer)")
	}
}

// allowedOrigins reads MORF_CORS_ALLOWED_ORIGINS as a comma-separated list.
// Falls back to the dev origin for local-only setups but warns loudly so
// production deployments are pushed to set the variable explicitly.
func allowedOrigins() []string {
	if v, ok := os.LookupEnv("MORF_CORS_ALLOWED_ORIGINS"); ok {
		raw := strings.Split(v, ",")
		out := make([]string, 0, len(raw))
		for _, s := range raw {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	log.Warn("MORF_CORS_ALLOWED_ORIGINS not set; defaulting to http://localhost:4200 (dev only)")
	return []string{"http://localhost:4200"}
}

// startDBPoolStatsReporter wires the DB connection-pool gauges (O-1). They were
// registered, dashboarded and runbook-referenced but never fed in production
// (only the unit test called SetDBPoolStats), so pool exhaustion was invisible.
// This samples sql.DBStats periodically in every run mode so the gauges are live.
func startDBPoolStatsReporter(ctx context.Context) {
	if !db.DatabaseRequired || db.GormDB == nil {
		return
	}
	sqlDB, err := db.GormDB.DB()
	if err != nil {
		log.Warnf("DB pool stats reporter not started: %v", err)
		return
	}
	metrics.StartDBPoolStatsReporter(ctx, func() sql.DBStats { return sqlDB.Stats() }, 10*time.Second)
	log.Info("DB pool stats reporter started")
}

// sweepJobWorkspaces removes leftover per-job scan workspaces under
// /tmp/morf/jobs left by a previous process (crash/OOM-kill) so disk does not
// accumulate across restarts (MED-ioFactor). Safe at startup because no scan is
// in flight yet.
func sweepJobWorkspaces() {
	dir := "/tmp/morf/jobs"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
	if len(entries) > 0 {
		log.Infof("Swept %d leftover job workspace(s) from %s", len(entries), dir)
	}
}

var rootCmd = &cobra.Command{
	Use:   "morf",
	Short: "Mobile Reconnaissance Framework",
	Long:  `A tool to scan mobile applications for sensitive information`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the MORF version and build metadata",
	Long:  `Print the semantic version, git commit, and build date stamped into the binary at release time.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.String())
	},
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run MORF as a web server",
	Long:  `Start the MORF web server with API and frontend`,
	Run:   runServer,
}

var apiOnlyCmd = &cobra.Command{
	Use:   "api",
	Short: "Run MORF API server only (no workers)",
	Long:  `Start the MORF API server without worker pool for independent scaling`,
	Run:   runAPIOnly,
}

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Run MORF worker pool only (no API)",
	Long:  `Start the MORF worker pool without API server for independent scaling`,
	Run:   runWorkerOnly,
}

// migrateCmd runs schema migrations once and exits. Used as a Kubernetes
// initContainer (or release pipeline step) so AutoMigrate doesn't run on
// every server boot, where it can serialize under load and risk schema-lock
// races between multiple replicas.
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations and exit",
	Long:  `Connects to the database, runs all pending migrations, and exits with status 0 on success.`,
	Run: func(cmd *cobra.Command, args []string) {
		// DB-3: the explicit `morf migrate` command must run the FULL migration
		// set (AutoMigrate + ordered SQL files) even when the deployment sets
		// MORF_DISABLE_AUTO_MIGRATE=true to keep AutoMigrate off the server-boot
		// path. Clearing it here ensures the migrate initContainer/job actually
		// migrates instead of silently no-opping.
		os.Unsetenv("MORF_DISABLE_AUTO_MIGRATE")
		log.Info("Running database migrations…")
		db.InitDB()
		if !db.DatabaseRequired || db.GormDB == nil {
			log.Fatal("Migrations failed: database not available. Set DATABASE_URL.")
		}
		log.Info("Migrations completed successfully.")

		// DB-5: optionally backfill the normalized schema from the legacy flat
		// tables. Gated behind --backfill so the routine migrate path stays
		// fast and idempotent. BackfillNormalized streams legacy rows in
		// batches (FindInBatches) and is idempotent (skips already-migrated
		// apk_hash), so re-running is safe.
		if backfill, _ := cmd.Flags().GetBool("backfill"); backfill {
			log.Info("--backfill set: backfilling normalized schema from legacy flat tables…")
			if err := migrations.BackfillNormalized(db.GormDB); err != nil {
				log.Fatalf("Backfill of normalized schema failed: %v", err)
			}
			log.Info("Normalized schema backfill completed successfully.")
		}
	},
}

func init() {
	// Configure logging. The formatter is env-gated via MORF_LOG_FORMAT (wired
	// through the config package): "json" selects logrus' JSONFormatter so log
	// aggregators can ingest structured lines (and correlation fields like
	// request_id/job_id become first-class JSON keys), while any other/unset
	// value keeps the human-readable text formatter for local runs.
	if config.LogFormat("text") == "json" {
		log.SetFormatter(&log.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}
	// Logs go to STDERR so stdout stays clean for machine-readable command
	// output (e.g. `morf scan --format sarif`, `morf benchmark --json` piped to
	// a file). Container/K8s log collectors read both streams, so server/worker
	// log capture is unaffected. CLI-8.
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)

	// TODO(observability): wire full OpenTelemetry tracing (spans across the
	// HTTP upload -> queue -> worker scan boundary, exported via OTLP). For now
	// correlation is carried by the request_id field: it is captured by
	// router.CorrelationIDMiddleware, persisted on models.ScanJob at enqueue, and
	// re-attached to the worker's structured scan logs, so an upload can already
	// be traced to its scan logs by request_id without a tracing backend.

	rootCmd.AddCommand(cmd.GetCliCmd())
	rootCmd.AddCommand(cmd.GetScanCmd())
	rootCmd.AddCommand(cmd.GetGateCmd())
	rootCmd.AddCommand(cmd.GetFetchCmd())
	rootCmd.AddCommand(cmd.GetBenchCmd())
	rootCmd.AddCommand(cmd.GetAPIKeyCmd())
	rootCmd.AddCommand(cmd.GetMCPCmd())
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(apiOnlyCmd)
	rootCmd.AddCommand(workerCmd)
	rootCmd.AddCommand(migrateCmd)

	// Server command flags
	serverCmd.Flags().IntP("port", "p", 9092, "Port to run the server on")
	serverCmd.Flags().StringP("db-url", "u", "", "Database URL (optional)")

	// API-only command flags
	apiOnlyCmd.Flags().IntP("port", "p", 9092, "Port to run the API server on")
	apiOnlyCmd.Flags().StringP("db-url", "u", "", "Database URL (optional)")

	// Worker command flags
	workerCmd.Flags().IntP("pool-size", "s", 0, "Worker pool size (0 = auto-calculate)")
	workerCmd.Flags().StringP("db-url", "u", "", "Database URL (optional)")

	// Migrate command flags
	migrateCmd.Flags().Bool("backfill", false, "After migrating, backfill the normalized schema from legacy flat tables (DB-5)")
}

func runServer(cmd *cobra.Command, args []string) {
	validateStorageOrExit()
	port, _ := cmd.Flags().GetInt("port")
	dbURL, _ := cmd.Flags().GetString("db-url")

	log.Info("Starting MORF server...")
	log.Infof("Port: %d", port)

	// CPU-1: honor the cgroup CPU limit when sizing GOMAXPROCS.
	log.Infof("GOMAXPROCS set to %d (cgroup-aware)", utils.MaxProcs())

	// Background context for long-running goroutines (queue-depth reporter,
	// queue reaper, cache invalidation subscriber). Cancelled on shutdown so
	// these drain before the process exits.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Set database URL if provided
	if dbURL != "" {
		os.Setenv("DATABASE_URL", dbURL)
	}

	// Load effective configuration once and log a masked summary. In full-node
	// mode the DB and queue both degrade gracefully, so validation is advisory
	// (requireDB/requireQueue=false) and does not fail fast here.
	cfg := config.Load()
	if err := cfg.Validate(false, false); err != nil {
		log.Warnf("Configuration warning: %v", err)
	}
	cfg.LogSummary()

	// Initialize database (will be disabled if DATABASE_URL is not set)
	db.InitDB()

	// Initialize Redis cache (will use same Redis client as queue after queue init)
	redisURL := cfg.RedisURL
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}
	// Initialize cache - will be updated to use queue's client after queue init
	if err := utils.InitCache(redisURL); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to initialize cache, continuing without caching")
	} else {
		log.Info("Cache initialized successfully")
	}

	// Start the cache invalidation subscriber so local in-process state is
	// busted on cross-replica invalidations.
	go utils.StartCacheInvalidationSubscriber(bgCtx)
	// MED-cache-refresh: periodically re-sync the local pattern-version counter
	// from Redis as a belt-and-suspenders fallback for dropped pub/sub
	// invalidations, so a partitioned pod cannot serve stale metadata until TTL.
	utils.StartPatternVersionRefresher(bgCtx, time.Minute)
	// Flush buffered API-key usage on the shutdown-bound context (final flush on cancel).
	auth.StartAPIKeyUsageFlusher(bgCtx)

	// Initialize circuit breakers
	utils.InitCircuitBreakers()
	log.Info("Circuit breakers initialized")

	// Initialize Redis job queue
	var wp *worker.WorkerPool
	if err := queue.InitQueue(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to initialize job queue, continuing without queue support")
	} else {
		// Update cache to use the same Redis client as queue
		if queue.GetQueue() != nil {
			// Get Redis client from queue and initialize cache with it
			queueClient := queue.GetQueue().GetClient()
			if queueClient != nil {
				utils.InitCacheFromClient(queueClient)
			}
		}

		// MED-ioFactor: clear any per-job scan workspaces leaked by a previous
		// process (crash/OOM) before starting fresh scans.
		sweepJobWorkspaces()

		// Initialize and start worker pool
		wp = worker.NewWorkerPool(queue.GetQueue())
		if err := wp.Start(); err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("Failed to start worker pool")
		} else {
			log.Info("Worker pool started")
			// Tune database connection pool based on worker count
			if db.DatabaseRequired && db.GormDB != nil {
				db.TuneConnectionPool(wp.GetWorkerCount())
			}
			// O-1: feed the DB connection-pool gauges so exhaustion is observable.
			startDBPoolStatsReporter(bgCtx)
		}

		// METRICS-1: single central source feeding the KEDA queue-depth gauge.
		metrics.StartQueueDepthReporter(bgCtx, func() (int64, error) {
			q := queue.GetQueue()
			if q == nil {
				return 0, nil
			}
			return q.GetQueueDepth()
		}, 10*time.Second)

		// Reliable-queue reaper: requeue jobs stuck in the processing list.
		if q := queue.GetQueue(); q != nil {
			go q.StartReaper(bgCtx, 2*time.Minute)
		}
	}

	// Initialize Gin (API-2 mode + API-3 trusted proxies configured below).
	configureGin()
	r := gin.New()
	applyTrustedProxies(r)
	r.Use(gin.Logger(), gin.Recovery())

	// Configure CORS (allow-list driven by MORF_CORS_ALLOWED_ORIGINS).
	config := cors.DefaultConfig()
	config.AllowOrigins = allowedOrigins()
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID", "X-API-Key"}
	r.Use(cors.New(config))

	// API routes
	apiGroup := r.Group("/api")
	router.InitRouters(apiGroup)

	// Serve static files for Angular frontend.
	// Hashed bundle assets (outputHashing: all) get aggressive caching;
	// the SPA shell (index.html) must not cache so users always get the
	// latest deploy reference.
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		}
		c.Next()
	})
	r.Static("/assets", "./web/dist/browser/assets")
	r.NoRoute(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.File("./web/dist/browser/index.html")
	})

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Start server in goroutine.
	// API-1: explicit timeouts guard against Slowloris / FD exhaustion.
	// ReadTimeout is generous (large APK uploads); WriteTimeout covers long
	// scan responses; IdleTimeout reaps idle keep-alive connections.
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Infof("Starting server on port %d", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Info("Shutting down server...")

	// Bound the whole shutdown sequence.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// SHUTDOWN-1: correct ordering is drain HTTP -> stop workers -> close DB,
	// so in-flight requests never hit a stopped worker pool or a closed DB.

	// (a) Drain in-flight HTTP requests first.
	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("Server forced to shutdown: %v", err)
	}

	// Stop background goroutines (reporter, reaper, cache subscriber).
	bgCancel()

	// (b) Then stop the worker pool.
	if wp != nil {
		log.Info("Stopping worker pool...")
		if err := wp.Stop(); err != nil {
			log.Errorf("Error stopping worker pool: %v", err)
		}
	}

	// (c) Finally close database connections.
	if db.GormDB != nil {
		sqlDB, err := db.GormDB.DB()
		if err == nil {
			if err := sqlDB.Close(); err != nil {
				log.Errorf("Error closing database: %v", err)
			}
		}
	}

	log.Info("Server exited gracefully")
}

func runAPIOnly(cmd *cobra.Command, args []string) {
	validateStorageOrExit()
	port, _ := cmd.Flags().GetInt("port")
	dbURL, _ := cmd.Flags().GetString("db-url")

	log.Info("Starting MORF API server (API-only mode)...")
	log.Infof("Port: %d", port)

	// CPU-1: honor the cgroup CPU limit when sizing GOMAXPROCS.
	log.Infof("GOMAXPROCS set to %d (cgroup-aware)", utils.MaxProcs())

	// Background context for long-running goroutines (cache invalidation
	// subscriber). Cancelled on shutdown.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Set database URL if provided
	if dbURL != "" {
		os.Setenv("DATABASE_URL", dbURL)
	}

	// Load effective configuration once and log a masked summary. API-only mode
	// hard-requires the Redis queue (it Fatals below if the queue cannot init),
	// so fail fast now on a missing REDIS_URL with a clear message. The DB still
	// degrades gracefully, so it is not required here.
	cfg := config.Load()
	if err := cfg.Validate(false, true); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	cfg.LogSummary()

	// Initialize database (will be disabled if DATABASE_URL is not set)
	db.InitDB()

	// Initialize Redis cache (will use same Redis client as queue after queue init)
	redisURL := cfg.RedisURL
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}
	// Initialize cache - will be updated to use queue's client after queue init
	if err := utils.InitCache(redisURL); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to initialize cache, continuing without caching")
	} else {
		log.Info("Cache initialized successfully")
	}

	// Start the cache invalidation subscriber so local in-process state is
	// busted on cross-replica invalidations.
	go utils.StartCacheInvalidationSubscriber(bgCtx)
	// MED-cache-refresh: periodically re-sync the local pattern-version counter
	// from Redis as a belt-and-suspenders fallback for dropped pub/sub
	// invalidations, so a partitioned pod cannot serve stale metadata until TTL.
	utils.StartPatternVersionRefresher(bgCtx, time.Minute)
	// Flush buffered API-key usage on the shutdown-bound context (final flush on cancel).
	auth.StartAPIKeyUsageFlusher(bgCtx)

	// Initialize circuit breakers
	utils.InitCircuitBreakers()
	log.Info("Circuit breakers initialized")

	// Initialize Redis job queue (required for API to enqueue jobs)
	if err := queue.InitQueue(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatal("Failed to initialize job queue - API server requires Redis queue")
	}

	// Update cache to use the same Redis client as queue
	if queue.GetQueue() != nil {
		queueClient := queue.GetQueue().GetClient()
		if queueClient != nil {
			utils.InitCacheFromClient(queueClient)
		}
	}

	log.Info("API-only mode: Worker pool will NOT be started. Jobs will be queued for external workers.")

	// SC-2: API-only pods have no worker pool, so TuneConnectionPool was never
	// called and the pool stayed at the connectToDatabase default. Tune it with a
	// nominal request-handler concurrency so MORF_DB_MAX_OPEN_CONNS is honored and
	// a large fleet of API pods does not collectively exhaust MySQL.
	if db.DatabaseRequired && db.GormDB != nil {
		db.TuneConnectionPool(8)
		// O-1: feed the DB connection-pool gauges so exhaustion is observable.
		startDBPoolStatsReporter(bgCtx)
	}

	// Initialize Gin (API-2 mode + API-3 trusted proxies configured below).
	configureGin()
	r := gin.New()
	applyTrustedProxies(r)
	r.Use(gin.Logger(), gin.Recovery())

	// Configure CORS (allow-list driven by MORF_CORS_ALLOWED_ORIGINS).
	config := cors.DefaultConfig()
	config.AllowOrigins = allowedOrigins()
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID", "X-API-Key"}
	r.Use(cors.New(config))

	// API routes
	apiGroup := r.Group("/api")
	router.InitRouters(apiGroup)

	// Serve static files for Angular frontend.
	// Hashed bundle assets (outputHashing: all) get aggressive caching;
	// the SPA shell (index.html) must not cache so users always get the
	// latest deploy reference.
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		}
		c.Next()
	})
	r.Static("/assets", "./web/dist/browser/assets")
	r.NoRoute(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.File("./web/dist/browser/index.html")
	})

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Start server in goroutine.
	// API-1: explicit timeouts guard against Slowloris / FD exhaustion.
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Infof("Starting API server on port %d (no workers)", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start API server: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Info("Shutting down API server...")

	// Bound the whole shutdown sequence.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// SHUTDOWN-1: drain in-flight HTTP requests BEFORE closing the DB, so
	// requests in flight never hit a closed database connection.
	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("API server forced to shutdown: %v", err)
	}

	// Stop background goroutines (cache subscriber).
	bgCancel()

	// Close database connections.
	if db.GormDB != nil {
		sqlDB, err := db.GormDB.DB()
		if err == nil {
			if err := sqlDB.Close(); err != nil {
				log.Errorf("Error closing database: %v", err)
			}
		}
	}

	log.Info("API server exited gracefully")
}

func runWorkerOnly(cmd *cobra.Command, args []string) {
	validateStorageOrExit()
	poolSize, _ := cmd.Flags().GetInt("pool-size")
	dbURL, _ := cmd.Flags().GetString("db-url")

	log.Info("Starting MORF worker pool (worker-only mode)...")

	// CPU-1: honor the cgroup CPU limit when sizing GOMAXPROCS.
	log.Infof("GOMAXPROCS set to %d (cgroup-aware)", utils.MaxProcs())

	// Background context for long-running goroutines (queue-depth reporter,
	// queue reaper, cache invalidation subscriber). Cancelled on shutdown.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// Set database URL if provided
	if dbURL != "" {
		os.Setenv("DATABASE_URL", dbURL)
	}

	// Load effective configuration once and log a masked summary. Worker-only
	// mode hard-requires the Redis queue (it Fatals below if the queue cannot
	// init), so fail fast now on a missing REDIS_URL. The DB degrades
	// gracefully, so it is not required here.
	cfg := config.Load()
	if err := cfg.Validate(false, true); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	cfg.LogSummary()

	// Initialize database (will be disabled if DATABASE_URL is not set)
	db.InitDB()

	// Initialize Redis cache (will use same Redis client as queue after queue init)
	redisURL := cfg.RedisURL
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}
	// Initialize cache - will be updated to use queue's client after queue init
	if err := utils.InitCache(redisURL); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to initialize cache, continuing without caching")
	} else {
		log.Info("Cache initialized successfully")
	}

	// Start the cache invalidation subscriber so local in-process state is
	// busted on cross-replica invalidations.
	go utils.StartCacheInvalidationSubscriber(bgCtx)
	// MED-cache-refresh: periodically re-sync the local pattern-version counter
	// from Redis as a belt-and-suspenders fallback for dropped pub/sub
	// invalidations, so a partitioned pod cannot serve stale metadata until TTL.
	utils.StartPatternVersionRefresher(bgCtx, time.Minute)
	// Flush buffered API-key usage on the shutdown-bound context (final flush on cancel).
	auth.StartAPIKeyUsageFlusher(bgCtx)

	// Initialize circuit breakers
	utils.InitCircuitBreakers()
	log.Info("Circuit breakers initialized")

	// Initialize Redis job queue (required for workers)
	if err := queue.InitQueue(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatal("Failed to initialize job queue - Worker pool requires Redis queue")
	}

	// Update cache to use the same Redis client as queue
	if queue.GetQueue() != nil {
		queueClient := queue.GetQueue().GetClient()
		if queueClient != nil {
			utils.InitCacheFromClient(queueClient)
		}
	}

	// MED-ioFactor: clear any per-job scan workspaces leaked by a previous
	// process (crash/OOM) before starting fresh scans.
	sweepJobWorkspaces()

	// Initialize and start worker pool
	wp := worker.NewWorkerPool(queue.GetQueue())

	// Set custom pool size if provided
	if poolSize > 0 {
		wp.SetWorkerCount(poolSize)
		log.Infof("Worker pool size set to %d", poolSize)
	}

	if err := wp.Start(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatal("Failed to start worker pool")
	}

	log.Infof("Worker pool started with %d workers (no API server)", wp.GetWorkerCount())

	// Tune database connection pool based on worker count
	if db.DatabaseRequired && db.GormDB != nil {
		db.TuneConnectionPool(wp.GetWorkerCount())
		// O-1: feed the DB connection-pool gauges so exhaustion is observable.
		startDBPoolStatsReporter(bgCtx)
	}

	// METRICS-1: single central source feeding the KEDA queue-depth gauge.
	metrics.StartQueueDepthReporter(bgCtx, func() (int64, error) {
		q := queue.GetQueue()
		if q == nil {
			return 0, nil
		}
		return q.GetQueueDepth()
	}, 10*time.Second)

	// Reliable-queue reaper: requeue jobs stuck in the processing list.
	if q := queue.GetQueue(); q != nil {
		go q.StartReaper(bgCtx, 2*time.Minute)
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Wait for shutdown signal
	<-sigChan
	log.Info("Shutting down worker pool...")

	// Stop background goroutines (reporter, reaper, cache subscriber).
	bgCancel()

	// Stop worker pool
	if err := wp.Stop(); err != nil {
		log.Errorf("Error stopping worker pool: %v", err)
	}

	// Close database connections
	if db.GormDB != nil {
		sqlDB, err := db.GormDB.DB()
		if err == nil {
			if err := sqlDB.Close(); err != nil {
				log.Errorf("Error closing database: %v", err)
			}
		}
	}

	log.Info("Worker pool exited gracefully")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
