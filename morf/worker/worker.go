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

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"morf/apk"
	database "morf/db"
	"morf/metrics"
	"morf/models"
	"morf/queue"
	"morf/response"
	"morf/storage"
	"morf/utils"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// scanResultSchemaVersion stamps results so subscribers (frontend, webhooks,
// downstream pipelines) can branch on shape changes during evolution.
// Bump on any breaking change to result/data layout.
const scanResultSchemaVersion = "1"

// workerStore is a lazily-initialized handle to the artifact store, mirroring the
// router track's accessor. Initializing on first use (rather than at package init)
// keeps the worker package free of an init-time dependency on the storage env.
var (
	workerStoreOnce sync.Once
	workerStore     storage.Storage
)

// getWorkerStore returns the process-wide storage backend, constructing it once.
// Returns nil if construction failed (logged); callers must handle a nil store.
func getWorkerStore() storage.Storage {
	workerStoreOnce.Do(func() {
		if s, err := storage.NewFromEnv(); err == nil {
			workerStore = s
		} else {
			log.Errorf("storage init: %v", err)
		}
	})
	return workerStore
}

// WEBHOOK-1: bound and track webhook deliveries. Previously every completed or
// failed job spawned a detached `go w.deliverWebhook(...)` goroutine, so a burst
// of completions (or a slow/hung receiver) could spawn an unbounded number of
// goroutines that the pool could neither bound nor wait for on shutdown.
//
//   - webhookSem caps the number of deliveries running concurrently.
//   - webhookWG tracks outstanding deliveries so the pool can drain them on
//     shutdown via WaitWebhooks.
const maxConcurrentWebhooks = 16

var (
	webhookSem = make(chan struct{}, maxConcurrentWebhooks)
	webhookWG  sync.WaitGroup
)

// WaitWebhooks blocks until every in-flight webhook delivery finishes, or until
// timeout elapses, whichever comes first. The worker pool calls this on shutdown
// so a completed job's notification is not dropped just because the process is
// draining. Returns true if all deliveries finished before the timeout.
func WaitWebhooks(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		webhookWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// deleteUploadedArtifact removes the uploaded APK object from the storage backend
// once a job reaches a TERMINAL state (DISK-1) so uploads do not accumulate
// forever. It is a no-op for legacy jobs that carry only a direct APKPath (no
// StorageKey) — those predate the storage abstraction and are managed elsewhere.
// Deletion is best-effort: a failure is logged, never fatal, and uses a fresh
// (background) context so a cancelled/expired scan context does not block cleanup.
func deleteUploadedArtifact(job *models.ScanJob) {
	if job.StorageKey == "" {
		return
	}
	store := getWorkerStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Delete(ctx, job.StorageKey); err != nil {
		log.WithFields(log.Fields{
			"job_id":      job.ID,
			"storage_key": job.StorageKey,
			"error":       err.Error(),
		}).Warn("Failed to delete uploaded APK from storage")
		return
	}
	log.WithFields(log.Fields{
		"job_id":      job.ID,
		"storage_key": job.StorageKey,
	}).Info("Deleted uploaded APK from storage")
}

// isRetryable classifies a scan error as transient (worth retrying) or
// deterministic (will fail identically on every attempt, so retrying only wastes
// work and delays the inevitable DLQ). CONC-4.
//
// Deterministic / non-retryable: failures rooted in the APK content itself — a
// zip-bomb / safety rejection (CheckAPKSafe), a corrupt/unparseable archive that
// fails decompilation, or input validation. Re-running these produces the same
// failure, so they go straight to the DLQ with no retry.
//
// Everything else (subprocess timeouts that did not originate in decompilation,
// transient I/O, Redis/storage hiccups, a momentarily-missing artifact) is treated
// as retryable and requeued with backoff.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	nonRetryable := []string{
		"safety check failed",  // CheckAPKSafe / zip-bomb rejection (deterministic)
		"decompilation failed", // corrupt / unparseable APK (deterministic)
		"validation failed",    // input validation (deterministic)
	}
	for _, s := range nonRetryable {
		if strings.Contains(msg, s) {
			return false
		}
	}
	return true
}

// retryBackoff returns an exponential delay keyed on the (1-based) retry count so
// transient failures are not requeued in a tight loop. Capped to keep a worker
// from sleeping for an unbounded time.
func retryBackoff(retryCount int) time.Duration {
	const base = 2 * time.Second
	const max = 30 * time.Second
	d := base
	for i := 1; i < retryCount; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		d = max
	}
	return d
}

// Worker processes jobs from the queue
type Worker struct {
	id    int
	queue *queue.JobQueue
}

// NewWorker creates a new worker
func NewWorker(q *queue.JobQueue, id int) *Worker {
	return &Worker{
		id:    id,
		queue: q,
	}
}

// Start starts the worker
func (w *Worker) Start(ctx context.Context) {
	workerID := fmt.Sprintf("worker-%d-%s", w.id, uuid.New().String()[:8])

	log.WithFields(log.Fields{
		"worker_id": workerID,
	}).Info("Worker started")

	// Register worker
	w.queue.RegisterWorker(workerID)

	// Heartbeat ticker
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	// CONC-5: backoff between pop attempts after a real (non-ErrNoJob) queue error,
	// so a whole fleet of workers does not hot-spin against a down Redis.
	const popBackoffBase = 500 * time.Millisecond
	const popBackoffMax = 30 * time.Second
	popBackoff := popBackoffBase

	// Process jobs
	for {
		select {
		case <-ctx.Done():
			log.WithFields(log.Fields{
				"worker_id": workerID,
			}).Info("Worker stopping")
			w.queue.UnregisterWorker(workerID)
			return

		case <-heartbeatTicker.C:
			// Send heartbeat
			w.queue.UpdateWorkerHeartbeat(workerID)

		default:
			// CONC-2: reliable pop — the job is atomically moved into THIS worker's
			// processing list, so a crash mid-scan does not lose it (the reaper
			// requeues abandoned processing entries).
			jobID, err := w.queue.PopJobReliable(1*time.Second, workerID)
			if err != nil {
				if err == queue.ErrNoJob {
					popBackoff = popBackoffBase
					continue
				}
				log.WithFields(log.Fields{
					"worker_id": workerID,
					"error":     err.Error(),
				}).Error("Error popping job from queue")

				// CONC-5: capped exponential backoff on a real queue error. Remain
				// responsive to shutdown while sleeping.
				select {
				case <-ctx.Done():
				case <-time.After(popBackoff):
				}
				popBackoff *= 2
				if popBackoff > popBackoffMax {
					popBackoff = popBackoffMax
				}
				continue
			}
			// A successful pop resets the backoff.
			popBackoff = popBackoffBase

			// CONC-6: scanCtx inside processJob is decoupled from this pool ctx, so
			// even if ctx is cancelled mid-scan the current job drains to completion;
			// the loop then exits on the next iteration via the ctx.Done() case.
			w.processJob(ctx, workerID, jobID)
		}
	}
}

// processJob processes a single job
func (w *Worker) processJob(ctx context.Context, workerID, jobID string) {
	// CONC-2: this job was moved into our processing list by PopJobReliable. Ack it
	// on EVERY terminal-for-this-attempt outcome (success, DLQ, cancelled, or
	// requeued-for-retry) so it leaves the processing list and the reaper does not
	// later re-deliver it. A deferred Ack covers all return paths uniformly; for the
	// retry path, handleJobFailure RPushes the job back onto the main queue BEFORE
	// this Ack removes the processing entry, so the job is never in limbo.
	defer w.queue.AckJob(workerID, jobID)

	log.WithFields(log.Fields{
		"worker_id": workerID,
		"job_id":    jobID,
	}).Info("Processing job")

	// Get job details
	job, err := w.queue.GetJob(jobID)
	if err != nil {
		log.WithFields(log.Fields{
			"worker_id": workerID,
			"job_id":    jobID,
			"error":     err.Error(),
		}).Error("Failed to get job details")
		return
	}

	// Check if job is cancelled
	if job.Status == models.JobStatusCancelled {
		log.WithFields(log.Fields{
			"worker_id": workerID,
			"job_id":    jobID,
		}).Info("Job was cancelled, skipping")
		// DISK-1: a cancelled job is terminal; drop its uploaded artifact.
		deleteUploadedArtifact(job)
		return
	}

	// Update job status to processing
	now := time.Now()
	job.Status = models.JobStatusProcessing
	job.StartedAt = &now
	job.WorkerID = workerID
	if err := w.queue.UpdateJob(job); err != nil {
		log.WithFields(log.Fields{
			"worker_id": workerID,
			"job_id":    jobID,
			"error":     err.Error(),
		}).Error("Failed to update job status")
		return
	}

	// Create timeout context for scan (default 30 minutes, configurable per job)
	scanTimeout := 30 * time.Minute
	if job.ScanTimeout > 0 {
		scanTimeout = time.Duration(job.ScanTimeout) * time.Second
	}

	// CONC-1 + CONC-6: derive scanCtx from a FRESH background context, NOT from the
	// pool ctx. Rationale: the scan must honor (a) its own per-job timeout and (b) an
	// explicit user cancellation, but it must NOT be torn down merely because the
	// pool is shutting down — that would kill an in-flight scan on every deploy.
	// Decoupling lets the current job drain to completion while the Start loop exits
	// after it (graceful drain, CONC-6). Explicit user cancellation is still honored
	// by the status poller below, which cancels scanCtx when the job is cancelled.
	scanCtx, scanCancel := context.WithTimeout(context.Background(), scanTimeout)
	defer scanCancel()

	// Explicit job-cancellation handling: poll the job status and cancel scanCtx if
	// the user cancels the job mid-scan (the cancellation propagates into every
	// subprocess via StartSecScanE). Intentionally independent of the pool ctx so a
	// shutdown does not abort the scan. The poller stops when the scan finishes.
	cancelWatchDone := make(chan struct{})
	defer close(cancelWatchDone)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-scanCtx.Done():
				return
			case <-cancelWatchDone:
				return
			case <-ticker.C:
				if j, gerr := w.queue.GetJob(jobID); gerr == nil && j.Status == models.JobStatusCancelled {
					log.WithFields(log.Fields{
						"worker_id": workerID,
						"job_id":    jobID,
					}).Info("Job cancelled by user; aborting scan")
					scanCancel()
					return
				}
			}
		}
	}()

	// Process the APK with timeout
	result, err := w.scanAPK(scanCtx, job)
	if err != nil {
		// Check if error is due to timeout
		if scanCtx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("scan timeout exceeded (%v): %v", scanTimeout, err)
		}
		// Check if job was cancelled (terminal — do not treat as a failure to retry).
		updatedJob, getErr := w.queue.GetJob(jobID)
		if getErr == nil && updatedJob.Status == models.JobStatusCancelled {
			log.WithFields(log.Fields{
				"worker_id": workerID,
				"job_id":    jobID,
			}).Info("Job was cancelled, skipping failure handling")
			// DISK-1: cancelled is terminal; remove its uploaded artifact.
			deleteUploadedArtifact(job)
			return
		}

		// Handle failure
		w.handleJobFailure(workerID, job, err)
		return
	}

	// Handle success
	w.handleJobSuccess(workerID, job, result)
}

// scanAPK performs the actual APK scanning.
// Each phase is timed and emitted as a structured log field
// (decompile_ms, meta_ms, pattern_ms, db_ms, total_ms) so log aggregators
// can break down per-phase latency without parsing free-form messages.
func (w *Worker) scanAPK(ctx context.Context, job *models.ScanJob) (gin.H, error) {
	scanStart := time.Now()
	timings := log.Fields{"job_id": job.ID}

	// Create job context
	jobCtx := utils.NewJobContext()
	jobCtx.JobID = job.ID

	// Create workspace
	if err := jobCtx.CreateWorkspace(); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %v", err)
	}
	defer jobCtx.CleanupWorkspace()

	// Check for cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("job cancelled")
	default:
	}

	// SCALE-1 / DISK-1: resolve a usable local filesystem path for the APK from the
	// storage backend BEFORE any metadata extraction or scanning. In a horizontally
	// scaled fleet the pod that runs the scan is usually NOT the pod that accepted
	// the upload, so the bytes live in shared object storage keyed by StorageKey
	// rather than on this pod's local disk.
	//
	// Resolution order:
	//   - StorageKey set + local backend  -> use LocalPath directly (no copy).
	//   - StorageKey set + remote backend -> stream the object into a temp file in
	//     this job's workspace (removed on return).
	//   - StorageKey empty (legacy job)   -> APKPath is already a direct path.
	//
	// A missing object is a HARD ERROR: we must never silently scan a non-existent
	// file and report an empty (false-negative) success across pods. The returned
	// error flows into handleJobFailure so the job is failed/retried, not completed.
	localPath, err := w.resolveAPKPath(ctx, job, jobCtx)
	if err != nil {
		return nil, err
	}

	// Check for duplicate (hash is computed from the resolved local file).
	if database.DatabaseRequired && database.GormDB != nil {
		dupStart := time.Now()
		apkFound, jsonData := utils.CheckDuplicateInDB(database.GormDB, localPath)
		timings["dup_check_ms"] = time.Since(dupStart).Milliseconds()
		if apkFound {
			metrics.RecordScan("duplicate")
			timings["total_ms"] = time.Since(scanStart).Milliseconds()
			timings["outcome"] = "duplicate"
			log.WithFields(timings).Info("Scan phase timings")
			// Parse existing result and return
			existingSecret, err := response.ParseExistingSecret(jsonData)
			if err == nil {
				apiHandler := response.NewAPIResponseHandler(existingSecret, existingSecret.SecretModel)
				return apiHandler.CreateDuplicateResponse(), nil
			}
		}
	}

	// Phase: extract metadata + package data (apkanalyzer / aapt)
	metaStart := time.Now()
	metadata, packageModel := apk.ExtractMetadataAndPackageData(localPath, jobCtx)
	timings["meta_ms"] = time.Since(metaStart).Milliseconds()

	// Phase: secret scan. CONC-1: use the ctx-aware StartSecScanE and propagate its
	// error so a failed scan fails the job instead of being silently swallowed. The
	// scanCtx (this ctx) threads the per-job timeout and explicit cancellation into
	// every subprocess.
	scanPhaseStart := time.Now()
	scannerData, scanErr := apk.StartSecScanE(ctx, localPath, jobCtx)
	timings["scan_ms"] = time.Since(scanPhaseStart).Milliseconds()
	if scanErr != nil {
		timings["outcome"] = "failed"
		timings["total_ms"] = time.Since(scanStart).Milliseconds()
		log.WithFields(timings).Warn("Scan phase timings (failed)")
		return nil, fmt.Errorf("secret scan failed: %w", scanErr)
	}

	secretData, err := json.Marshal(scannerData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scanner data: %v", err)
	}
	secret := utils.CreateSecretModel(job.OriginalFilename, packageModel, metadata, scannerData, secretData)

	// Phase: persist
	if database.DatabaseRequired && database.GormDB != nil {
		dbStart := time.Now()
		database.InsertSecrets(secret, database.GormDB)
		timings["db_ms"] = time.Since(dbStart).Milliseconds()
	}

	timings["secret_count"] = len(scannerData)
	timings["total_ms"] = time.Since(scanStart).Milliseconds()
	timings["outcome"] = "success"
	log.WithFields(timings).Info("Scan phase timings")

	// Create response using response handlers
	apiHandler := response.NewAPIResponseHandler(secret, scannerData)
	result := apiHandler.CreateSuccessResponse()

	return result, nil
}

// resolveAPKPath turns the job's storage key into a local filesystem path the
// external tools can read (see scanAPK for the full SCALE-1 / DISK-1 rationale).
// For a remote backend the object is streamed into a temp file in the job's
// workspace that is removed when scanAPK returns. A missing/unreadable object is
// returned as an error so the job is never scanned-and-reported-successful.
func (w *Worker) resolveAPKPath(ctx context.Context, job *models.ScanJob, jobCtx *utils.JobContext) (string, error) {
	key := job.StorageKey

	var localPath string
	if key == "" {
		// Legacy back-compat: APKPath is already a direct filesystem path on this
		// pod (these jobs predate the storage abstraction).
		localPath = job.APKPath
	} else {
		store := getWorkerStore()
		if store == nil {
			return "", fmt.Errorf("storage backend unavailable; cannot resolve APK for key %q", key)
		}
		if p, ok := store.LocalPath(key); ok {
			// Local backend: hand the path straight to the tools (no copy).
			localPath = p
		} else {
			// Remote backend: stream the object into a temp file in the workspace.
			rc, openErr := store.Open(ctx, key)
			if openErr != nil {
				return "", fmt.Errorf("failed to open APK object %q from storage: %w", key, openErr)
			}
			defer rc.Close()

			tmpFile, tmpErr := os.CreateTemp(jobCtx.GetTmpDir(), "apk-*.apk")
			if tmpErr != nil {
				return "", fmt.Errorf("failed to create temp APK file: %w", tmpErr)
			}
			tmpPath := tmpFile.Name()
			// The temp file lives in the job workspace (cleaned by CleanupWorkspace),
			// but remove it explicitly too so it never outlives the scan.
			defer os.Remove(tmpPath)

			if _, copyErr := io.Copy(tmpFile, rc); copyErr != nil {
				tmpFile.Close()
				return "", fmt.Errorf("failed to copy APK object %q to temp file: %w", key, copyErr)
			}
			if closeErr := tmpFile.Close(); closeErr != nil {
				return "", fmt.Errorf("failed to finalize temp APK file: %w", closeErr)
			}
			localPath = tmpPath
		}
	}

	// Guard against a missing artifact regardless of backend: a local LocalPath()
	// always returns a path even when the file is absent, so verify it really exists
	// before handing it to the scanner. Missing -> hard error (never scan-and-succeed).
	st, statErr := os.Stat(localPath)
	if statErr != nil || st.IsDir() {
		return "", fmt.Errorf("apk artifact for key %q is unavailable at %q: %v", key, localPath, statErr)
	}
	return localPath, nil
}

// handleJobSuccess handles successful job completion.
// A schema_version field is stamped onto the result so consumers can detect
// shape changes without a probing dance.
func (w *Worker) handleJobSuccess(workerID string, job *models.ScanJob, result gin.H) {
	now := time.Now()
	job.Status = models.JobStatusCompleted
	job.CompletedAt = &now

	// Stamp schema version on the persisted/served result.
	if result != nil {
		result["schema_version"] = scanResultSchemaVersion
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.WithFields(log.Fields{
			"worker_id": workerID,
			"job_id":    job.ID,
			"error":     err.Error(),
		}).Error("Failed to marshal result")
		job.Error = err.Error()
		job.Status = models.JobStatusFailed
		failedAt := time.Now()
		job.FailedAt = &failedAt
	} else {
		job.Result = string(resultJSON)
	}

	// Update job in Redis
	if err := w.queue.UpdateJob(job); err != nil {
		log.WithFields(log.Fields{
			"worker_id": workerID,
			"job_id":    job.ID,
			"error":     err.Error(),
		}).Error("Failed to update job status")
		return
	}

	log.WithFields(log.Fields{
		"worker_id": workerID,
		"job_id":    job.ID,
	}).Info("Job completed successfully")

	metrics.RecordScan("success")

	// DISK-1: terminal success — the uploaded artifact is no longer needed.
	deleteUploadedArtifact(job)

	// Deliver webhook if configured (bounded + tracked).
	if job.WebhookURL != "" {
		w.dispatchWebhook(job, result, false)
	}
}

// dispatchWebhook fires a webhook delivery asynchronously, but bounded by
// webhookSem (at most maxConcurrentWebhooks concurrent deliveries) and tracked by
// webhookWG (so the pool can drain outstanding deliveries via WaitWebhooks on
// shutdown). WEBHOOK-1: replaces the previous unbounded, untracked
// `go w.deliverWebhook(...)`.
func (w *Worker) dispatchWebhook(job *models.ScanJob, result gin.H, isFailure bool) {
	webhookWG.Add(1)
	go func() {
		defer webhookWG.Done()
		webhookSem <- struct{}{}
		defer func() { <-webhookSem }()
		w.deliverWebhook(job, result, isFailure)
	}()
}

// deliverWebhook delivers webhook notification for job completion/failure.
// Sets X-MORF-Schema-Version header on outbound delivery so subscribers can
// version-pin their consumers. Headers travel separately from payload to
// avoid forcing a payload-shape change on legacy subscribers.
func (w *Worker) deliverWebhook(job *models.ScanJob, result gin.H, isFailure bool) {
	payload := models.WebhookPayload{
		JobID:         job.ID,
		Status:        string(job.Status),
		Timestamp:     time.Now(),
		SchemaVersion: scanResultSchemaVersion,
	}

	if isFailure {
		payload.Error = job.Error
	} else {
		payload.Result = result
	}

	// Deliver webhook with retry
	if err := utils.DeliverWebhookWithRetry(job.WebhookURL, job.WebhookSecret, payload); err != nil {
		log.WithFields(log.Fields{
			"job_id":      job.ID,
			"webhook_url": utils.MaskURLForLogging(job.WebhookURL),
			"error":       err.Error(),
		}).Error("Failed to deliver webhook after retries")
	} else {
		log.WithFields(log.Fields{
			"job_id":      job.ID,
			"webhook_url": utils.MaskURLForLogging(job.WebhookURL),
		}).Info("Webhook delivered successfully")
	}
}

// handleJobFailure handles job failure.
//
// CONC-4: failures are classified before deciding what to do. A deterministic
// (non-retryable) error — a safety rejection, a corrupt/unparseable APK, or a
// validation failure — goes straight to the DLQ with no retry, since re-running it
// only reproduces the same failure. A transient error is requeued with an
// increasing (exponential) backoff keyed on RetryCount, up to maxRetries.
func (w *Worker) handleJobFailure(workerID string, job *models.ScanJob, err error) {
	now := time.Now()
	job.Status = models.JobStatusFailed
	job.FailedAt = &now
	job.Error = err.Error()
	job.RetryCount++

	maxRetries := 3
	retryable := isRetryable(err)

	if retryable && job.RetryCount < maxRetries {
		// CONC-4: sleep an exponential backoff before requeueing so transient
		// failures are not retried in a tight loop.
		backoff := retryBackoff(job.RetryCount)
		log.WithFields(log.Fields{
			"worker_id":   workerID,
			"job_id":      job.ID,
			"retry_count": job.RetryCount,
			"backoff":     backoff.String(),
		}).Info("Requeuing failed job for retry after backoff")
		time.Sleep(backoff)

		job.Status = models.JobStatusQueued
		job.StartedAt = nil
		job.WorkerID = ""
		if uerr := w.queue.UpdateJob(job); uerr == nil {
			// Requeue (RPush) BEFORE processJob's deferred AckJob removes this
			// job from the processing list, so the job is never lost in between.
			w.queue.PushJob(job.ID)
		}
		// DISK-1: do NOT delete the uploaded artifact here — the retry needs it.
	} else {
		// Non-retryable, or retries exhausted -> dead letter queue.
		if retryable {
			log.WithFields(log.Fields{
				"worker_id": workerID,
				"job_id":    job.ID,
			}).Warn("Job failed after max retries, moving to DLQ")
		} else {
			log.WithFields(log.Fields{
				"worker_id": workerID,
				"job_id":    job.ID,
				"error":     err.Error(),
			}).Warn("Job failed with non-retryable error, moving to DLQ")
		}

		if uerr := w.queue.UpdateJob(job); uerr == nil {
			w.queue.MoveToDLQ(job.ID)
		}
		// DISK-1: terminal failure — drop the uploaded artifact.
		deleteUploadedArtifact(job)
	}

	metrics.RecordScan("failed")
	metrics.RecordError("job_processing")

	// Deliver webhook if configured (bounded + tracked).
	if job.WebhookURL != "" {
		w.dispatchWebhook(job, nil, true)
	}
}

// createSuccessResponse creates a success response from secret data
func createSuccessResponse(secret *models.Secrets, scannerData []models.SecretModel) gin.H {
	// This is a simplified version - should match the actual response format
	return gin.H{
		"message": "Success",
		"data": gin.H{
			"fileName":    secret.FileName,
			"packageName": secret.PackageDataModel.PackageName,
			"version":     secret.PackageDataModel.VersionName,
			"secretCount": len(scannerData),
			"secrets":     scannerData,
		},
	}
}
