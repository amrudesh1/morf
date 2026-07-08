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
	"errors"
	"fmt"
	"io"
	"morf/apk"
	database "morf/db"
	"morf/detect"
	"morf/ios"
	"morf/metrics"
	"morf/models"
	"morf/queue"
	"morf/response"
	"morf/storage"
	"morf/verify"
	"morf/utils"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
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

// jobLogFields builds the base structured-log field set for a loaded job. It
// carries worker_id + job_id and, crucially, re-attaches the originating
// request_id captured at enqueue (models.ScanJob.RequestID) so a scan's async
// log lines can be correlated back to the HTTP upload that produced them
// across the queue boundary. request_id is omitted when the job carries none
// (e.g. legacy jobs enqueued before this field existed) to avoid noisy empty
// fields.
func jobLogFields(workerID string, job *models.ScanJob) log.Fields {
	f := log.Fields{
		"worker_id": workerID,
		"job_id":    job.ID,
	}
	if job.RequestID != "" {
		f["request_id"] = job.RequestID
	}
	return f
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
//
// Classification is now typed-error-first: deterministic producers wrap their
// error with utils.ErrNonRetryable, so this checks errors.Is BEFORE falling back
// to the legacy substring heuristics. The substring fallback is retained only so
// errors constructed elsewhere (or in older tests) without the sentinel still
// classify correctly; new code should wrap with utils.ErrNonRetryable rather than
// relying on the message text.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	// Typed sentinel takes precedence over any string heuristic.
	if errors.Is(err, utils.ErrNonRetryable) {
		return false
	}
	if errors.Is(err, utils.ErrRetryable) {
		return true
	}
	// Legacy fallback: substring match for deterministic failures produced
	// without the sentinel.
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

// retryTuning holds the config-driven retry knobs for the worker's failure
// handling. Read once at package init so a hot loop does not re-parse env on
// every failure. Overridable via:
//   - MORF_WORKER_MAX_RETRIES     (int,      default 3)
//   - MORF_WORKER_RETRY_BASE      (duration, default 2s)
//   - MORF_WORKER_RETRY_MAX       (duration, default 30s)
var (
	workerMaxRetries  = envInt("MORF_WORKER_MAX_RETRIES", 3)
	workerRetryBase   = envDuration("MORF_WORKER_RETRY_BASE", 2*time.Second)
	workerRetryMaxDur = envDuration("MORF_WORKER_RETRY_MAX", 30*time.Second)
)

// retryBackoff returns an exponential delay keyed on the (1-based) retry count so
// transient failures are not requeued in a tight loop. Capped (workerRetryMaxDur)
// to keep a worker from sleeping for an unbounded time.
func retryBackoff(retryCount int) time.Duration {
	base := workerRetryBase
	max := workerRetryMaxDur
	if base <= 0 {
		base = 2 * time.Second
	}
	if max <= 0 {
		max = 30 * time.Second
	}
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
			// Send heartbeat. Log a failed heartbeat so a live-but-Redis-unreachable
			// worker is observable instead of silently appearing dead to the reaper.
			if err := w.queue.UpdateWorkerHeartbeat(workerID); err != nil {
				log.WithFields(log.Fields{
					"worker_id": workerID,
					"error":     err.Error(),
				}).Warn("Failed to update worker heartbeat")
			}

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
	//
	// R-2: ackJob is the gate. It defaults to true (the normal case), but a
	// terminal-transition Redis failure (UpdateJob fails on the success or
	// failure path) sets it false so the job is LEFT in the processing list for
	// the reaper to recover, rather than being silently dropped by an Ack that
	// fires after a state-update that never persisted.
	ackJob := true
	defer func() {
		if ackJob {
			w.queue.AckJob(workerID, jobID)
		}
	}()

	// job is declared here (not via := below) so the C-1 recover defer can route
	// it through handleJobFailure on panic.
	var job *models.ScanJob

	// C-1: recover from any panic in scanning so it never escapes this worker
	// goroutine and crashes the process. Registered AFTER the Ack defer so it runs
	// FIRST on unwind: it logs the panic + stack and routes the job through
	// handleJobFailure (advancing RetryCount so the job reaches the DLQ), then the
	// Ack defer removes the processing entry.
	defer func() {
		if r := recover(); r != nil {
			// Include request_id when the job was already loaded (job != nil) so
			// even a panic is traceable back to the originating upload.
			fields := log.Fields{
				"worker_id": workerID,
				"job_id":    jobID,
				"panic":     fmt.Sprintf("%v", r),
				"stack":     string(debug.Stack()),
			}
			if job != nil && job.RequestID != "" {
				fields["request_id"] = job.RequestID
			}
			log.WithFields(fields).Error("Recovered from panic while processing job")
			if job != nil {
				ackJob = w.handleJobFailure(ctx, workerID, job, fmt.Errorf("panic in scan: %v", r))
			}
		}
	}()

	// CONC-7 (Row 029): emit heartbeats for the ENTIRE duration of this job from a
	// dedicated goroutine. The Start loop's heartbeat ticker only fires in its
	// select loop, which is blocked for the whole synchronous processJob call — so
	// without this a scan lasting longer than the reaper's staleAfter window would
	// be mistaken for a dead worker, requeued, and double-run concurrently. The
	// goroutine ticks every 30s and stops when processJob returns (heartbeatDone is
	// closed via defer on every return path).
	heartbeatDone := make(chan struct{})
	defer close(heartbeatDone)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatDone:
				return
			case <-ticker.C:
				// Log a failed heartbeat so a live-but-Redis-unreachable worker is
				// observable instead of silently appearing dead to the reaper.
				if err := w.queue.UpdateWorkerHeartbeat(workerID); err != nil {
					log.WithFields(log.Fields{
						"worker_id": workerID,
						"job_id":    jobID,
						"error":     err.Error(),
					}).Warn("Failed to update worker heartbeat")
				}
			}
		}
	}()

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

	// IDEMPOTENCY SHORT-CIRCUIT (at-least-once redelivery): the reliable queue
	// guarantees at-least-once delivery, so a job that already reached a terminal
	// state (completed or failed) can be re-delivered — e.g. a worker finished the
	// work and persisted the result but crashed BEFORE Ack, leaving the job in its
	// processing list for the reaper to requeue. Re-running it would duplicate all
	// the work (decompile + scan + DB writes) and overwrite a good result. If the
	// job is already terminal, Ack it (remove it from the processing list) and
	// return immediately rather than reprocessing. Cancelled is handled just below
	// (it additionally drops the uploaded artifact).
	if job.Status == models.JobStatusCompleted || job.Status == models.JobStatusFailed {
		fields := jobLogFields(workerID, job)
		fields["status"] = string(job.Status)
		log.WithFields(fields).Info("Job already terminal on redelivery; acking without reprocessing (idempotency)")
		// ackJob is already true (the deferred Ack will remove it from the
		// processing list). Nothing else to do.
		return
	}

	// Check if job is cancelled
	if job.Status == models.JobStatusCancelled {
		log.WithFields(jobLogFields(workerID, job)).Info("Job was cancelled, skipping")
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
		fields := jobLogFields(workerID, job)
		fields["error"] = err.Error()
		log.WithFields(fields).Error("Failed to update job status")
		return
	}

	// MED-reaper-fp: claim the job lease so that if this worker is later FALSELY
	// reaped and the job re-delivered, the new owner overwrites this lease and our
	// terminal write is fenced off (see handleJobSuccess). Best-effort: a lease
	// error does not abort the scan.
	if err := w.queue.SetJobLease(jobID, workerID); err != nil {
		fields := jobLogFields(workerID, job)
		fields["error"] = err.Error()
		log.WithFields(fields).Warn("Failed to set job lease (continuing; fencing degraded)")
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
					log.WithFields(jobLogFields(workerID, job)).Info("Job cancelled by user; aborting scan")
					scanCancel()
					return
				}
			}
		}
	}()

	// MED-reaper-fp: verify we still OWN the lease BEFORE the expensive
	// decompile/scan, not only before the terminal write. If this worker was
	// falsely reaped and the job re-delivered to another worker that has since
	// taken the lease, there is no point spending a full decompile + scan whose
	// result would be fenced off at the terminal write anyway — abandon early and
	// Ack out cleanly. Fail-open: a missing/unreadable lease (err != nil) does NOT
	// abort the scan, so a transient lease-read blip never drops legitimate work.
	if owns, lerr := w.queue.CheckJobLease(jobID, workerID); lerr == nil && !owns {
		log.WithFields(jobLogFields(workerID, job)).Warn("Job lease taken over by another worker before scan; abandoning without reprocessing")
		// ackJob remains true: remove this stale delivery from our processing list.
		return
	}

	// Process the artifact with timeout. Dispatch on the job's FileType platform
	// discriminator: an "ipa" job runs the iOS pipeline (scanIPA), everything else
	// (including an empty FileType, which is legacy Android) runs scanAPK. Both
	// return the same gin.H result shape consumed by handleJobSuccess.
	var result gin.H
	if strings.EqualFold(job.FileType, "ipa") {
		result, err = w.scanIPA(scanCtx, job)
	} else {
		result, err = w.scanAPK(scanCtx, job)
	}
	if err != nil {
		// Check if error is due to timeout
		if scanCtx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("scan timeout exceeded (%v): %v", scanTimeout, err)
		}
		// Check if job was cancelled (terminal — do not treat as a failure to retry).
		updatedJob, getErr := w.queue.GetJob(jobID)
		if getErr == nil && updatedJob.Status == models.JobStatusCancelled {
			log.WithFields(jobLogFields(workerID, job)).Info("Job was cancelled, skipping failure handling")
			// DISK-1: cancelled is terminal; remove its uploaded artifact.
			deleteUploadedArtifact(job)
			return
		}

		// Handle failure
		ackJob = w.handleJobFailure(ctx, workerID, job, err)
		return
	}

	// Handle success
	ackJob = w.handleJobSuccess(ctx, workerID, job, result)
}

// scanAPK performs the actual APK scanning.
// Each phase is timed and emitted as a structured log field
// (decompile_ms, meta_ms, pattern_ms, db_ms, total_ms) so log aggregators
// can break down per-phase latency without parsing free-form messages.
func (w *Worker) scanAPK(ctx context.Context, job *models.ScanJob) (gin.H, error) {
	scanStart := time.Now()
	// Seed the timings field set with job_id and the originating request_id (when
	// present) so every per-phase timing line is correlated to the upload.
	timings := log.Fields{"job_id": job.ID}
	if job.RequestID != "" {
		timings["request_id"] = job.RequestID
	}

	// Create job context. MED-ioFactor(2): key the on-disk workspace directory on
	// the job ID (deterministic) rather than a random UUID, so a stray workspace
	// can be correlated back to its job.
	jobCtx := utils.NewJobContextForID(job.ID)

	// Create workspace
	if err := jobCtx.CreateWorkspace(); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %v", err)
	}
	defer jobCtx.CleanupWorkspace()

	// UI phase: preparing the workspace / fetching the package bytes.
	_ = w.queue.SetJobPhase(job.ID, "unpacking")

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

	// S-5: gate every job on the zip-bomb / zip-slip check at the EARLIEST per-job
	// entry — before the duplicate lookup, metadata extraction, or any JVM/tool
	// runs on the bytes. A failure here fails the job deterministically. Tag it
	// with ErrNonRetryable so isRetryable classifies it via errors.Is (typed),
	// not the message text.
	if err := utils.CheckAPKSafe(localPath); err != nil {
		return nil, fmt.Errorf("safety check failed: %w: %w", utils.ErrNonRetryable, err)
	}

	// Check for duplicate (hash is computed from the resolved local file).
	if database.DatabaseRequired && database.GormDB != nil {
		dupStart := time.Now()
		apkFound, jsonData := utils.CheckDuplicateInDB(database.GormDB, localPath)
		timings["dup_check_ms"] = time.Since(dupStart).Milliseconds()
		if apkFound {
			// Parse existing result and return.
			existingSecret, err := response.ParseExistingSecret(jsonData)
			if err == nil {
				// Row 030: only record the 'duplicate' metric and emit the timings
				// line on the SUCCESSFUL duplicate path. If parsing fails we fall
				// through to a full scan (which records 'success'); recording
				// 'duplicate' here too would double-count one job as both.
				metrics.RecordScan("duplicate")
				timings["total_ms"] = time.Since(scanStart).Milliseconds()
				timings["outcome"] = "duplicate"
				log.WithFields(timings).Info("Scan phase timings")
				// A-1: mirror apk/analysis.go handleExistingAPK — enrich the
				// duplicate envelope with component/resource fields so the async
				// (worker) path returns the same shape as the synchronous path.
				apiHandler := response.NewAPIResponseHandler(existingSecret, existingSecret.SecretModel)
				metadataHandler := response.NewMetadataHandler(existingSecret.Metadata)
				resourceHandler := response.NewResourceHandler(existingSecret.Metadata.ResourceData)
				resp := apiHandler.CreateDuplicateResponse()
				metadataHandler.AddMetadataToResponse(resp, &existingSecret)
				resourceHandler.AddResourceDataToResponse(resp)
				return resp, nil
			}
			// Parse failed: fall through to a full metadata+secret scan WITHOUT
			// recording a duplicate metric or timings line (Row 030).
			dupFields := jobLogFields(job.WorkerID, job)
			dupFields["error"] = err.Error()
			log.WithFields(dupFields).Warn("Failed to parse existing duplicate secret; falling through to full scan")
		}
	}

	// Phase: extract metadata + package data (apkanalyzer / aapt)
	_ = w.queue.SetJobPhase(job.ID, "parsing")
	metaStart := time.Now()
	// R-1: thread scanCtx into metadata extraction and propagate its error so an
	// apkanalyzer/open/unmarshal failure fails the job instead of silently
	// returning an empty metadata model.
	metadata, packageModel, metaErr := apk.ExtractMetadataAndPackageData(ctx, localPath, jobCtx)
	timings["meta_ms"] = time.Since(metaStart).Milliseconds()
	if metaErr != nil {
		timings["outcome"] = "failed"
		timings["total_ms"] = time.Since(scanStart).Milliseconds()
		log.WithFields(timings).Warn("Scan phase timings (failed)")
		return nil, fmt.Errorf("metadata extraction failed: %w", metaErr)
	}

	// Phase: secret scan. CONC-1: use the ctx-aware StartSecScanE and propagate its
	// error so a failed scan fails the job instead of being silently swallowed. The
	// scanCtx (this ctx) threads the per-job timeout and explicit cancellation into
	// every subprocess.
	_ = w.queue.SetJobPhase(job.ID, "scanning")
	scanPhaseStart := time.Now()
	scannerData, scanErr := apk.StartSecScanE(ctx, localPath, jobCtx)
	timings["scan_ms"] = time.Since(scanPhaseStart).Milliseconds()
	if scanErr != nil {
		timings["outcome"] = "failed"
		timings["total_ms"] = time.Since(scanStart).Milliseconds()
		log.WithFields(timings).Warn("Scan phase timings (failed)")
		return nil, fmt.Errorf("secret scan failed: %w", scanErr)
	}

	// StartSecScanE already sanitized (deduplicated) the findings. Post-process
	// them through the shared precision + verification stages before assembling
	// the dossier: ApplyPrecision drops/downgrades false positives deterministically,
	// then VerifySecrets stamps a VerificationStatus (a no-op "unchecked" unless
	// MORF_ENABLE_VERIFICATION=true). The scan ctx threads timeout/cancellation.
	scannerData = detect.ApplyPrecision(scannerData)
	scannerData = verify.VerifySecrets(ctx, scannerData)

	// UI phase: assembling + persisting the dossier.
	_ = w.queue.SetJobPhase(job.ID, "compiling")
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

	// Create response using response handlers. A-1: mirror apk/analysis.go's
	// synchronous builder — enrich the success envelope with component/resource
	// fields so the async (worker) path returns the same shape.
	apiHandler := response.NewAPIResponseHandler(secret, scannerData)
	metadataHandler := response.NewMetadataHandler(secret.Metadata)
	resourceHandler := response.NewResourceHandler(secret.Metadata.ResourceData)
	result := apiHandler.CreateSuccessResponse()
	metadataHandler.AddMetadataToResponse(result, &secret)
	resourceHandler.AddResourceDataToResponse(result)

	return result, nil
}

// scanIPA performs the actual iOS (.ipa) scanning. It is the iOS analogue of
// scanAPK and returns the SAME gin.H result envelope shape so handleJobSuccess,
// the /results/:jobID reader, and webhook subscribers stay platform-agnostic.
//
// It mirrors scanAPK's structure: create the workspace, resolve the artifact via
// the shared resolveAPKPath (an .ipa is just a file in the storage backend, keyed
// on StorageKey exactly like an APK), gate it on the shared zip-bomb/zip-slip
// check (an .ipa is a zip), short-circuit on a duplicate, run the iOS extraction
// pipeline (ios.StartIOSExtraction: unzip + Mach-O strings + plist + frameworks +
// corpus scan), persist a platform="ios" secret with its IOSMetadata, and build
// the result with the iOS metadata handler. Per-phase timings (unzip/macho/plist
// aggregated as the extract phase) are emitted as structured fields.
func (w *Worker) scanIPA(ctx context.Context, job *models.ScanJob) (gin.H, error) {
	scanStart := time.Now()
	timings := log.Fields{"job_id": job.ID, "platform": "ios"}
	if job.RequestID != "" {
		timings["request_id"] = job.RequestID
	}

	// Deterministic per-job workspace keyed on the job ID (MED-ioFactor(2)).
	jobCtx := utils.NewJobContextForID(job.ID)
	if err := jobCtx.CreateWorkspace(); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %v", err)
	}
	defer jobCtx.CleanupWorkspace()

	// UI phase: preparing the workspace / fetching the package bytes.
	_ = w.queue.SetJobPhase(job.ID, "unpacking")

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("job cancelled")
	default:
	}

	// SCALE-1 / DISK-1: resolve a usable local path for the .ipa from the storage
	// backend (reused verbatim from the APK path — resolution is content-agnostic).
	localPath, err := w.resolveAPKPath(ctx, job, jobCtx)
	if err != nil {
		return nil, err
	}

	// S-5: gate on the shared zip-bomb / zip-slip check before any extraction. An
	// .ipa is a zip archive, so the same guard applies. Tag deterministic.
	if err := utils.CheckAPKSafe(localPath); err != nil {
		return nil, fmt.Errorf("safety check failed: %w: %w", utils.ErrNonRetryable, err)
	}

	// Duplicate check: the hash is computed from the resolved local file, exactly
	// as for APKs, so a re-uploaded .ipa short-circuits to the stored result.
	if database.DatabaseRequired && database.GormDB != nil {
		dupStart := time.Now()
		found, jsonData := utils.CheckDuplicateInDB(database.GormDB, localPath)
		timings["dup_check_ms"] = time.Since(dupStart).Milliseconds()
		if found {
			if existingSecret, perr := response.ParseExistingSecret(jsonData); perr == nil {
				metrics.RecordScan("duplicate")
				timings["total_ms"] = time.Since(scanStart).Milliseconds()
				timings["outcome"] = "duplicate"
				log.WithFields(timings).Info("Scan phase timings")
				apiHandler := response.NewAPIResponseHandler(existingSecret, existingSecret.SecretModel)
				return apiHandler.CreateDuplicateResponse(), nil
			}
			dupFields := jobLogFields(job.WorkerID, job)
			log.WithFields(dupFields).Warn("Failed to parse existing duplicate iOS secret; falling through to full scan")
		}
	}

	// Phase: iOS extraction pipeline (unzip + macho + plist + frameworks + scan).
	// Record per-tool metrics for the phases the pipeline drives so iOS scans are
	// observable alongside the APK tool metrics.
	_ = w.queue.SetJobPhase(job.ID, "scanning")
	extractStart := time.Now()
	secretsModels, iosMeta, extractErr := ios.StartIOSExtraction(ctx, localPath, jobCtx)
	extractDur := time.Since(extractStart)
	timings["extract_ms"] = extractDur.Milliseconds()
	// The pipeline internally runs unzip -> macho parse -> plist parse; attribute
	// the aggregate extraction time to each tool name so the tool-execution
	// histogram carries ipa_unzip / macho_parse / plist_parse series.
	metrics.RecordToolExecution("ipa_unzip", extractDur.Seconds())
	metrics.RecordToolExecution("macho_parse", extractDur.Seconds())
	metrics.RecordToolExecution("plist_parse", extractDur.Seconds())
	if extractErr != nil {
		timings["outcome"] = "failed"
		timings["total_ms"] = time.Since(scanStart).Milliseconds()
		log.WithFields(timings).Warn("Scan phase timings (failed)")
		return nil, fmt.Errorf("ios extraction failed: %w", extractErr)
	}

	// StartIOSExtraction already sanitized (deduplicated) the findings. Post-process
	// them through the shared precision + verification stages before assembling
	// the dossier, identically to the APK path: ApplyPrecision drops/downgrades
	// false positives deterministically, then VerifySecrets stamps a
	// VerificationStatus (a no-op "unchecked" unless MORF_ENABLE_VERIFICATION=true).
	// The scan ctx threads timeout/cancellation.
	secretsModels = detect.ApplyPrecision(secretsModels)
	secretsModels = verify.VerifySecrets(ctx, secretsModels)

	// Build the legacy-shaped Secrets carrier. iOS has no apkanalyzer package
	// data; the hash is computed from the resolved file (same helper as the
	// duplicate check) and the bundle identifier/version are carried on the
	// IOSMetadata row rather than the Android package_data columns.
	// UI phase: assembling + persisting the dossier.
	_ = w.queue.SetJobPhase(job.ID, "compiling")
	apkHash := utils.ExtractHash(localPath)
	secret := models.Secrets{
		FileName:    job.OriginalFilename,
		APKHash:     apkHash,
		APKVersion:  iosMeta.BundleVersion,
		SecretModel: models.SecretModelArray(secretsModels),
		PackageDataModel: models.PackageDataModel{
			APKHash:     apkHash,
			PackageName: iosMeta.BundleIdentifier,
			VersionName: iosMeta.BundleVersion,
		},
	}

	// Phase: persist. iOS routes through InsertSecretsIOS which stamps
	// platform="ios", skips the Android component tables, and links the
	// ios_metadata row to the created secret.
	if database.DatabaseRequired && database.GormDB != nil {
		dbStart := time.Now()
		database.InsertSecretsIOS(secret, iosMeta)
		timings["db_ms"] = time.Since(dbStart).Milliseconds()
	}

	timings["secret_count"] = len(secretsModels)
	timings["total_ms"] = time.Since(scanStart).Milliseconds()
	timings["outcome"] = "success"
	log.WithFields(timings).Info("Scan phase timings")

	// Build the response with the iOS metadata handler so the envelope carries
	// the iOS fields (bundle identity, architectures, encryption, frameworks, …)
	// in place of the Android component fields.
	apiHandler := response.NewAPIResponseHandler(secret, secretsModels)
	iosHandler := response.NewIOSMetadataHandler(iosMeta)
	result := apiHandler.CreateSuccessResponse()
	iosHandler.AddMetadataToResponse(result)

	return result, nil
}

// freeBytesOnFS returns the number of bytes available to an unprivileged process
// on the filesystem backing dir. The bool is false when the free space cannot be
// determined (e.g. syscall.Statfs is unsupported on the platform), in which case
// callers fail-open and skip the admission check. syscall.Statfs is available on
// linux and darwin (MORF's build/runtime targets); the uint64 casts keep the
// arithmetic identical across the two platforms' differing Statfs_t field types.
func freeBytesOnFS(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}

// checkDiskAdmission (SC-3) refuses a job pre-flight if the workspace filesystem
// lacks enough free space to hold the APK plus its decompiled expansion. The
// decompiled tree (apktool sources + decoded resources) is typically many times
// the archive size, so we require objSize * factor bytes free. The multiplier is
// tunable via MORF_DISK_DECOMPILE_FACTOR (default 20). It fails open when the
// object size is unknown (<= 0) or the free space cannot be measured, so the
// check never spuriously blocks a scan on a platform where it cannot measure.
func checkDiskAdmission(workspaceDir string, objSize int64) error {
	if objSize <= 0 {
		return nil
	}
	factor := int64(envInt("MORF_DISK_DECOMPILE_FACTOR", 20))
	required := uint64(objSize) * uint64(factor)
	free, ok := freeBytesOnFS(workspaceDir)
	if !ok {
		return nil // cannot measure free space; fail-open rather than block.
	}
	if free < required {
		return fmt.Errorf("insufficient disk for scan: need ~%d bytes (apk %d x%d expansion) but only %d free on workspace filesystem", required, objSize, factor, free)
	}
	return nil
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
			// SC-3: disk admission control — refuse to stream + decompile an object
			// that cannot fit (with decompile expansion) on the workspace filesystem,
			// BEFORE opening the object or copying any bytes.
			if size, statErr := store.Stat(ctx, key); statErr == nil {
				if admitErr := checkDiskAdmission(jobCtx.GetTmpDir(), size); admitErr != nil {
					return "", admitErr
				}
			}

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

	// SC-3: also gate the resolved local file (legacy APKPath or local backend,
	// where no streaming copy happens) on decompile-expansion headroom so a scan
	// is not started on a filesystem that cannot hold the decompiled tree.
	if admitErr := checkDiskAdmission(jobCtx.GetTmpDir(), st.Size()); admitErr != nil {
		return "", admitErr
	}
	return localPath, nil
}

// handleJobSuccess handles successful job completion.
// A schema_version field is stamped onto the result so consumers can detect
// shape changes without a probing dance.
// It returns whether the job should be acked out of the processing list. It
// returns false when a terminal Redis transition fails (so the reaper recovers
// the job instead of it being silently dropped by the deferred Ack).
func (w *Worker) handleJobSuccess(ctx context.Context, workerID string, job *models.ScanJob, result gin.H) bool {
	// MED-reaper-fp: if this worker no longer owns the job lease, it was falsely
	// reaped and the job re-delivered to (and possibly already completed by)
	// another worker. Abandon this stale result write so we never overwrite the
	// current owner's outcome; ack out so this worker stops cleanly. Fail-open: a
	// missing/unreadable lease (err != nil) does NOT block the write.
	if owns, err := w.queue.CheckJobLease(job.ID, workerID); err == nil && !owns {
		log.WithFields(jobLogFields(workerID, job)).Warn("Job lease taken over by another worker (false-reap); abandoning stale success write")
		return true
	}

	// Stamp schema version on the persisted/served result.
	if result != nil {
		result["schema_version"] = scanResultSchemaVersion
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		// Row 031: a marshal failure is a genuine failure, not a success. Route it
		// through handleJobFailure so the job is DLQ'd/retried, the uploaded
		// artifact is cleaned up on the failure path, and a FAILURE webhook (not a
		// success one) is dispatched — instead of falling through the success tail
		// (which would record a "success" metric and fire a success webhook for a
		// job that actually failed).
		mf := jobLogFields(workerID, job)
		mf["error"] = err.Error()
		log.WithFields(mf).Error("Failed to marshal result")
		return w.handleJobFailure(ctx, workerID, job, fmt.Errorf("failed to marshal result: %w", err))
	}

	now := time.Now()
	job.Status = models.JobStatusCompleted
	job.CompletedAt = &now
	job.Result = string(resultJSON)

	// Update job in Redis
	if err := w.queue.UpdateJob(job); err != nil {
		// R-2: the success transition did not persist. Do NOT ack — a deferred
		// Ack would drop the job from the processing list while Redis still shows
		// it as in-flight, silently losing it. Returning false leaves it for the
		// reaper to recover and re-run (at-least-once).
		pf := jobLogFields(workerID, job)
		pf["error"] = err.Error()
		log.WithFields(pf).Error("Failed to persist completed job in Redis; not acking so reaper recovers it")
		return false
	}

	// MED-reaper-fp: terminal success persisted — release the lease.
	w.queue.ClearJobLease(job.ID)

	log.WithFields(jobLogFields(workerID, job)).Info("Job completed successfully")

	metrics.RecordScan("success")

	// DISK-1: terminal success — the uploaded artifact is no longer needed.
	deleteUploadedArtifact(job)

	// Deliver webhook if configured (bounded + tracked).
	if job.WebhookURL != "" {
		w.dispatchWebhook(job, result, false)
	}
	return true
}

// dispatchWebhook fires a webhook delivery asynchronously, but bounded by
// webhookSem (at most maxConcurrentWebhooks concurrent deliveries) and tracked by
// webhookWG (so the pool can drain outstanding deliveries via WaitWebhooks on
// shutdown). WEBHOOK-1: replaces the previous unbounded, untracked
// `go w.deliverWebhook(...)`.
func (w *Worker) dispatchWebhook(job *models.ScanJob, result gin.H, isFailure bool) {
	// Row 032: acquire the concurrency slot BEFORE spawning the goroutine, so the
	// number of live goroutines — not merely the number of in-flight HTTP
	// deliveries — is bounded by maxConcurrentWebhooks. Previously the goroutine was
	// launched first and only blocked on the semaphore send inside itself, so a
	// burst of N completions spawned N goroutines (N-16 of them just parked on the
	// send). Acquiring here applies backpressure to the caller instead.
	webhookSem <- struct{}{}
	webhookWG.Add(1)
	go func() {
		defer webhookWG.Done()
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
		wf := log.Fields{
			"job_id":      job.ID,
			"webhook_url": utils.MaskURLForLogging(job.WebhookURL),
			"error":       err.Error(),
		}
		if job.RequestID != "" {
			wf["request_id"] = job.RequestID
		}
		log.WithFields(wf).Error("Failed to deliver webhook after retries")
		// MED-webhook-dlq: persist the exhausted delivery to a durable DLQ so it
		// is not silently lost; an operator can inspect (and later replay) it.
		if rerr := w.queue.RecordFailedWebhook(queue.FailedWebhook{
			JobID:      job.ID,
			WebhookURL: job.WebhookURL,
			JobStatus:  string(job.Status),
			Error:      err.Error(),
			RecordedAt: time.Now().Unix(),
		}); rerr != nil {
			log.WithFields(log.Fields{
				"job_id": job.ID,
				"error":  rerr.Error(),
			}).Warn("Failed to record webhook delivery in webhook DLQ")
		}
	} else {
		wf := log.Fields{
			"job_id":      job.ID,
			"webhook_url": utils.MaskURLForLogging(job.WebhookURL),
		}
		if job.RequestID != "" {
			wf["request_id"] = job.RequestID
		}
		log.WithFields(wf).Info("Webhook delivered successfully")
	}
}

// handleJobFailure handles job failure.
//
// CONC-4: failures are classified before deciding what to do. A deterministic
// (non-retryable) error — a safety rejection, a corrupt/unparseable APK, or a
// validation failure — goes straight to the DLQ with no retry, since re-running it
// only reproduces the same failure. A transient error is requeued with an
// increasing (exponential) backoff keyed on RetryCount, up to maxRetries.
// It returns whether the job should be acked out of the processing list. It
// returns false when a terminal Redis transition (UpdateJob) fails, so the
// reaper recovers the job instead of it being silently dropped by the deferred
// Ack.
func (w *Worker) handleJobFailure(ctx context.Context, workerID string, job *models.ScanJob, err error) bool {
	// MED-reaper-fp: if this worker no longer owns the lease it was falsely reaped
	// and the job re-delivered elsewhere. Abandon this stale failure transition so
	// we never overwrite (or wrongly DLQ) a job another worker now owns. Fail-open.
	if owns, lerr := w.queue.CheckJobLease(job.ID, workerID); lerr == nil && !owns {
		log.WithFields(jobLogFields(workerID, job)).Warn("Job lease taken over by another worker (false-reap); abandoning stale failure write")
		return true
	}

	now := time.Now()
	job.Status = models.JobStatusFailed
	job.FailedAt = &now
	job.Error = err.Error()
	job.RetryCount++

	maxRetries := workerMaxRetries
	retryable := isRetryable(err)
	ackJob := true

	if retryable && job.RetryCount < maxRetries {
		// CONC-4: sleep an exponential backoff before requeueing so transient
		// failures are not retried in a tight loop.
		backoff := retryBackoff(job.RetryCount)
		bf := jobLogFields(workerID, job)
		bf["retry_count"] = job.RetryCount
		bf["backoff"] = backoff.String()
		log.WithFields(bf).Info("Requeuing failed job for retry after backoff")
		// Row 033: wait the backoff in a context-aware way instead of a blocking
		// time.Sleep. A bare sleep ran on the Start-loop goroutine, so during it the
		// worker could not observe ctx cancellation (graceful shutdown) nor exit
		// promptly. On shutdown we stop waiting early and requeue immediately — the
		// job is still pushed back below, so nothing is lost.
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			log.WithFields(jobLogFields(workerID, job)).Info("Shutdown during retry backoff; requeuing immediately")
		}

		job.Status = models.JobStatusQueued
		job.StartedAt = nil
		job.WorkerID = ""
		if uerr := w.queue.UpdateJob(job); uerr == nil {
			// Requeue (RPush) BEFORE processJob's deferred AckJob removes this
			// job from the processing list, so the job is never lost in between.
			w.queue.PushJob(job.ID)
		} else {
			// R-2: the requeue transition did not persist. Do NOT push (the job
			// state in Redis is inconsistent) and do NOT ack — leave the job in
			// the processing list so the reaper recovers it instead of dropping it.
			rf := jobLogFields(workerID, job)
			rf["error"] = uerr.Error()
			log.WithFields(rf).Error("Failed to persist requeued job in Redis; not acking so reaper recovers it")
			ackJob = false
		}
		// DISK-1: do NOT delete the uploaded artifact here — the retry needs it.
	} else {
		// Non-retryable, or retries exhausted -> dead letter queue.
		if retryable {
			log.WithFields(jobLogFields(workerID, job)).Warn("Job failed after max retries, moving to DLQ")
		} else {
			nf := jobLogFields(workerID, job)
			nf["error"] = err.Error()
			log.WithFields(nf).Warn("Job failed with non-retryable error, moving to DLQ")
		}

		if uerr := w.queue.UpdateJob(job); uerr == nil {
			w.queue.MoveToDLQ(job.ID)
			// DISK-1: terminal failure — drop the uploaded artifact.
			deleteUploadedArtifact(job)
		} else {
			// R-2: the DLQ transition did not persist. Do NOT move to DLQ, do NOT
			// delete the artifact, and do NOT ack — leave the job in the processing
			// list so the reaper recovers it instead of silently dropping it.
			df := jobLogFields(workerID, job)
			df["error"] = uerr.Error()
			log.WithFields(df).Error("Failed to persist DLQ transition in Redis; not acking so reaper recovers it")
			ackJob = false
		}
	}

	metrics.RecordScan("failed")
	metrics.RecordError("job_processing")

	// Deliver webhook if configured (bounded + tracked).
	if job.WebhookURL != "" {
		w.dispatchWebhook(job, nil, true)
	}
	return ackJob
}
