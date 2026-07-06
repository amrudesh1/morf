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

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"morf/models"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

// SC-1 (single-Redis SPOF): this queue is backed by ONE Redis client. Redis is
// therefore a single point of failure and a single point of contention for the
// whole job pipeline — if it is down, slow, or partitioned, every producer and
// worker stalls. There is no replica failover or local fallback here. To keep a
// hung Redis from wedging goroutines indefinitely, every NON-blocking Redis call
// is bounded by a per-op timeout (see opCtx / MORF_REDIS_OP_TIMEOUT) so the op
// is sheddable. The intentionally-blocking BLMOVE dequeue in PopJobReliable is
// the one exception: it keeps its own (caller-supplied) block timeout.

var (
	// ErrNoJob is returned when no job is available
	ErrNoJob = errors.New("no job available")
)

// defaultOpTimeout bounds a single non-blocking Redis operation. Overridable via
// the MORF_REDIS_OP_TIMEOUT env var (any Go duration string, e.g. "3s", "500ms").
const defaultOpTimeout = 5 * time.Second

// redisOpTimeout returns the configured per-op Redis timeout, falling back to
// defaultOpTimeout when MORF_REDIS_OP_TIMEOUT is unset or invalid.
func redisOpTimeout() time.Duration {
	if v := os.Getenv("MORF_REDIS_OP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Warnf("invalid MORF_REDIS_OP_TIMEOUT %q; using default %s", v, defaultOpTimeout)
	}
	return defaultOpTimeout
}

// opCtx returns a child of q.ctx bounded by the per-op Redis timeout. Callers
// MUST defer the returned cancel. Use it for all NON-blocking Redis calls so a
// hung Redis op is sheddable (SC-1). The intentionally-blocking BLMOVE dequeue
// in PopJobReliable is exempt and keeps its own block timeout.
func (q *JobQueue) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(q.ctx, redisOpTimeout())
}

// enqueueScript atomically publishes a job (R-3). It performs, as one unit:
//   HSET job hash, SADD status:queued, EXPIRE the hash, RPUSH onto job_queue.
// Running these together means a crash can never leave a job in status:queued
// without it also being on job_queue (or vice versa).
//   KEYS[1] = job hash key, KEYS[2] = status set key, KEYS[3] = job_queue list
//   ARGV[1] = jobID, ARGV[2] = ttl seconds, ARGV[3..] = flattened hash field/value pairs
var enqueueScript = redis.NewScript(`
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('SADD', KEYS[2], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
redis.call('RPUSH', KEYS[3], ARGV[1])
return 1
`)

// JobQueue manages jobs in Redis
type JobQueue struct {
	client *redis.Client
	ctx    context.Context
}

// NewJobQueue creates a new job queue
func NewJobQueue(redisURL string) (*JobQueue, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		// Try as simple host:port
		opt = &redis.Options{
			Addr:     redisURL,
			Password: "",
			DB:       0,
		}
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return &JobQueue{
		client: client,
		ctx:    ctx,
	}, nil
}

// CreateJob creates a new job in Redis.
//
// NOTE: CreateJob + PushJob are two separate steps and are NOT atomic — a crash
// between them can leave a job in status:queued without it being on job_queue.
// Producers should prefer EnqueueJobAtomic (R-3), which performs both as one
// atomic unit. CreateJob/PushJob are retained for compatibility.
func (q *JobQueue) CreateJob(job *models.ScanJob) error {
	ctx, cancel := q.opCtx()
	defer cancel()

	// Set job hash
	key := fmt.Sprintf("morf:jobs:%s", job.ID)
	if err := q.client.HSet(ctx, key, job.ToMap()).Err(); err != nil {
		return fmt.Errorf("failed to create job: %v", err)
	}

	// Add to status set
	statusKey := fmt.Sprintf("morf:jobs:status:%s", job.Status)
	if err := q.client.SAdd(ctx, statusKey, job.ID).Err(); err != nil {
		return fmt.Errorf("failed to add to status set: %v", err)
	}

	// Set TTL (7 days)
	if err := q.client.Expire(ctx, key, 7*24*time.Hour).Err(); err != nil {
		log.Warnf("Failed to set TTL for job %s: %v", job.ID, err)
	}

	return nil
}

// EnqueueJobAtomic atomically publishes a job (R-3): it writes the job hash,
// adds it to the status:queued set, sets the 7-day TTL, and RPushes the job ID
// onto the FIFO queue in a SINGLE Redis round-trip via a Lua script. Because all
// four operations execute as one unit, a crash can never leave a job registered
// in status:queued without it also being on job_queue (the failure mode of the
// non-atomic CreateJob + PushJob pair).
//
// The job's status MUST be queued when calling this (the status set key is
// derived from job.Status); callers publishing a fresh job should set
// models.JobStatusQueued first.
func (q *JobQueue) EnqueueJobAtomic(job *models.ScanJob) error {
	jobKey := fmt.Sprintf("morf:jobs:%s", job.ID)
	statusKey := fmt.Sprintf("morf:jobs:status:%s", job.Status)
	ttlSeconds := int(7 * 24 * time.Hour / time.Second)

	hash := job.ToMap()
	args := make([]interface{}, 0, 2+2*len(hash))
	args = append(args, job.ID, ttlSeconds)
	for k, v := range hash {
		args = append(args, k, v)
	}

	ctx, cancel := q.opCtx()
	defer cancel()
	if err := enqueueScript.Run(ctx, q.client, []string{jobKey, statusKey, jobQueueKey}, args...).Err(); err != nil {
		return fmt.Errorf("failed to atomically enqueue job: %v", err)
	}
	return nil
}

// PushJob adds a job ID to the queue.
//
// CONC-3 (FIFO): append to the TAIL with RPush. Consumers pop from the HEAD
// (BLPop / BLMOVE LEFT), so RPush + head-pop yields first-in-first-out order.
// Previously this used LPush, which combined with head-popping produced LIFO
// (newest job served first) and could starve older jobs.
// --- MED-webhook-dlq -------------------------------------------------------
// Durable record of webhook deliveries that exhausted their in-process retries,
// so they are not silently logged-and-dropped. Stored as a capped Redis list of
// JSON records; an operator can inspect them via GET /api/webhook-dlq (replay
// remains a follow-up).

const webhookDLQKey = "morf:webhook_dlq"
const webhookDLQMaxLen = 1000

// FailedWebhook is one exhausted webhook delivery recorded to the webhook DLQ.
type FailedWebhook struct {
	JobID      string `json:"job_id"`
	WebhookURL string `json:"webhook_url"`
	JobStatus  string `json:"job_status"`
	Error      string `json:"error"`
	RecordedAt int64  `json:"recorded_at"`
}

// RecordFailedWebhook appends a failed delivery to the webhook DLQ list, trimmed
// to the most-recent webhookDLQMaxLen entries to bound memory.
func (q *JobQueue) RecordFailedWebhook(rec FailedWebhook) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook DLQ record: %v", err)
	}
	if err := q.client.RPush(ctx, webhookDLQKey, b).Err(); err != nil {
		return fmt.Errorf("failed to record failed webhook: %v", err)
	}
	q.client.LTrim(ctx, webhookDLQKey, -int64(webhookDLQMaxLen), -1)
	return nil
}

// GetWebhookDLQDepth returns the number of recorded failed webhook deliveries.
func (q *JobQueue) GetWebhookDLQDepth() (int64, error) {
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.LLen(ctx, webhookDLQKey).Result()
}

// GetWebhookDLQPage returns up to limit failed-webhook JSON records from offset.
func (q *JobQueue) GetWebhookDLQPage(offset, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.LRange(ctx, webhookDLQKey, int64(offset), int64(offset+limit-1)).Result()
}

// terminalJobStatuses are the states whose status sets accumulate dangling
// members once a job hash TTL-expires (MED-statusset-leak).
var terminalJobStatuses = []string{"completed", "failed", "cancelled"}

// TrimTerminalStatusSets removes members of the terminal status sets whose job
// hash no longer exists (TTL-expired), bounding the slow unbounded growth those
// sets would otherwise exhibit. Work is bounded per call (one SSCAN batch per
// set) so it is cheap on every reaper sweep; expired members are reclaimed
// incrementally over successive sweeps.
func (q *JobQueue) TrimTerminalStatusSets() error {
	ctx, cancel := q.opCtx()
	defer cancel()
	for _, status := range terminalJobStatuses {
		setKey := fmt.Sprintf("morf:jobs:status:%s", status)
		ids, _, err := q.client.SScan(ctx, setKey, 0, "", 256).Result()
		if err != nil {
			return err
		}
		for _, id := range ids {
			n, err := q.client.Exists(ctx, fmt.Sprintf("morf:jobs:%s", id)).Result()
			if err == nil && n == 0 {
				q.client.SRem(ctx, setKey, id)
			}
		}
	}
	return nil
}

// --- MED-reaper-fp: per-job lease fencing ----------------------------------
// A best-effort ownership fence so a worker that was FALSELY reaped (its
// heartbeat went stale on a transient Redis blip while it was still alive) does
// not overwrite the result of the worker that legitimately re-picked the
// requeued job. The picking worker SETs the lease to its own ID; before writing
// a terminal result a worker checks the lease is still its own and abandons the
// write if another worker has taken over. Combined with the idempotent,
// LREM-count-guarded reaper requeue (SCALE-1) this makes a false reap harmless.
// The check fails OPEN (a missing/unreadable lease never blocks a write), so the
// fence can only suppress a provably-stale writer, never a legitimate one.

const jobLeaseTTL = 2 * time.Hour

func jobLeaseKey(jobID string) string { return fmt.Sprintf("morf:jobs:lease:%s", jobID) }

// SetJobLease records workerID as the current owner of jobID (called at pickup).
func (q *JobQueue) SetJobLease(jobID, workerID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.Set(ctx, jobLeaseKey(jobID), workerID, jobLeaseTTL).Err()
}

// CheckJobLease reports whether workerID still owns jobID's lease. A missing
// lease or a Redis error returns true (fail-open) so the fence never blocks a
// legitimate terminal write — it only suppresses a writer that has been
// provably superseded by another owner.
func (q *JobQueue) CheckJobLease(jobID, workerID string) (bool, error) {
	ctx, cancel := q.opCtx()
	defer cancel()
	owner, err := q.client.Get(ctx, jobLeaseKey(jobID)).Result()
	if err == redis.Nil {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return owner == workerID, nil
}

// ClearJobLease removes a job's lease once it reaches a terminal state.
func (q *JobQueue) ClearJobLease(jobID string) {
	ctx, cancel := q.opCtx()
	defer cancel()
	q.client.Del(ctx, jobLeaseKey(jobID))
}

func (q *JobQueue) PushJob(jobID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.RPush(ctx, jobQueueKey, jobID).Err()
}

// jobQueueKey is the main FIFO queue list key.
const jobQueueKey = "morf:job_queue"

// processingKey returns the per-worker in-flight ("processing") list key.
// Pure helper, unit-tested in queue_test.go.
func processingKey(workerID string) string {
	return fmt.Sprintf("morf:processing:%s", workerID)
}

// PopJobReliable implements the reliable-queue (at-least-once) pattern.
//
// CONC-2: instead of BLPop (which removes the job from Redis the instant it is
// handed to a worker — so a worker crash before completion silently loses the
// job), it BLMOVEs the job from the HEAD of "morf:job_queue" (LEFT) to the TAIL
// of the per-worker processing list "morf:processing:<workerID>" (RIGHT). The
// move is atomic, so the job is never in limbo: it is either in the main queue
// or in exactly one worker's processing list. If the worker crashes, the job
// remains in its processing list and the reaper (StartReaper) requeues it.
//
// At-least-once semantics: the worker MUST call AckJob once the job reaches a
// terminal state. A job may run twice if a worker dies AFTER finishing the work
// but BEFORE Ack — this is acceptable; downstream processing must be idempotent.
//
// Returns ErrNoJob if nothing arrives within timeout. timeout==0 blocks forever
// (standard BLMOVE semantics).
func (q *JobQueue) PopJobReliable(timeout time.Duration, workerID string) (string, error) {
	dest := processingKey(workerID)
	jobID, err := q.client.BLMove(q.ctx, jobQueueKey, dest, "LEFT", "RIGHT", timeout).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrNoJob
		}
		return "", err
	}
	return jobID, nil
}

// AckJob acknowledges that a job has reached a terminal state (completed, moved
// to the DLQ, or requeued) and removes it from the worker's processing list.
// Must be called exactly once per PopJobReliable to avoid the reaper later
// re-delivering an already-handled job. Removes a single occurrence (count 1).
func (q *JobQueue) AckJob(workerID, jobID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.LRem(ctx, processingKey(workerID), 1, jobID).Err()
}

// RequeueProcessing moves a job from a worker's processing list back onto the
// main queue (LREM from processing, then RPush to the tail of job_queue so FIFO
// order is preserved). Used by the reaper for dead workers and on retry. The
// LREM happens before the RPush so a single occurrence cannot be double-queued.
func (q *JobQueue) RequeueProcessing(workerID, jobID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	n, err := q.client.LRem(ctx, processingKey(workerID), 1, jobID).Result()
	if err != nil {
		return fmt.Errorf("failed to remove from processing list: %v", err)
	}
	// SCALE-1: only requeue when this call actually removed the job. In a
	// horizontally scaled fleet every pod runs StartReaper, so two reapers can
	// sweep the same stale worker concurrently: the first LREM removes the entry
	// and RPushes, while the second LREM removes 0 elements and must NOT RPush —
	// otherwise it injects a duplicate jobID into the main queue, breaking the
	// reliable-queue invariant (a job is in the main queue or exactly one
	// processing list). Capturing the count makes requeue idempotent.
	if n == 0 {
		return nil
	}
	if err := q.client.RPush(ctx, jobQueueKey, jobID).Err(); err != nil {
		return fmt.Errorf("failed to requeue job: %v", err)
	}
	return nil
}

// GetJob retrieves a job by ID
func (q *JobQueue) GetJob(jobID string) (*models.ScanJob, error) {
	ctx, cancel := q.opCtx()
	defer cancel()
	key := fmt.Sprintf("morf:jobs:%s", jobID)
	result, err := q.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get job: %v", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	job := &models.ScanJob{}
	if err := job.FromMap(convertMap(result)); err != nil {
		return nil, fmt.Errorf("failed to parse job: %v", err)
	}

	return job, nil
}

// isTerminalStatus reports whether a job status is terminal (no further
// transitions expected).
func isTerminalStatus(s models.JobStatus) bool {
	switch s {
	case models.JobStatusCompleted, models.JobStatusFailed, models.JobStatusCancelled:
		return true
	}
	return false
}

// nonTerminalStatuses are the status sets a job must NOT remain in once it has
// reached a terminal state.
var nonTerminalStatuses = []models.JobStatus{models.JobStatusQueued, models.JobStatusProcessing}

// UpdateJob updates a job in Redis
func (q *JobQueue) UpdateJob(job *models.ScanJob) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	key := fmt.Sprintf("morf:jobs:%s", job.ID)

	// CONC-9: read the OLD status BEFORE overwriting the hash. The previous
	// implementation HSet the new map first and then HGet "status", so
	// oldStatus already equalled the new status and the SRem/SAdd bookkeeping
	// below was always a no-op — leaking the morf:jobs:status:* sets (jobs
	// accumulated in their original status set forever).
	oldStatus, _ := q.client.HGet(ctx, key, "status").Result()

	// Update hash
	if err := q.client.HSet(ctx, key, job.ToMap()).Err(); err != nil {
		return fmt.Errorf("failed to update job: %v", err)
	}

	// MED-statusset-leak (1): re-apply the 7-day TTL on every update. CreateJob/
	// EnqueueJobAtomic set the TTL once at creation and it was never refreshed,
	// so a job that stays active longer than 7 days (slow scans, many retries)
	// would have its hash silently expire mid-flight. Refreshing here keeps an
	// actively-progressing job alive while still bounding abandoned jobs.
	if err := q.client.Expire(ctx, key, 7*24*time.Hour).Err(); err != nil {
		log.Warnf("Failed to refresh TTL for job %s: %v", job.ID, err)
	}

	// Update status sets only on an actual transition
	if oldStatus != "" && oldStatus != string(job.Status) {
		// Remove from old status set
		oldStatusKey := fmt.Sprintf("morf:jobs:status:%s", oldStatus)
		q.client.SRem(ctx, oldStatusKey, job.ID)

		// Add to new status set
		newStatusKey := fmt.Sprintf("morf:jobs:status:%s", job.Status)
		q.client.SAdd(ctx, newStatusKey, job.ID)
	}

	// MED-statusset-leak (2): once a job reaches a terminal state, ensure it no
	// longer lingers in any non-terminal status set (defends against historical
	// double-membership and bounds the queued/processing sets). The terminal sets
	// (completed/failed/cancelled) are intentionally retained for queryability;
	// their members become dangling once the job hash TTL expires. A periodic
	// trim of the terminal sets against still-existing hashes is left as residual.
	if isTerminalStatus(job.Status) {
		for _, st := range nonTerminalStatuses {
			q.client.SRem(ctx, fmt.Sprintf("morf:jobs:status:%s", st), job.ID)
		}
	}

	return nil
}

// MoveToDLQ moves a job to the dead letter queue
func (q *JobQueue) MoveToDLQ(jobID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()

	// Add to DLQ
	if err := q.client.LPush(ctx, "morf:dlq", jobID).Err(); err != nil {
		return fmt.Errorf("failed to move to DLQ: %v", err)
	}

	// Remove from status sets
	statuses := []string{"queued", "processing", "failed"}
	for _, status := range statuses {
		statusKey := fmt.Sprintf("morf:jobs:status:%s", status)
		q.client.SRem(ctx, statusKey, jobID)
	}

	return nil
}

// RegisterWorker registers a worker
func (q *JobQueue) RegisterWorker(workerID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	key := fmt.Sprintf("morf:workers:%s", workerID)
	now := time.Now()
	return q.client.HSet(ctx, key, map[string]interface{}{
		"id":             workerID,
		"started_at":     now.Format(time.RFC3339),
		"last_heartbeat": now.Format(time.RFC3339),
	}).Err()
}

// UnregisterWorker unregisters a worker
func (q *JobQueue) UnregisterWorker(workerID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	key := fmt.Sprintf("morf:workers:%s", workerID)
	return q.client.Del(ctx, key).Err()
}

// UpdateWorkerHeartbeat updates worker heartbeat
func (q *JobQueue) UpdateWorkerHeartbeat(workerID string) error {
	ctx, cancel := q.opCtx()
	defer cancel()
	key := fmt.Sprintf("morf:workers:%s", workerID)
	return q.client.HSet(ctx, key, "last_heartbeat", time.Now().Format(time.RFC3339)).Err()
}

// GetQueueDepth returns the current queue depth
func (q *JobQueue) GetQueueDepth() (int64, error) {
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.LLen(ctx, jobQueueKey).Result()
}

// GetDLQDepth returns the current dead letter queue depth
func (q *JobQueue) GetDLQDepth() (int64, error) {
	ctx, cancel := q.opCtx()
	defer cancel()
	return q.client.LLen(ctx, "morf:dlq").Result()
}

// GetDLQJobsPage returns a paginated slice of DLQ job IDs.
// offset >= 0; limit > 0. Inputs out of range return an empty slice.
func (q *JobQueue) GetDLQJobsPage(offset, limit int) ([]string, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		return []string{}, nil
	}
	ctx, cancel := q.opCtx()
	defer cancel()
	end := int64(offset + limit - 1)
	return q.client.LRange(ctx, "morf:dlq", int64(offset), end).Result()
}

// RetryDLQJob moves a job from DLQ back to the main queue
func (q *JobQueue) RetryDLQJob(jobID string) error {
	// Remove from DLQ
	rmCtx, rmCancel := q.opCtx()
	err := q.client.LRem(rmCtx, "morf:dlq", 1, jobID).Err()
	rmCancel()
	if err != nil {
		return fmt.Errorf("failed to remove from DLQ: %v", err)
	}

	// Get job and reset its status
	job, err := q.GetJob(jobID)
	if err != nil {
		return fmt.Errorf("failed to get job: %v", err)
	}

	// Reset job status
	job.Status = models.JobStatusQueued
	job.RetryCount = 0
	job.Error = ""
	job.StartedAt = nil
	job.FailedAt = nil
	job.WorkerID = ""

	// Update job
	if err := q.UpdateJob(job); err != nil {
		return fmt.Errorf("failed to update job: %v", err)
	}

	// Push back to queue
	if err := q.PushJob(jobID); err != nil {
		return fmt.Errorf("failed to push job: %v", err)
	}

	return nil
}

// CancelJob cancels a job
func (q *JobQueue) CancelJob(jobID string) error {
	job, err := q.GetJob(jobID)
	if err != nil {
		return fmt.Errorf("failed to get job: %v", err)
	}

	// Only cancel queued or processing jobs
	if job.Status != models.JobStatusQueued && job.Status != models.JobStatusProcessing {
		return fmt.Errorf("cannot cancel job with status: %s", job.Status)
	}

	// Store original status before updating
	originalStatus := job.Status

	// Update job status to cancelled
	now := time.Now()
	job.Status = models.JobStatusCancelled
	job.FailedAt = &now
	job.Error = "Job cancelled by user"

	// Update job in Redis
	if err := q.UpdateJob(job); err != nil {
		return fmt.Errorf("failed to update job: %v", err)
	}

	// Remove from queue if it was queued
	if originalStatus == models.JobStatusQueued {
		rmCtx, rmCancel := q.opCtx()
		q.client.LRem(rmCtx, jobQueueKey, 1, jobID)
		rmCancel()
	}

	return nil
}

// GetClient returns the underlying Redis client
func (q *JobQueue) GetClient() *redis.Client {
	return q.client
}

// Close closes the Redis client connection
func (q *JobQueue) Close() error {
	return q.client.Close()
}

// convertMap converts map[string]string to map[string]interface{}
func convertMap(m map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}
