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
	"errors"
	"fmt"
	"morf/models"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

var (
	// ErrNoJob is returned when no job is available
	ErrNoJob = errors.New("no job available")
)

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

// NewJobQueueFromClient creates a job queue from existing Redis client
func NewJobQueueFromClient(client *redis.Client) *JobQueue {
	return &JobQueue{
		client: client,
		ctx:    context.Background(),
	}
}

// CreateJob creates a new job in Redis
func (q *JobQueue) CreateJob(job *models.ScanJob) error {
	// Set job hash
	key := fmt.Sprintf("morf:jobs:%s", job.ID)
	if err := q.client.HSet(q.ctx, key, job.ToMap()).Err(); err != nil {
		return fmt.Errorf("failed to create job: %v", err)
	}

	// Add to status set
	statusKey := fmt.Sprintf("morf:jobs:status:%s", job.Status)
	if err := q.client.SAdd(q.ctx, statusKey, job.ID).Err(); err != nil {
		return fmt.Errorf("failed to add to status set: %v", err)
	}

	// Set TTL (7 days)
	if err := q.client.Expire(q.ctx, key, 7*24*time.Hour).Err(); err != nil {
		log.Warnf("Failed to set TTL for job %s: %v", job.ID, err)
	}

	return nil
}

// PushJob adds a job ID to the queue.
//
// CONC-3 (FIFO): append to the TAIL with RPush. Consumers pop from the HEAD
// (BLPop / BLMOVE LEFT), so RPush + head-pop yields first-in-first-out order.
// Previously this used LPush, which combined with head-popping produced LIFO
// (newest job served first) and could starve older jobs.
func (q *JobQueue) PushJob(jobID string) error {
	return q.client.RPush(q.ctx, "morf:job_queue", jobID).Err()
}

// PopJob pops a job ID from the queue (non-blocking)
func (q *JobQueue) PopJob(timeout time.Duration) (string, error) {
	if timeout > 0 {
		// Blocking pop
		result, err := q.client.BLPop(q.ctx, timeout, "morf:job_queue").Result()
		if err != nil {
			if err == redis.Nil {
				return "", ErrNoJob
			}
			return "", err
		}
		if len(result) >= 2 {
			return result[1], nil
		}
		return "", ErrNoJob
	}

	// Non-blocking pop. CONC-3: pop from the HEAD (LPop) so this path stays
	// FIFO-consistent with the blocking BLPop branch now that PushJob appends
	// to the tail. (Signature unchanged.)
	result, err := q.client.LPop(q.ctx, "morf:job_queue").Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrNoJob
		}
		return "", err
	}
	return result, nil
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
	return q.client.LRem(q.ctx, processingKey(workerID), 1, jobID).Err()
}

// RequeueProcessing moves a job from a worker's processing list back onto the
// main queue (LREM from processing, then RPush to the tail of job_queue so FIFO
// order is preserved). Used by the reaper for dead workers and on retry. The
// LREM happens before the RPush so a single occurrence cannot be double-queued.
func (q *JobQueue) RequeueProcessing(workerID, jobID string) error {
	if err := q.client.LRem(q.ctx, processingKey(workerID), 1, jobID).Err(); err != nil {
		return fmt.Errorf("failed to remove from processing list: %v", err)
	}
	if err := q.client.RPush(q.ctx, jobQueueKey, jobID).Err(); err != nil {
		return fmt.Errorf("failed to requeue job: %v", err)
	}
	return nil
}

// GetJob retrieves a job by ID
func (q *JobQueue) GetJob(jobID string) (*models.ScanJob, error) {
	key := fmt.Sprintf("morf:jobs:%s", jobID)
	result, err := q.client.HGetAll(q.ctx, key).Result()
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

// UpdateJob updates a job in Redis
func (q *JobQueue) UpdateJob(job *models.ScanJob) error {
	key := fmt.Sprintf("morf:jobs:%s", job.ID)

	// CONC-9: read the OLD status BEFORE overwriting the hash. The previous
	// implementation HSet the new map first and then HGet "status", so
	// oldStatus already equalled the new status and the SRem/SAdd bookkeeping
	// below was always a no-op — leaking the morf:jobs:status:* sets (jobs
	// accumulated in their original status set forever).
	oldStatus, _ := q.client.HGet(q.ctx, key, "status").Result()

	// Update hash
	if err := q.client.HSet(q.ctx, key, job.ToMap()).Err(); err != nil {
		return fmt.Errorf("failed to update job: %v", err)
	}

	// Update status sets only on an actual transition
	if oldStatus != "" && oldStatus != string(job.Status) {
		// Remove from old status set
		oldStatusKey := fmt.Sprintf("morf:jobs:status:%s", oldStatus)
		q.client.SRem(q.ctx, oldStatusKey, job.ID)

		// Add to new status set
		newStatusKey := fmt.Sprintf("morf:jobs:status:%s", job.Status)
		q.client.SAdd(q.ctx, newStatusKey, job.ID)
	}

	return nil
}

// MoveToDLQ moves a job to the dead letter queue
func (q *JobQueue) MoveToDLQ(jobID string) error {
	// Add to DLQ
	if err := q.client.LPush(q.ctx, "morf:dlq", jobID).Err(); err != nil {
		return fmt.Errorf("failed to move to DLQ: %v", err)
	}

	// Remove from status sets
	statuses := []string{"queued", "processing", "failed"}
	for _, status := range statuses {
		statusKey := fmt.Sprintf("morf:jobs:status:%s", status)
		q.client.SRem(q.ctx, statusKey, jobID)
	}

	return nil
}

// RegisterWorker registers a worker
func (q *JobQueue) RegisterWorker(workerID string) error {
	key := fmt.Sprintf("morf:workers:%s", workerID)
	now := time.Now()
	return q.client.HSet(q.ctx, key, map[string]interface{}{
		"id":             workerID,
		"started_at":     now.Format(time.RFC3339),
		"last_heartbeat": now.Format(time.RFC3339),
	}).Err()
}

// UnregisterWorker unregisters a worker
func (q *JobQueue) UnregisterWorker(workerID string) error {
	key := fmt.Sprintf("morf:workers:%s", workerID)
	return q.client.Del(q.ctx, key).Err()
}

// UpdateWorkerHeartbeat updates worker heartbeat
func (q *JobQueue) UpdateWorkerHeartbeat(workerID string) error {
	key := fmt.Sprintf("morf:workers:%s", workerID)
	return q.client.HSet(q.ctx, key, "last_heartbeat", time.Now().Format(time.RFC3339)).Err()
}

// GetQueueDepth returns the current queue depth
func (q *JobQueue) GetQueueDepth() (int64, error) {
	return q.client.LLen(q.ctx, "morf:job_queue").Result()
}

// GetDLQDepth returns the current dead letter queue depth
func (q *JobQueue) GetDLQDepth() (int64, error) {
	return q.client.LLen(q.ctx, "morf:dlq").Result()
}

// GetDLQJobs returns all jobs in the dead letter queue.
// Prefer GetDLQJobsPage for bounded memory on production-sized DLQs.
func (q *JobQueue) GetDLQJobs() ([]string, error) {
	return q.client.LRange(q.ctx, "morf:dlq", 0, -1).Result()
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
	end := int64(offset + limit - 1)
	return q.client.LRange(q.ctx, "morf:dlq", int64(offset), end).Result()
}

// RetryDLQJob moves a job from DLQ back to the main queue
func (q *JobQueue) RetryDLQJob(jobID string) error {
	// Remove from DLQ
	if err := q.client.LRem(q.ctx, "morf:dlq", 1, jobID).Err(); err != nil {
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
		q.client.LRem(q.ctx, "morf:job_queue", 1, jobID)
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
