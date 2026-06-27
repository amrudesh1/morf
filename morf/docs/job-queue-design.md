# MORF Job Queue Design

## Overview
This document describes the Redis-based job queue design for MORF to enable horizontal scaling and eliminate in-memory state.

## Redis Data Structures

### 1. Job Queue (`morf:job_queue`)
- **Type:** List (LPUSH/RPOP)
- **Purpose:** FIFO queue of job IDs waiting to be processed
- **Operations:**
  - `LPUSH morf:job_queue {jobID}` - Add job to queue
  - `RPOP morf:job_queue` - Get next job from queue
  - `BLPOP morf:job_queue 0` - Blocking pop (wait for job)

### 2. Job Details (`morf:jobs:{jobID}`)
- **Type:** Hash
- **Purpose:** Store complete job information
- **Fields:**
  - `id` - Job ID (UUID)
  - `status` - Job status (queued, processing, completed, failed, cancelled)
  - `apk_path` - Path to uploaded APK file
  - `original_filename` - Original filename
  - `created_at` - Timestamp when job was created
  - `started_at` - Timestamp when processing started
  - `completed_at` - Timestamp when processing completed
  - `failed_at` - Timestamp when job failed
  - `error` - Error message if failed
  - `result` - JSON string of scan results (when completed)
  - `worker_id` - ID of worker processing the job
  - `retry_count` - Number of retry attempts

### 3. Job Status Sets (`morf:jobs:status:{status}`)
- **Type:** Set
- **Purpose:** Track jobs by status for monitoring
- **Statuses:**
  - `morf:jobs:status:queued` - Jobs waiting in queue
  - `morf:jobs:status:processing` - Jobs currently being processed
  - `morf:jobs:status:completed` - Successfully completed jobs
  - `morf:jobs:status:failed` - Failed jobs
  - `morf:jobs:status:cancelled` - Cancelled jobs

### 4. Dead Letter Queue (`morf:dlq`)
- **Type:** List
- **Purpose:** Store jobs that failed after max retries
- **Operations:**
  - `LPUSH morf:dlq {jobID}` - Add failed job to DLQ
  - `LRANGE morf:dlq 0 -1` - List all DLQ jobs

### 5. Worker Registry (`morf:workers:{workerID}`)
- **Type:** Hash
- **Purpose:** Track active workers
- **Fields:**
  - `id` - Worker ID
  - `started_at` - When worker started
  - `last_heartbeat` - Last heartbeat timestamp
  - `current_job` - Current job ID being processed
  - `jobs_processed` - Total jobs processed

## Job States

### State Transitions
```
queued -> processing -> completed
                    -> failed -> (retry) -> processing
                              -> (max retries) -> dlq
queued -> cancelled
processing -> cancelled
```

### State Descriptions
- **queued:** Job is in queue waiting to be picked up
- **processing:** Worker has picked up job and is processing
- **completed:** Job completed successfully, results available
- **failed:** Job failed, may be retried
- **cancelled:** Job was cancelled by user
- **dlq:** Job failed after max retries

## Job Data Structure

```go
type ScanJob struct {
    ID              string    `json:"id"`
    Status          string    `json:"status"`
    APKPath         string    `json:"apk_path"`
    OriginalFilename string   `json:"original_filename"`
    CreatedAt       time.Time `json:"created_at"`
    StartedAt       *time.Time `json:"started_at,omitempty"`
    CompletedAt     *time.Time `json:"completed_at,omitempty"`
    FailedAt        *time.Time `json:"failed_at,omitempty"`
    Error           string    `json:"error,omitempty"`
    Result          string    `json:"result,omitempty"` // JSON string
    WorkerID        string    `json:"worker_id,omitempty"`
    RetryCount      int       `json:"retry_count"`
}
```

## Redis Operations

### Creating a Job
1. Generate job ID (UUID)
2. Create job hash: `HSET morf:jobs:{jobID} ...`
3. Add to status set: `SADD morf:jobs:status:queued {jobID}`
4. Push to queue: `LPUSH morf:job_queue {jobID}`

### Processing a Job
1. Worker pops job: `BLPOP morf:job_queue 0`
2. Update status: `HSET morf:jobs:{jobID} status processing started_at {timestamp} worker_id {workerID}`
3. Move status: `SREM morf:jobs:status:queued {jobID}` and `SADD morf:jobs:status:processing {jobID}`
4. Process job
5. On success: Update status to completed, store results
6. On failure: Update status to failed, increment retry count

### Getting Job Status
1. Get job hash: `HGETALL morf:jobs:{jobID}`
2. Return job details

### Job Retention
- Completed jobs: Retain for 7 days
- Failed jobs: Retain for 7 days
- DLQ jobs: Retain indefinitely (manual cleanup)
- Use Redis TTL: `EXPIRE morf:jobs:{jobID} 604800` (7 days)

## Worker Pool Design

### Worker Count Calculation
```go
workerCount := min(max(2, runtime.NumCPU() * 2), 10)
```

### Worker Lifecycle
1. Start: Register worker in Redis
2. Heartbeat: Update last_heartbeat every 30s
3. Process: BLPOP from queue, process job
4. Stop: Gracefully finish current job, unregister

### Worker Health
- Workers send heartbeat every 30s
- Workers not seen for 2 minutes are considered dead
- Dead worker's jobs are requeued

## Performance Considerations

### Queue Depth Monitoring
- Monitor `LLEN morf:job_queue` for queue depth
- Alert if queue depth > 1000

### Job Processing Rate
- Track jobs processed per second
- Monitor worker utilization

### Redis Memory
- Set max memory policy: `allkeys-lru`
- Monitor Redis memory usage
- Clean up old jobs automatically

## Error Handling

### Retry Logic
- Max retries: 3
- Exponential backoff: 1s, 2s, 4s
- Retry on: transient errors (timeouts, network errors)
- Don't retry on: validation errors, corrupted files

### Dead Letter Queue
- Jobs that fail after max retries go to DLQ
- DLQ requires manual intervention
- DLQ jobs can be manually retried

## Scalability

### Horizontal Scaling
- Multiple instances can share same Redis
- Workers from different instances process jobs
- No shared state between instances

### Load Balancing
- Jobs distributed evenly across workers
- Workers process jobs in FIFO order
- No job affinity required

## Monitoring

### Key Metrics
- Queue depth: `LLEN morf:job_queue`
- Jobs by status: `SCARD morf:jobs:status:{status}`
- Active workers: `SCARD morf:workers`
- Processing rate: Jobs completed per second

### Alerts
- Queue depth > 1000
- No active workers
- High failure rate
- DLQ depth > 100

