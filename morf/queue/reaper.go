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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// workerKeyPrefix is the prefix under which workers register themselves
// (see RegisterWorker: "morf:workers:<id>").
const workerKeyPrefix = "morf:workers:"

// reaperScanCount bounds the work per SCAN round-trip so a large worker fleet
// does not block Redis in a single call.
const reaperScanCount = 100

// reaperInterval derives how often the reaper sweeps from the staleness
// threshold. It scans roughly twice per staleAfter window so a dead worker's
// jobs are recovered promptly, with a 1s floor to avoid a hot loop when
// staleAfter is tiny. Pure helper, unit-tested in queue_test.go.
func reaperInterval(staleAfter time.Duration) time.Duration {
	interval := staleAfter / 2
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}

// StartReaper runs the dead-worker reaper until ctx is cancelled.
//
// CONC-2 (at-least-once recovery): PopJobReliable leaves each in-flight job in
// its worker's processing list ("morf:processing:<id>") until the worker calls
// AckJob. If a worker dies mid-job it never Acks, so the job would sit in the
// processing list forever. The reaper periodically scans worker registrations
// ("morf:workers:*"); for any worker whose last_heartbeat is older than
// staleAfter it requeues every job in that worker's processing list back onto
// the main queue and deletes the dead registration.
//
// At-least-once semantics: a job may be executed more than once — e.g. a worker
// that finishes the work but dies before AckJob will have its job requeued and
// re-run by another worker. This is an accepted trade-off (no lost jobs at the
// cost of possible duplicates); job processing must therefore be idempotent.
//
// The sweep is bounded: SCAN is paginated (reaperScanCount per round) and each
// job is requeued via RequeueProcessing, which LREMs the job from the
// processing list before RPushing it, so a single occurrence cannot be
// double-requeued within a sweep. The reaper is expected to run as a single
// goroutine; running multiple concurrent reapers could re-deliver the same job
// twice, which is consistent with the at-least-once contract above.
func (q *JobQueue) StartReaper(ctx context.Context, staleAfter time.Duration) {
	interval := reaperInterval(staleAfter)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.WithFields(log.Fields{
		"stale_after": staleAfter.String(),
		"scan_every":  interval.String(),
	}).Info("Queue reaper started")

	for {
		select {
		case <-ctx.Done():
			log.Info("Queue reaper stopping")
			return
		case <-ticker.C:
			if err := q.reapOnce(staleAfter); err != nil {
				log.Warnf("reaper sweep failed: %v", err)
			}
		}
	}
}

// reapOnce performs a single bounded sweep over all registered workers.
func (q *JobQueue) reapOnce(staleAfter time.Duration) error {
	var cursor uint64
	for {
		keys, next, err := q.client.Scan(q.ctx, cursor, workerKeyPrefix+"*", reaperScanCount).Result()
		if err != nil {
			return err
		}
		for _, workerKey := range keys {
			q.reapWorker(workerKey, staleAfter)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return nil
}

// reapWorker requeues the in-flight jobs of a single worker if it is stale.
func (q *JobQueue) reapWorker(workerKey string, staleAfter time.Duration) {
	workerID := strings.TrimPrefix(workerKey, workerKeyPrefix)
	if workerID == workerKey || workerID == "" {
		return // not a worker registration key; skip defensively
	}

	hb, err := q.client.HGet(q.ctx, workerKey, "last_heartbeat").Result()
	if err != nil {
		// Missing heartbeat field or key vanished mid-scan: nothing to do.
		return
	}

	last, perr := time.Parse(time.RFC3339, hb)
	if perr != nil {
		log.Warnf("reaper: worker %s has unparseable heartbeat %q: %v", workerID, hb, perr)
		return
	}

	if time.Since(last) < staleAfter {
		return // worker is alive
	}

	pkey := processingKey(workerID)
	jobIDs, err := q.client.LRange(q.ctx, pkey, 0, -1).Result()
	if err != nil {
		log.Warnf("reaper: failed to read processing list %s: %v", pkey, err)
		return
	}

	for _, jobID := range jobIDs {
		if err := q.RequeueProcessing(workerID, jobID); err != nil {
			log.Warnf("reaper: failed to requeue job %s from dead worker %s: %v", jobID, workerID, err)
			continue
		}
		log.WithFields(log.Fields{
			"job_id":    jobID,
			"worker_id": workerID,
		}).Info("Reaper requeued job from dead worker")
	}

	// Clean up the dead worker registration so it is not scanned again.
	if err := q.client.Del(q.ctx, workerKey).Err(); err != nil {
		log.Warnf("reaper: failed to delete dead worker %s: %v", workerKey, err)
	}
}
