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
	"math"
	"morf/queue"
	"morf/utils"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// envInt reads an int from env, falling back to def when unset/invalid.
func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// envDuration reads a time.Duration from env (e.g. "5m", "30s"), falling back
// to def when the variable is unset or cannot be parsed.
func envDuration(name string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(name); ok {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// WorkerPool manages a pool of workers that process jobs from Redis queue
type WorkerPool struct {
	workerCount int
	workers     []*Worker
	queue       *queue.JobQueue
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	started     bool
}

// NewWorkerPool creates a new worker pool.
//
// Worker count is derived from the cgroup-aware effective CPU count
// (utils.EffectiveCPUs) rather than the raw node CPU count. The scan pipeline
// is I/O-bound (apktool, ripgrep, DB writes spend most time in syscalls), so
// the default multiplier is 2x: default = max(2, round(EffectiveCPUs * 2)).
//
// Env overrides (all optional):
//
//	MORF_WORKER_COUNT      — direct override; skips the formula
//	MORF_WORKER_MAX        — upper bound (default: round(EffectiveCPUs)*4)
//	MORF_WORKER_MEM_BUDGET_MB — total memory budget for all in-flight scans
//	MORF_SCAN_MEM_MB       — per-scan memory estimate (used with budget above)
func NewWorkerPool(q *queue.JobQueue) *WorkerPool {
	effectiveCPUs := utils.EffectiveCPUs()

	const ioFactor = 2.0
	defaultWorkers := int(math.Round(effectiveCPUs * ioFactor))
	if defaultWorkers < 2 {
		defaultWorkers = 2
	}

	workerCount := envInt("MORF_WORKER_COUNT", defaultWorkers)
	if workerCount < 2 {
		workerCount = 2
	}

	maxWorkers := envInt("MORF_WORKER_MAX", int(math.Round(effectiveCPUs))*4)
	if maxWorkers < 2 {
		maxWorkers = 2
	}
	if workerCount > maxWorkers {
		workerCount = maxWorkers
	}

	// Optional memory-budget cap: cap = floor(budget / per_scan), min 2.
	if memBudget := envInt("MORF_WORKER_MEM_BUDGET_MB", 0); memBudget > 0 {
		if perScan := envInt("MORF_SCAN_MEM_MB", 0); perScan > 0 {
			maxByMem := memBudget / perScan
			if maxByMem < 2 {
				maxByMem = 2
			}
			if workerCount > maxByMem {
				workerCount = maxByMem
			}
		}
	}

	log.WithFields(log.Fields{
		"effective_cpus": effectiveCPUs,
		"io_factor":      ioFactor,
		"worker_count":   workerCount,
		"max_workers":    maxWorkers,
	}).Info("Worker pool sizing")

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workerCount: workerCount,
		queue:       q,
		ctx:         ctx,
		cancel:      cancel,
		workers:     make([]*Worker, 0, workerCount),
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.started {
		return nil
	}

	log.WithFields(log.Fields{
		"worker_count": wp.workerCount,
	}).Info("Starting worker pool")

	for i := 0; i < wp.workerCount; i++ {
		worker := NewWorker(wp.queue, i+1)
		wp.workers = append(wp.workers, worker)
		wp.wg.Add(1)
		go func(w *Worker) {
			defer wp.wg.Done()
			w.Start(wp.ctx)
		}(worker)
	}

	wp.started = true
	log.WithFields(log.Fields{
		"worker_count": wp.workerCount,
	}).Info("Worker pool started")

	return nil
}

// Stop stops the worker pool gracefully.
//
// Drain timeout is configurable via MORF_DRAIN_TIMEOUT (default 5m); a longer
// default than the previous 30 s allows in-flight scans (which may run up to
// 30 min each) to finish naturally before the process exits.
//
// After workers drain, pending webhook deliveries are flushed via
// WaitWebhooks (worker track) with the remaining drain budget.
func (wp *WorkerPool) Stop() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.started {
		return nil
	}

	log.Info("Stopping worker pool")

	// Cancel context to signal workers to stop accepting new jobs.
	wp.cancel()

	// Wait for in-flight workers to drain, with a configurable timeout so long
	// scans can complete before the process exits.
	drainTimeout := envDuration("MORF_DRAIN_TIMEOUT", 5*time.Minute)
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	drainStart := time.Now()
	select {
	case <-done:
		log.WithFields(log.Fields{
			"drain_timeout": drainTimeout.String(),
		}).Info("All workers drained gracefully")
	case <-time.After(drainTimeout):
		log.WithFields(log.Fields{
			"drain_timeout": drainTimeout.String(),
		}).Warn("Drain timeout elapsed; some workers may still be running")
	}

	// Flush any in-flight webhook deliveries (bounded, tracked by the worker
	// track) with whatever remains of the drain budget, so subscribers aren't
	// dropped on shutdown (CONC-6 / WEBHOOK-1).
	if remaining := drainTimeout - time.Since(drainStart); remaining > 0 {
		if WaitWebhooks(remaining) {
			log.Info("Pending webhook deliveries flushed")
		} else {
			log.Warn("Webhook flush timed out; some deliveries may be incomplete")
		}
	}

	wp.started = false
	return nil
}

// GetWorkerCount returns the number of workers
func (wp *WorkerPool) GetWorkerCount() int {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return wp.workerCount
}

// SetWorkerCount sets the worker count (must be called before Start())
func (wp *WorkerPool) SetWorkerCount(count int) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if !wp.started && count > 0 {
		wp.workerCount = count
		log.WithFields(log.Fields{
			"worker_count": wp.workerCount,
		}).Info("Worker count set")
	}
}

// IsStarted returns whether the pool is started
func (wp *WorkerPool) IsStarted() bool {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return wp.started
}
