/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package queue

import (
	"context"
	"morf/models"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newMiniQueue spins an in-memory Redis (miniredis) backed JobQueue for E2E-ish
// behavior tests that need real Redis semantics (Lua EVAL, lists, sets) without
// a live server.
func newMiniQueue(t *testing.T) (*JobQueue, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &JobQueue{client: client, ctx: context.Background()}, mr
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestEnqueueJobAtomic verifies R-3: the job hash, the status:queued membership,
// the TTL, and the FIFO queue entry are ALL written by EnqueueJobAtomic — the
// atomicity that prevents a job being registered-but-unqueued.
func TestEnqueueJobAtomic(t *testing.T) {
	q, mr := newMiniQueue(t)
	job := &models.ScanJob{ID: "job-1", Status: models.JobStatusQueued}

	if err := q.EnqueueJobAtomic(job); err != nil {
		t.Fatalf("EnqueueJobAtomic: %v", err)
	}

	if !mr.Exists("morf:jobs:job-1") {
		t.Error("job hash was not written")
	}
	members, _ := mr.SMembers("morf:jobs:status:queued")
	if !contains(members, "job-1") {
		t.Errorf("job-1 not in status:queued set: %v", members)
	}
	list, _ := mr.List("morf:job_queue")
	if len(list) != 1 || list[0] != "job-1" {
		t.Errorf("job_queue = %v, want [job-1]", list)
	}
	if ttl := mr.TTL("morf:jobs:job-1"); ttl <= 0 {
		t.Errorf("job hash TTL = %v, want > 0 (7d)", ttl)
	}
}

// TestWebhookDLQ verifies MED-webhook-dlq: failed deliveries are durably
// recorded, counted, and paginated.
func TestWebhookDLQ(t *testing.T) {
	q, _ := newMiniQueue(t)

	if d, err := q.GetWebhookDLQDepth(); err != nil || d != 0 {
		t.Fatalf("initial depth = %d (err %v), want 0", d, err)
	}
	for i := 0; i < 3; i++ {
		if err := q.RecordFailedWebhook(FailedWebhook{
			JobID:      "j",
			WebhookURL: "https://example.test/hook",
			JobStatus:  "completed",
			Error:      "boom",
			RecordedAt: int64(i),
		}); err != nil {
			t.Fatalf("RecordFailedWebhook[%d]: %v", i, err)
		}
	}

	d, err := q.GetWebhookDLQDepth()
	if err != nil || d != 3 {
		t.Fatalf("depth = %d (err %v), want 3", d, err)
	}
	page, err := q.GetWebhookDLQPage(0, 10)
	if err != nil {
		t.Fatalf("GetWebhookDLQPage: %v", err)
	}
	if len(page) != 3 {
		t.Errorf("page length = %d, want 3", len(page))
	}
}

// TestTrimTerminalStatusSets verifies MED-statusset-leak: members of a terminal
// status set whose job hash has TTL-expired are reclaimed, while live members
// (hash still present) are retained.
func TestTrimTerminalStatusSets(t *testing.T) {
	q, mr := newMiniQueue(t)

	// Live member: its job hash still exists.
	mr.HSet("morf:jobs:live", "status", "completed")
	if _, err := mr.SetAdd("morf:jobs:status:completed", "live"); err != nil {
		t.Fatalf("seed live: %v", err)
	}
	// Dangling member: in the set but its hash has expired.
	if _, err := mr.SetAdd("morf:jobs:status:completed", "dangling"); err != nil {
		t.Fatalf("seed dangling: %v", err)
	}

	if err := q.TrimTerminalStatusSets(); err != nil {
		t.Fatalf("TrimTerminalStatusSets: %v", err)
	}

	members, _ := mr.SMembers("morf:jobs:status:completed")
	if contains(members, "dangling") {
		t.Errorf("dangling member (no hash) should have been trimmed: %v", members)
	}
	if !contains(members, "live") {
		t.Errorf("live member (hash exists) must be retained: %v", members)
	}
}

// TestLeaseFencing verifies MED-reaper-fp: a worker that still holds the lease
// passes the ownership check, but once the lease is taken over (a reaped job
// re-leased by another worker) the original worker's check fails, so its stale
// terminal write is fenced off.
func TestLeaseFencing(t *testing.T) {
	q, _ := newMiniQueue(t)

	if err := q.SetJobLease("job-9", "worker-A"); err != nil {
		t.Fatalf("SetJobLease(A): %v", err)
	}
	if ok, err := q.CheckJobLease("job-9", "worker-A"); err != nil || !ok {
		t.Errorf("CheckJobLease(A) = %v (err %v), want true", ok, err)
	}
	// Another worker takes the lease (job was reaped and re-delivered).
	if err := q.SetJobLease("job-9", "worker-B"); err != nil {
		t.Fatalf("SetJobLease(B): %v", err)
	}
	if ok, _ := q.CheckJobLease("job-9", "worker-A"); ok {
		t.Error("CheckJobLease(A) = true after takeover, want false (fenced)")
	}
	if ok, _ := q.CheckJobLease("job-9", "worker-B"); !ok {
		t.Error("CheckJobLease(B) = false, want true (current owner)")
	}
}
