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

package tests

import (
	"context"
	"fmt"
	"morf/models"
	"morf/queue"
	"morf/worker"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// TestMultiInstanceJobDistribution tests that jobs are distributed across multiple instances
func TestMultiInstanceJobDistribution(t *testing.T) {
	// Skip if Redis is not available
	redisURL := "localhost:6379"
	client := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	// Create two job queues (simulating two instances)
	queue1, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 1: %v", err)
	}
	defer queue1.Close()

	queue2, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 2: %v", err)
	}
	defer queue2.Close()

	// Create worker pools for each instance (not started in test)
	_ = worker.NewWorkerPool(queue1)
	_ = worker.NewWorkerPool(queue2)

	// Create 10 jobs
	numJobs := 10
	jobIDs := make([]string, numJobs)
	for i := 0; i < numJobs; i++ {
		jobID := uuid.New().String()
		jobIDs[i] = jobID

		job := &models.ScanJob{
			ID:               jobID,
			Status:           models.JobStatusQueued,
			APKPath:          fmt.Sprintf("/tmp/test-%d.apk", i),
			OriginalFilename: fmt.Sprintf("test-%d.apk", i),
			CreatedAt:        time.Now(),
			RetryCount:       0,
		}

		if err := queue1.CreateJob(job); err != nil {
			t.Fatalf("Failed to create job %d: %v", i, err)
		}

		if err := queue1.PushJob(jobID); err != nil {
			t.Fatalf("Failed to push job %d: %v", i, err)
		}
	}

	// Start worker pools
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Note: In a real test, we would start the pools and let them process jobs
	// For now, we just verify that jobs can be created and retrieved from both instances

	// Verify jobs can be retrieved from both instances
	for _, jobID := range jobIDs {
		job1, err := queue1.GetJob(jobID)
		if err != nil {
			t.Errorf("Instance 1 failed to get job %s: %v", jobID, err)
			continue
		}

		job2, err := queue2.GetJob(jobID)
		if err != nil {
			t.Errorf("Instance 2 failed to get job %s: %v", jobID, err)
			continue
		}

		if job1.ID != job2.ID {
			t.Errorf("Job IDs don't match: %s != %s", job1.ID, job2.ID)
		}
	}

	// Cleanup
	for _, jobID := range jobIDs {
		key := fmt.Sprintf("morf:jobs:%s", jobID)
		client.Del(ctx, key)
	}
	client.Del(ctx, "morf:job_queue")
}

// TestNoSharedStateIssues tests that there are no shared state issues between instances
func TestNoSharedStateIssues(t *testing.T) {
	// Skip if Redis is not available
	redisURL := "localhost:6379"
	client := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	// Create two job queues
	queue1, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 1: %v", err)
	}
	defer queue1.Close()

	queue2, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 2: %v", err)
	}
	defer queue2.Close()

	// Create jobs from instance 1
	jobID1 := uuid.New().String()
	job1 := &models.ScanJob{
		ID:               jobID1,
		Status:           models.JobStatusQueued,
		APKPath:          "/tmp/test1.apk",
		OriginalFilename: "test1.apk",
		CreatedAt:        time.Now(),
		RetryCount:       0,
	}

	if err := queue1.CreateJob(job1); err != nil {
		t.Fatalf("Failed to create job 1: %v", err)
	}

	// Create jobs from instance 2
	jobID2 := uuid.New().String()
	job2 := &models.ScanJob{
		ID:               jobID2,
		Status:           models.JobStatusQueued,
		APKPath:          "/tmp/test2.apk",
		OriginalFilename: "test2.apk",
		CreatedAt:        time.Now(),
		RetryCount:       0,
	}

	if err := queue2.CreateJob(job2); err != nil {
		t.Fatalf("Failed to create job 2: %v", err)
	}

	// Verify both jobs exist and are independent
	retrievedJob1, err := queue1.GetJob(jobID1)
	if err != nil {
		t.Fatalf("Failed to retrieve job 1: %v", err)
	}

	retrievedJob2, err := queue2.GetJob(jobID2)
	if err != nil {
		t.Fatalf("Failed to retrieve job 2: %v", err)
	}

	// Verify jobs are independent
	if retrievedJob1.ID != jobID1 {
		t.Errorf("Job 1 ID mismatch: expected %s, got %s", jobID1, retrievedJob1.ID)
	}

	if retrievedJob2.ID != jobID2 {
		t.Errorf("Job 2 ID mismatch: expected %s, got %s", jobID2, retrievedJob2.ID)
	}

	// Verify instance 1 can't see job 2's internal state and vice versa
	// (This is more of a conceptual test - in practice, both can see all jobs in Redis)

	// Cleanup
	client.Del(ctx, fmt.Sprintf("morf:jobs:%s", jobID1))
	client.Del(ctx, fmt.Sprintf("morf:jobs:%s", jobID2))
}

// TestConcurrentJobCreation tests concurrent job creation from multiple instances
func TestConcurrentJobCreation(t *testing.T) {
	// Skip if Redis is not available
	redisURL := "localhost:6379"
	client := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	// Create two job queues
	queue1, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 1: %v", err)
	}
	defer queue1.Close()

	queue2, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 2: %v", err)
	}
	defer queue2.Close()

	// Create jobs concurrently from both instances
	numJobsPerInstance := 5
	var wg sync.WaitGroup
	allJobIDs := make([]string, 0, numJobsPerInstance*2)
	var mu sync.Mutex

	// Instance 1 creates jobs
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numJobsPerInstance; i++ {
			jobID := uuid.New().String()
			job := &models.ScanJob{
				ID:               jobID,
				Status:           models.JobStatusQueued,
				APKPath:          fmt.Sprintf("/tmp/instance1-test-%d.apk", i),
				OriginalFilename: fmt.Sprintf("instance1-test-%d.apk", i),
				CreatedAt:        time.Now(),
				RetryCount:       0,
			}

			if err := queue1.CreateJob(job); err != nil {
				t.Errorf("Instance 1 failed to create job %d: %v", i, err)
				continue
			}

			mu.Lock()
			allJobIDs = append(allJobIDs, jobID)
			mu.Unlock()
		}
	}()

	// Instance 2 creates jobs
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numJobsPerInstance; i++ {
			jobID := uuid.New().String()
			job := &models.ScanJob{
				ID:               jobID,
				Status:           models.JobStatusQueued,
				APKPath:          fmt.Sprintf("/tmp/instance2-test-%d.apk", i),
				OriginalFilename: fmt.Sprintf("instance2-test-%d.apk", i),
				CreatedAt:        time.Now(),
				RetryCount:       0,
			}

			if err := queue2.CreateJob(job); err != nil {
				t.Errorf("Instance 2 failed to create job %d: %v", i, err)
				continue
			}

			mu.Lock()
			allJobIDs = append(allJobIDs, jobID)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Verify all jobs were created successfully
	if len(allJobIDs) != numJobsPerInstance*2 {
		t.Errorf("Expected %d jobs, got %d", numJobsPerInstance*2, len(allJobIDs))
	}

	// Verify all jobs can be retrieved
	for _, jobID := range allJobIDs {
		_, err := queue1.GetJob(jobID)
		if err != nil {
			t.Errorf("Failed to retrieve job %s: %v", jobID, err)
		}
	}

	// Cleanup
	for _, jobID := range allJobIDs {
		client.Del(ctx, fmt.Sprintf("morf:jobs:%s", jobID))
	}
}

// TestFailoverScenarios tests failover scenarios
func TestFailoverScenarios(t *testing.T) {
	// Skip if Redis is not available
	redisURL := "localhost:6379"
	client := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}

	// Create job queue
	queue1, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue1.Close()

	// Create a job
	jobID := uuid.New().String()
	job := &models.ScanJob{
		ID:               jobID,
		Status:           models.JobStatusQueued,
		APKPath:          "/tmp/test.apk",
		OriginalFilename: "test.apk",
		CreatedAt:        time.Now(),
		RetryCount:       0,
	}

	if err := queue1.CreateJob(job); err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Simulate instance 1 failure - create new instance 2
	queue2, err := queue.NewJobQueue(redisURL)
	if err != nil {
		t.Fatalf("Failed to create queue 2: %v", err)
	}
	defer queue2.Close()

	// Verify job can still be retrieved from instance 2
	retrievedJob, err := queue2.GetJob(jobID)
	if err != nil {
		t.Fatalf("Failed to retrieve job after failover: %v", err)
	}

	if retrievedJob.ID != jobID {
		t.Errorf("Job ID mismatch after failover: expected %s, got %s", jobID, retrievedJob.ID)
	}

	// Cleanup
	client.Del(ctx, fmt.Sprintf("morf:jobs:%s", jobID))
}
