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
	"testing"
	"time"
)

// These are pure unit tests for the non-Redis logic. They deliberately avoid a
// Redis/miniredis harness so no new dependency is introduced (see go.mod).

func TestProcessingKey(t *testing.T) {
	cases := []struct {
		workerID string
		want     string
	}{
		{"worker-1", "morf:processing:worker-1"},
		{"abc123", "morf:processing:abc123"},
		{"", "morf:processing:"},
	}
	for _, c := range cases {
		if got := processingKey(c.workerID); got != c.want {
			t.Errorf("processingKey(%q) = %q, want %q", c.workerID, got, c.want)
		}
	}
}

// processingKey must never collide with the main queue key, otherwise a pop
// would move a job onto the queue it was just taken from.
func TestProcessingKeyDistinctFromMainQueue(t *testing.T) {
	if processingKey("anything") == jobQueueKey {
		t.Fatalf("processingKey collides with jobQueueKey %q", jobQueueKey)
	}
}

func TestReaperInterval(t *testing.T) {
	cases := []struct {
		staleAfter time.Duration
		want       time.Duration
	}{
		{60 * time.Second, 30 * time.Second}, // half of stale window
		{10 * time.Second, 5 * time.Second},
		{2 * time.Second, time.Second},       // half is 1s -> floor
		{500 * time.Millisecond, time.Second}, // below floor -> clamp to 1s
		{0, time.Second},                      // degenerate -> floor
	}
	for _, c := range cases {
		if got := reaperInterval(c.staleAfter); got != c.want {
			t.Errorf("reaperInterval(%v) = %v, want %v", c.staleAfter, got, c.want)
		}
	}
}

// reaperInterval must always be at least the 1s floor so the sweep never
// degenerates into a hot loop.
func TestReaperIntervalFloor(t *testing.T) {
	for _, d := range []time.Duration{0, time.Nanosecond, 100 * time.Millisecond, time.Second} {
		if got := reaperInterval(d); got < time.Second {
			t.Errorf("reaperInterval(%v) = %v, below 1s floor", d, got)
		}
	}
}
