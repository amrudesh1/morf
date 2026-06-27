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

package utils

import (
	"context"
	"testing"
)

// TestCacheInvalidateChannelName verifies the pub/sub channel name is stable.
func TestCacheInvalidateChannelName(t *testing.T) {
	const want = "morf:cache:invalidate"
	if cacheInvalidateChannel != want {
		t.Errorf("cacheInvalidateChannel = %q; want %q", cacheInvalidateChannel, want)
	}
}

// TestInvalidateAllSentinel verifies the wildcard sentinel is stable.
func TestInvalidateAllSentinel(t *testing.T) {
	const want = "*"
	if invalidateAllSentinel != want {
		t.Errorf("invalidateAllSentinel = %q; want %q", invalidateAllSentinel, want)
	}
}

// TestStartCacheInvalidationSubscriber_NilSafe verifies that calling
// StartCacheInvalidationSubscriber with no Redis client does not panic.
func TestStartCacheInvalidationSubscriber_NilSafe(t *testing.T) {
	orig := cacheEnabled
	origClient := redisClient
	defer func() {
		cacheEnabled = orig
		redisClient = origClient
	}()

	cacheEnabled = false
	redisClient = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Must return immediately without panic.
	StartCacheInvalidationSubscriber(ctx)
}

// TestPublishInvalidation_NilSafe verifies that publishInvalidation is a no-op
// (and does not panic) when the cache is disabled.
func TestPublishInvalidation_NilSafe(t *testing.T) {
	orig := cacheEnabled
	origClient := redisClient
	defer func() {
		cacheEnabled = orig
		redisClient = origClient
	}()

	cacheEnabled = false
	redisClient = nil

	publishInvalidation(context.Background(), invalidateAllSentinel)
	publishInvalidation(context.Background(), "someApkHash")
}

// TestLoadPatternVersion_CacheDisabled verifies that loadPatternVersion does not
// panic (i.e. does not touch the nil Redis client) when the cache is disabled.
// The implementation short-circuits with return 0 in that case.
func TestLoadPatternVersion_CacheDisabled(t *testing.T) {
	orig := cacheEnabled
	origClient := redisClient
	origVersion := patternVersion.Load()
	defer func() {
		cacheEnabled = orig
		redisClient = origClient
		patternVersion.Store(origVersion)
	}()

	cacheEnabled = false
	redisClient = nil
	patternVersion.Store(99)

	got := loadPatternVersion(context.Background())
	// Short-circuits to 0 when cache is disabled — must not touch Redis (nil).
	if got != 0 {
		t.Errorf("loadPatternVersion (cache disabled) = %d; want 0 (short-circuit)", got)
	}
	// The local atomic must be unmodified since we never reached the Store call.
	if patternVersion.Load() != 99 {
		t.Errorf("patternVersion mutated unexpectedly; got %d, want 99", patternVersion.Load())
	}
}

// TestHandleInvalidationMessage_AllSentinel_CacheDisabled verifies that
// handleInvalidationMessage with the wildcard sentinel does not panic when the
// cache is disabled (loadPatternVersion short-circuits before touching Redis).
func TestHandleInvalidationMessage_AllSentinel_CacheDisabled(t *testing.T) {
	orig := cacheEnabled
	origClient := redisClient
	origVersion := patternVersion.Load()
	defer func() {
		cacheEnabled = orig
		redisClient = origClient
		patternVersion.Store(origVersion)
	}()

	cacheEnabled = false
	redisClient = nil
	patternVersion.Store(7)

	// Must not panic.
	handleInvalidationMessage(context.Background(), invalidateAllSentinel)

	// Local version must be unchanged because loadPatternVersion is a no-op
	// when cache is disabled.
	if patternVersion.Load() != 7 {
		t.Errorf("patternVersion changed unexpectedly; got %d, want 7", patternVersion.Load())
	}
}

// TestMetadataKeyIncludesVersion verifies that metadataKey embeds the current
// patternVersion so that a version bump produces a different key.
func TestMetadataKeyIncludesVersion(t *testing.T) {
	origVersion := patternVersion.Load()
	defer patternVersion.Store(origVersion)

	patternVersion.Store(1)
	k1 := metadataKey("abc")

	patternVersion.Store(2)
	k2 := metadataKey("abc")

	if k1 == k2 {
		t.Errorf("metadataKey should differ across versions; both = %q", k1)
	}
}
