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
	"encoding/json"
	"fmt"
	"morf/models"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	// Cache key prefixes
	metadataCachePrefix    = "morf:metadata:"
	packageDataCachePrefix = "morf:package_data:"

	// Pattern-version counter; bumping it invalidates the entire metadata cache
	// in O(1) without a Redis SCAN. Old keys age out by TTL.
	patternVersionKey = "morf:pattern_version"

	// Cache TTL
	metadataCacheTTL = 7 * 24 * time.Hour // 7 days

	// cacheInvalidateChannel is the Redis pub/sub channel used to broadcast
	// invalidation events to all pods. Receiving pods update their local
	// patternVersion or delete the specific key so stale in-process state
	// is flushed without waiting for a TTL expiry.
	cacheInvalidateChannel = "morf:cache:invalidate"

	// invalidateAllSentinel is the message payload that means "invalidate
	// all metadata cache entries" (as opposed to a specific apkHash).
	invalidateAllSentinel = "*"
)

// patternVersion is a process-local cache of the pattern-version counter.
// We refresh it from Redis on misses so cache reads after an invalidation
// pick up the new version without scanning. Atomic for concurrent access.
var patternVersion atomic.Int64

func loadPatternVersion(ctx context.Context) int64 {
	client := getRedisClient()
	if client == nil {
		return 0
	}
	v, err := client.Get(ctx, patternVersionKey).Int64()
	if err == redis.Nil {
		return 0
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Failed to load pattern version")
		return patternVersion.Load()
	}
	patternVersion.Store(v)
	return v
}

func metadataKey(apkHash string) string {
	v := patternVersion.Load()
	return fmt.Sprintf("%sv%d:%s", metadataCachePrefix, v, apkHash)
}

func packageDataKey(apkHash string) string {
	// package data is independent of patterns, so no version is included.
	return packageDataCachePrefix + apkHash
}

// redisClient is guarded by redisMu. It is read by the invalidation subscriber
// goroutine while InitCache/InitCacheFromClient may overwrite it, so all
// access MUST go through getRedisClient/setRedisClient to stay race-free
// (-race / go vet clean). cacheEnabled is updated only during init under the
// same write lock to keep it consistent with the client swap.
var (
	redisMu      sync.RWMutex
	redisClient  *redis.Client
	cacheEnabled = false
)

// getRedisClient returns the current Redis client under a read lock. It may be
// nil if the cache has not been initialized.
func getRedisClient() *redis.Client {
	redisMu.RLock()
	defer redisMu.RUnlock()
	return redisClient
}

// setRedisClient swaps the Redis client (and the enabled flag) under a write
// lock and returns the previous client (possibly nil) so the caller can
// Close() it to avoid leaking its connection pool.
func setRedisClient(client *redis.Client, enabled bool) *redis.Client {
	redisMu.Lock()
	defer redisMu.Unlock()
	prev := redisClient
	redisClient = client
	cacheEnabled = enabled
	return prev
}

// InitCache initializes the Redis cache client
func InitCache(redisURL string) error {
	if redisURL == "" {
		log.Warn("Redis URL not provided, caching disabled")
		setRedisClient(nil, false)
		return nil
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to parse Redis URL, caching disabled")
		setRedisClient(nil, false)
		return err
	}

	newClient := redis.NewClient(opt)

	// Test connection before swapping it in.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := newClient.Ping(ctx).Err(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to connect to Redis, caching disabled")
		// Close the just-created client so its pool does not leak.
		_ = newClient.Close()
		setRedisClient(nil, false)
		return err
	}

	// Swap in the new client and close the previous one (if any).
	if prev := setRedisClient(newClient, true); prev != nil {
		_ = prev.Close()
	}
	loadPatternVersion(ctx)
	log.Info("Redis cache initialized successfully")
	return nil
}

// InitCacheFromClient initializes the cache using an existing Redis client
func InitCacheFromClient(client *redis.Client) {
	if client == nil {
		log.Warn("Redis client is nil, caching disabled")
		setRedisClient(nil, false)
		return
	}

	// Test connection before swapping it in.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to ping Redis client, caching disabled")
		setRedisClient(nil, false)
		return
	}

	// Swap in the provided client and close the previous one (if any). The
	// caller owns `client`, so we only close the client we are replacing.
	if prev := setRedisClient(client, true); prev != nil {
		_ = prev.Close()
	}
	loadPatternVersion(ctx)
	log.Info("Redis cache initialized from existing client successfully")
}

// IsCacheEnabled returns whether caching is enabled
func IsCacheEnabled() bool {
	redisMu.RLock()
	defer redisMu.RUnlock()
	return cacheEnabled && redisClient != nil
}

// GetMetadataFromCache retrieves metadata from cache by APK hash
func GetMetadataFromCache(apkHash string) (models.MetaDataModel, bool) {
	client := getRedisClient()
	if client == nil {
		return models.MetaDataModel{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := metadataKey(apkHash)
	data, err := client.Get(ctx, key).Result()
	if err == redis.Nil {
		// On a miss, refresh the local patternVersion from Redis before
		// reporting a miss. A pod that dropped a pub/sub invalidation may be
		// reading from a stale (lower) version prefix; re-syncing here makes
		// subsequent reads use the current key prefix without a SCAN.
		loadPatternVersion(ctx)
		return models.MetaDataModel{}, false
	}
	if err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to get metadata from cache")
		return models.MetaDataModel{}, false
	}

	var metadata models.MetaDataModel
	if err := json.Unmarshal([]byte(data), &metadata); err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to unmarshal cached metadata")
		return models.MetaDataModel{}, false
	}

	log.WithFields(log.Fields{
		"apk_hash": apkHash,
	}).Debug("Metadata retrieved from cache")
	return metadata, true
}

// SetMetadataInCache stores metadata in cache
func SetMetadataInCache(apkHash string, metadata models.MetaDataModel) error {
	client := getRedisClient()
	if client == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	key := metadataKey(apkHash)
	if err := client.Set(ctx, key, data, metadataCacheTTL).Err(); err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to set metadata in cache")
		return err
	}

	log.WithFields(log.Fields{
		"apk_hash": apkHash,
		"ttl":      metadataCacheTTL,
	}).Debug("Metadata cached successfully")
	return nil
}

// GetPackageDataFromCache retrieves package data from cache by APK hash
func GetPackageDataFromCache(apkHash string) (models.PackageDataModel, bool) {
	client := getRedisClient()
	if client == nil {
		return models.PackageDataModel{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := packageDataKey(apkHash)
	data, err := client.Get(ctx, key).Result()
	if err == redis.Nil {
		return models.PackageDataModel{}, false
	}
	if err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to get package data from cache")
		return models.PackageDataModel{}, false
	}

	var packageData models.PackageDataModel
	if err := json.Unmarshal([]byte(data), &packageData); err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to unmarshal cached package data")
		return models.PackageDataModel{}, false
	}

	log.WithFields(log.Fields{
		"apk_hash": apkHash,
	}).Debug("Package data retrieved from cache")
	return packageData, true
}

// SetPackageDataInCache stores package data in cache
func SetPackageDataInCache(apkHash string, packageData models.PackageDataModel) error {
	client := getRedisClient()
	if client == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(packageData)
	if err != nil {
		return fmt.Errorf("failed to marshal package data: %v", err)
	}

	key := packageDataKey(apkHash)
	if err := client.Set(ctx, key, data, metadataCacheTTL).Err(); err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to set package data in cache")
		return err
	}

	log.WithFields(log.Fields{
		"apk_hash": apkHash,
		"ttl":      metadataCacheTTL,
	}).Debug("Package data cached successfully")
	return nil
}

// InvalidateAllMetadataCache logically invalidates all metadata cache by
// bumping the pattern-version counter. New reads use a different key prefix,
// so old entries are no longer visible and age out via TTL. This replaces a
// previous Redis SCAN+DEL that blocked under load.
func InvalidateAllMetadataCache() error {
	client := getRedisClient()
	if client == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	v, err := client.Incr(ctx, patternVersionKey).Result()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Warn("Failed to bump pattern version")
		return err
	}
	patternVersion.Store(v)

	log.WithFields(log.Fields{
		"pattern_version": v,
	}).Info("Bumped pattern version; metadata cache logically invalidated")

	// Notify other pods so they refresh their local patternVersion and stop
	// serving stale keys from the previous version.
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pubCancel()
	publishInvalidation(pubCtx, invalidateAllSentinel)

	return nil
}

// publishInvalidation publishes key (or invalidateAllSentinel) to the shared
// invalidation channel so other pods can bust their local state.
// Redis failures are logged at warn and never panic.
func publishInvalidation(ctx context.Context, key string) {
	client := getRedisClient()
	if client == nil {
		return
	}
	if err := client.Publish(ctx, cacheInvalidateChannel, key).Err(); err != nil {
		log.WithFields(log.Fields{
			"channel": cacheInvalidateChannel,
			"key":     key,
			"error":   err.Error(),
		}).Warn("Failed to publish cache invalidation event")
	}
}

// handleInvalidationMessage is called by the subscriber goroutine for each
// inbound message. Only the "invalidate all" sentinel is published (see
// InvalidateAllMetadataCache), which refreshes patternVersion from Redis so
// this pod starts using the new key prefix on the next read.
//   - payload == invalidateAllSentinel → refresh patternVersion from Redis.
//
// Any other payload is ignored. There is no single-key invalidation path:
// deleting metadataKey(payload) here would use the RECEIVING pod's local
// patternVersion, which can differ from the publisher's, and could delete the
// wrong versioned key.
func handleInvalidationMessage(ctx context.Context, payload string) {
	if payload == invalidateAllSentinel {
		loadPatternVersion(ctx)
		log.Debug("Cache invalidation: all metadata (local version refreshed from Redis)")
		return
	}
	log.WithFields(log.Fields{"payload": payload}).
		Debug("Ignoring unrecognized cache invalidation payload")
}

// StartCacheInvalidationSubscriber subscribes to cacheInvalidateChannel using
// the cache's Redis client and, on each message, busts the corresponding
// local in-process state. Runs until ctx is done; the subscription is cleanly
// closed on exit. Safe to call when the cache is not initialized (no-op).
func StartCacheInvalidationSubscriber(ctx context.Context) {
	client := getRedisClient()
	if client == nil {
		log.Debug("Cache not enabled; invalidation subscriber not started")
		return
	}

	// Subscribe with a background context so the channel itself is not
	// scoped to the caller's deadline; we manage lifecycle via ctx.Done().
	sub := client.Subscribe(context.Background(), cacheInvalidateChannel)
	ch := sub.Channel()

	go func() {
		defer func() {
			if err := sub.Close(); err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).
					Debug("Failed to close cache invalidation subscriber")
			}
		}()

		log.WithFields(log.Fields{"channel": cacheInvalidateChannel}).
			Info("Cache invalidation subscriber running")

		for {
			select {
			case <-ctx.Done():
				log.Debug("Cache invalidation subscriber stopping (context cancelled)")
				return
			case msg, ok := <-ch:
				if !ok {
					log.Debug("Cache invalidation subscriber channel closed")
					return
				}
				handleInvalidationMessage(ctx, msg.Payload)
			}
		}
	}()

	log.WithFields(log.Fields{"channel": cacheInvalidateChannel}).
		Info("Cache invalidation subscriber started")
}

// RefreshPatternVersion forces a one-shot reload of the local pattern-version
// counter from Redis and returns the resulting version. Safe to call when the
// cache is disabled (no-op returning 0).
func RefreshPatternVersion(ctx context.Context) int64 {
	return loadPatternVersion(ctx)
}

// StartPatternVersionRefresher launches a background goroutine that periodically
// reloads the local pattern-version counter from Redis. This is a
// belt-and-suspenders guard against dropped pub/sub invalidation messages: even
// if a pod misses an invalidation event, it re-syncs within `interval`. Runs
// until ctx is done. A non-positive interval defaults to one minute. Safe to
// call when the cache is disabled (the periodic reload is a no-op).
//
// NOTE: the orchestrator's main.go must call this (e.g.
// utils.StartPatternVersionRefresher(ctx, time.Minute)) to actually start it.
func StartPatternVersionRefresher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debug("Pattern-version refresher stopping (context cancelled)")
				return
			case <-ticker.C:
				if getRedisClient() == nil {
					continue
				}
				loadPatternVersion(ctx)
			}
		}
	}()

	log.WithFields(log.Fields{"interval": interval.String()}).
		Info("Pattern-version refresher started")
}
