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
	if !IsCacheEnabled() {
		return 0
	}
	v, err := redisClient.Get(ctx, patternVersionKey).Int64()
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

var (
	redisClient  *redis.Client
	cacheEnabled = false
)

// InitCache initializes the Redis cache client
func InitCache(redisURL string) error {
	if redisURL == "" {
		log.Warn("Redis URL not provided, caching disabled")
		cacheEnabled = false
		return nil
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to parse Redis URL, caching disabled")
		cacheEnabled = false
		return err
	}

	redisClient = redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to connect to Redis, caching disabled")
		cacheEnabled = false
		return err
	}

	cacheEnabled = true
	loadPatternVersion(ctx)
	log.Info("Redis cache initialized successfully")
	return nil
}

// InitCacheFromClient initializes the cache using an existing Redis client
func InitCacheFromClient(client *redis.Client) {
	if client == nil {
		log.Warn("Redis client is nil, caching disabled")
		cacheEnabled = false
		return
	}

	redisClient = client

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Warn("Failed to ping Redis client, caching disabled")
		cacheEnabled = false
		return
	}

	cacheEnabled = true
	loadPatternVersion(ctx)
	log.Info("Redis cache initialized from existing client successfully")
}

// GetCacheClient returns the Redis client (for use by queue package)
func GetCacheClient() *redis.Client {
	return redisClient
}

// IsCacheEnabled returns whether caching is enabled
func IsCacheEnabled() bool {
	return cacheEnabled && redisClient != nil
}

// GetMetadataFromCache retrieves metadata from cache by APK hash
func GetMetadataFromCache(apkHash string) (models.MetaDataModel, bool) {
	if !IsCacheEnabled() {
		return models.MetaDataModel{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := metadataKey(apkHash)
	data, err := redisClient.Get(ctx, key).Result()
	if err == redis.Nil {
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
	if !IsCacheEnabled() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	key := metadataKey(apkHash)
	if err := redisClient.Set(ctx, key, data, metadataCacheTTL).Err(); err != nil {
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
	if !IsCacheEnabled() {
		return models.PackageDataModel{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := packageDataKey(apkHash)
	data, err := redisClient.Get(ctx, key).Result()
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
	if !IsCacheEnabled() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, err := json.Marshal(packageData)
	if err != nil {
		return fmt.Errorf("failed to marshal package data: %v", err)
	}

	key := packageDataKey(apkHash)
	if err := redisClient.Set(ctx, key, data, metadataCacheTTL).Err(); err != nil {
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

// InvalidateMetadataCache invalidates metadata cache for a specific APK hash
// (single-key delete; cheap regardless of overall cache size).
func InvalidateMetadataCache(apkHash string) error {
	if !IsCacheEnabled() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := metadataKey(apkHash)
	if err := redisClient.Del(ctx, key).Err(); err != nil {
		log.WithFields(log.Fields{
			"apk_hash": apkHash,
			"error":    err.Error(),
		}).Warn("Failed to invalidate metadata cache")
		return err
	}

	log.WithFields(log.Fields{
		"apk_hash": apkHash,
	}).Debug("Metadata cache invalidated")

	// Notify other pods so they also bust their local copy of this key.
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pubCancel()
	publishInvalidation(pubCtx, apkHash)

	return nil
}

// InvalidateAllMetadataCache logically invalidates all metadata cache by
// bumping the pattern-version counter. New reads use a different key prefix,
// so old entries are no longer visible and age out via TTL. This replaces a
// previous Redis SCAN+DEL that blocked under load.
func InvalidateAllMetadataCache() error {
	if !IsCacheEnabled() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	v, err := redisClient.Incr(ctx, patternVersionKey).Result()
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
	if !IsCacheEnabled() {
		return
	}
	if err := redisClient.Publish(ctx, cacheInvalidateChannel, key).Err(); err != nil {
		log.WithFields(log.Fields{
			"channel": cacheInvalidateChannel,
			"key":     key,
			"error":   err.Error(),
		}).Warn("Failed to publish cache invalidation event")
	}
}

// handleInvalidationMessage is called by the subscriber goroutine for each
// inbound message. It busts the corresponding local state:
//   - payload == invalidateAllSentinel → refresh patternVersion from Redis so
//     this pod starts using the new key prefix on the next read.
//   - payload == apkHash              → delete the key under the current local
//     version so the next read is a cache miss and forces a fresh load.
func handleInvalidationMessage(ctx context.Context, payload string) {
	if payload == invalidateAllSentinel {
		loadPatternVersion(ctx)
		log.Debug("Cache invalidation: all metadata (local version refreshed from Redis)")
		return
	}
	// Single-key invalidation: remove from Redis under our current version.
	key := metadataKey(payload)
	delCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := redisClient.Del(delCtx, key).Err(); err != nil {
		log.WithFields(log.Fields{
			"apk_hash": payload,
			"error":    err.Error(),
		}).Debug("Failed to delete key on cross-pod invalidation message")
	} else {
		log.WithFields(log.Fields{"apk_hash": payload}).Debug("Cache invalidation: single key busted via pub/sub")
	}
	cancel()
}

// StartCacheInvalidationSubscriber subscribes to cacheInvalidateChannel using
// the cache's Redis client and, on each message, busts the corresponding
// local in-process state. Runs until ctx is done; the subscription is cleanly
// closed on exit. Safe to call when the cache is not initialized (no-op).
func StartCacheInvalidationSubscriber(ctx context.Context) {
	if !IsCacheEnabled() {
		log.Debug("Cache not enabled; invalidation subscriber not started")
		return
	}

	// Subscribe with a background context so the channel itself is not
	// scoped to the caller's deadline; we manage lifecycle via ctx.Done().
	sub := redisClient.Subscribe(context.Background(), cacheInvalidateChannel)
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

// GetCacheStats returns cache statistics. Counters are derived from the
// version counter and Redis DBSIZE-style approximations rather than full
// SCANs to keep this cheap even on multi-million-key deployments.
func GetCacheStats() map[string]interface{} {
	if !IsCacheEnabled() {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	v := patternVersion.Load()
	return map[string]interface{}{
		"enabled":         true,
		"pattern_version": v,
		"ttl_seconds":     int(metadataCacheTTL.Seconds()),
	}
}
