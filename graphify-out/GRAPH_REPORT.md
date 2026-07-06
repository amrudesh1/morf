# Graph Report - morf-improve  (2026-07-06)

## Corpus Check
- 157 files · ~140,878 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 383 nodes · 820 edges · 19 communities
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 58 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `c2ef3367`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]

## God Nodes (most connected - your core abstractions)
1. `JobQueue` - 32 edges
2. `InitRouters()` - 20 edges
3. `CircuitBreaker` - 20 edges
4. `Pattern` - 20 edges
5. `Worker` - 19 edges
6. `Config` - 18 edges
7. `S3Storage` - 18 edges
8. `redisDo()` - 17 edges
9. `JobContext` - 15 edges
10. `newMiniQueue()` - 12 edges

## Surprising Connections (you probably didn't know these)
- `extractSecret()` --calls--> `contains()`  [INFERRED]
  morf/apk/scanner.go → morf/queue/atomic_dlq_test.go
- `InitRouters()` --calls--> `contains()`  [INFERRED]
  morf/router/routers.go → morf/queue/atomic_dlq_test.go
- `IsRetryable()` --calls--> `contains()`  [INFERRED]
  morf/utils/retry.go → morf/queue/atomic_dlq_test.go
- `isRetryable()` --calls--> `contains()`  [INFERRED]
  morf/worker/worker.go → morf/queue/atomic_dlq_test.go
- `redisDo()` --calls--> `Do()`  [INFERRED]
  morf/queue/queue.go → morf/utils/circuitbreaker.go

## Import Cycles
- None detected.

## Communities (19 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.13
Nodes (25): byteSemaphore, Client, Cond, credentials, Context, Mutex, ReadCloser, Reader (+17 more)

### Community 1 - "Community 1"
Cohesion: 0.13
Nodes (19): Float(), Int(), HandlerFunc, Limit, Limiter, Duration, Mutex, rateVisitor (+11 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (37): CancelFunc, Command, Config, Bool(), defaultStr(), Duration(), DurationPositive(), FloatPositive() (+29 more)

### Community 3 - "Community 3"
Cohesion: 0.12
Nodes (14): JobStatus, Client, Context, Duration, ScanJob, FailedWebhook, JobQueue, convertMap() (+6 more)

### Community 4 - "Community 4"
Cohesion: 0.20
Nodes (19): connectToDatabase(), convertSecretToOldFormat(), GetLastSecret(), GetSecrets(), GetSecretsPage(), InitDB(), InsertSecrets(), InsertSecretsAsync() (+11 more)

### Community 5 - "Community 5"
Cohesion: 0.67
Nodes (3): Activity, Model, Secret

### Community 6 - "Community 6"
Cohesion: 0.19
Nodes (26): H, Storage, checkDatabaseStatus(), checkExternalToolsHealth(), getUploadStore(), InitRouters(), RouterGroup, Pattern (+18 more)

### Community 7 - "Community 7"
Cohesion: 0.24
Nodes (13): Context, DB, JiraModel, SlackData, CheckDuplicateInDB(), commentToJira(), CookJiraComment(), isAllowedJiraHost() (+5 more)

### Community 8 - "Community 8"
Cohesion: 0.25
Nodes (4): Fs, JobContext, NewJobContext(), NewJobContextForID()

### Community 9 - "Community 9"
Cohesion: 0.67
Nodes (3): BroadcastReceiver, Model, Secret

### Community 10 - "Community 10"
Cohesion: 0.67
Nodes (3): ContentProvider, Model, Secret

### Community 11 - "Community 11"
Cohesion: 0.67
Nodes (3): Service, Model, Secret

### Community 12 - "Community 12"
Cohesion: 0.19
Nodes (18): Duration, Time, T, RWMutex, CircuitBreaker, BreakerState(), Do(), TestBreakerState_Redis() (+10 more)

### Community 13 - "Community 13"
Cohesion: 0.18
Nodes (24): PatternInfo, apkanalyzerJar(), apktoolJar(), extractSecret(), jvmHeapFlag(), patternsDir(), readPatternFile(), SanitizeSecrets() (+16 more)

### Community 14 - "Community 14"
Cohesion: 0.20
Nodes (24): MetaDataModel, Client, Context, Duration, PackageDataModel, GetMetadataFromCache(), GetPackageDataFromCache(), getRedisClient() (+16 more)

### Community 15 - "Community 15"
Cohesion: 0.20
Nodes (16): Context, Duration, H, JobContext, JobQueue, ScanJob, Storage, Worker (+8 more)

### Community 16 - "Community 16"
Cohesion: 0.37
Nodes (13): Miniredis, JobQueue, T, contains(), newMiniQueue(), TestCancelJobAtomic(), TestEnqueueJobAtomic(), TestEnqueueJobAtomicWithLimit() (+5 more)

### Community 17 - "Community 17"
Cohesion: 0.21
Nodes (10): Context, Duration, T, DefaultRetryConfig(), IsRetryable(), RetryWithContext(), TestIsRetryable(), TestRetryWithContext() (+2 more)

### Community 18 - "Community 18"
Cohesion: 0.60
Nodes (4): T, TestEnvIntFloatDefaults(), TestIsRetryable(), TestRetryBackoff()

## Knowledge Gaps
- **42 isolated node(s):** `SecretPatterns`, `FileInfo`, `JobQueue`, `Miniredis`, `JobStatus` (+37 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CancelFunc` connect `Community 2` to `Community 3`?**
  _High betweenness centrality (0.366) - this node is a cross-community bridge._
- **Why does `InitRouters()` connect `Community 6` to `Community 4`, `Community 12`, `Community 14`, `Community 15`, `Community 16`?**
  _High betweenness centrality (0.320) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `InitRouters()` (e.g. with `GetSecretsPage()` and `contains()`) actually correct?**
  _`InitRouters()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **What connects `SecretPatterns`, `FileInfo`, `JobQueue` to the rest of the system?**
  _42 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.12955465587044535 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.13043478260869565 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06826241134751773 - nodes in this community are weakly interconnected._