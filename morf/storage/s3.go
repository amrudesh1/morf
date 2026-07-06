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

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"morf/utils"
)

// defaultS3Region is used when MORF_S3_REGION is unset.
const defaultS3Region = "us-east-1"

// s3HTTPTimeout bounds each S3 HTTP request.
const s3HTTPTimeout = 5 * time.Minute

// maxS3UploadBytes caps a single object upload. The streaming path enforces it
// via the declared size; the buffered fallback enforces it on the in-memory read
// so a hostile or buggy reader cannot become an OOM/DoS vector. It is a defense-
// in-depth backstop for the router's own per-upload limit and is set generously
// above the largest artifact the router admits (router maxBulkUploadSize = 2 GiB).
const maxS3UploadBytes = 2 << 30 // 2 GiB

// defaultS3MaxInflightBytes bounds the total resident memory across all in-flight
// uploads on this backend. PUTs acquire weight equal to their size from a global
// weighted semaphore before sending, so concurrent uploads cannot collectively
// exhaust memory. Overridable via MORF_S3_MAX_INFLIGHT_BYTES. The default (4 GiB)
// is >= maxS3UploadBytes so a single max-size upload can always proceed.
const defaultS3MaxInflightBytes = 4 << 30 // 4 GiB

// ErrNotExist is returned by S3Storage for operations on a missing key.
var ErrNotExist = errors.New("storage: object does not exist")

// s3RetryConfig returns the bounded exponential-backoff policy for transient S3
// HTTP failures (network errors, 5xx, 429). 4xx responses are not retried.
func s3RetryConfig() utils.RetryConfig {
	return utils.RetryConfig{
		MaxRetries:   3,
		InitialDelay: 200 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// S3Storage is an S3-compatible object store backend (AWS S3, MinIO, R2),
// implemented with the standard library and signed with AWS Signature V4.
type S3Storage struct {
	client    *http.Client
	endpoint  *url.URL // scheme://host[:port]
	bucket    string
	region    string
	creds     credentials
	pathStyle bool
	inflight  *byteSemaphore // bounds total resident upload memory
}

// byteSemaphore is a weighted, FIFO-fair-enough counting semaphore over a byte
// budget. It bounds the sum of in-flight upload weights to cap resident memory
// without pulling in an external dependency.
type byteSemaphore struct {
	mu    sync.Mutex
	cond  *sync.Cond
	cap   int64
	avail int64
}

func newByteSemaphore(capacity int64) *byteSemaphore {
	if capacity < 1 {
		capacity = 1
	}
	s := &byteSemaphore{cap: capacity, avail: capacity}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// acquire blocks until n bytes of budget are available or ctx is done, returning
// the actual (clamped) weight reserved on success so the caller can release the
// same amount. n is clamped to the total capacity so an oversized request cannot
// deadlock against a budget it can never satisfy.
func (b *byteSemaphore) acquire(ctx context.Context, n int64) (int64, error) {
	if n < 0 {
		n = 0
	}
	if n > b.cap {
		n = b.cap
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Wake any waiter when ctx is cancelled so a blocked acquire can unwind.
	stop := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	})
	defer stop()
	for b.avail < n {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		b.cond.Wait()
	}
	b.avail -= n
	return n, nil
}

// release returns n bytes of budget. n must match the acquired (clamped) amount.
func (b *byteSemaphore) release(n int64) {
	if n < 0 {
		n = 0
	}
	if n > b.cap {
		n = b.cap
	}
	b.mu.Lock()
	b.avail += n
	if b.avail > b.cap {
		b.avail = b.cap
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

// compile-time interface check.
var _ Storage = (*S3Storage)(nil)

// S3Config configures an S3Storage. Empty fields fall back to defaults where
// noted in NewS3Storage.
type S3Config struct {
	Endpoint        string // e.g. https://s3.us-east-1.amazonaws.com or http://localhost:9000
	Bucket          string
	Region          string // default "us-east-1"
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional
	ForcePathStyle  bool   // default true (MinIO/R2 friendly)
	Client          *http.Client
	// MaxInflightBytes caps the total resident memory across concurrent uploads.
	// <= 0 falls back to defaultS3MaxInflightBytes.
	MaxInflightBytes int64
}

// NewS3StorageFromEnv builds an S3Storage from the MORF_S3_* / AWS_* environment.
func NewS3StorageFromEnv() (*S3Storage, error) {
	cfg := S3Config{
		Endpoint:         os.Getenv("MORF_S3_ENDPOINT"),
		Bucket:           os.Getenv("MORF_S3_BUCKET"),
		Region:           os.Getenv("MORF_S3_REGION"),
		AccessKeyID:      os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey:  os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:     os.Getenv("AWS_SESSION_TOKEN"),
		ForcePathStyle:   envBoolDefault("MORF_S3_FORCE_PATH_STYLE", true),
		MaxInflightBytes: envInt64Default("MORF_S3_MAX_INFLIGHT_BYTES", defaultS3MaxInflightBytes),
	}
	return NewS3Storage(cfg)
}

// envInt64Default parses an int64 env var, returning def when unset/blank/invalid
// or non-positive.
func envInt64Default(name string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// envBoolDefault parses a boolean env var, returning def when unset/blank.
func envBoolDefault(name string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// NewS3Storage validates cfg and constructs an S3Storage.
func NewS3Storage(cfg S3Config) (*S3Storage, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("storage: MORF_S3_BUCKET is required for the s3 backend")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, errors.New("storage: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for the s3 backend")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = defaultS3Region
	}
	// MORF_S3_ENDPOINT is only required for non-AWS S3-compatible stores. When
	// it is empty (the documented path for real AWS S3, see k8s/deployment.yaml),
	// derive the regional AWS endpoint and use virtual-host-style addressing
	// (bucket.s3.<region>.amazonaws.com), which is AWS's native scheme.
	endpointRaw := strings.TrimSpace(cfg.Endpoint)
	pathStyle := cfg.ForcePathStyle
	if endpointRaw == "" {
		endpointRaw = "https://s3." + region + ".amazonaws.com"
		pathStyle = false
	}
	ep, err := url.Parse(strings.TrimRight(endpointRaw, "/"))
	if err != nil {
		return nil, fmt.Errorf("storage: invalid MORF_S3_ENDPOINT %q: %w", endpointRaw, err)
	}
	if ep.Scheme == "" || ep.Host == "" {
		return nil, fmt.Errorf("storage: MORF_S3_ENDPOINT %q must include scheme and host", endpointRaw)
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: s3HTTPTimeout}
	}
	inflightCap := cfg.MaxInflightBytes
	if inflightCap <= 0 {
		inflightCap = defaultS3MaxInflightBytes
	}
	return &S3Storage{
		client:   client,
		endpoint: ep,
		bucket:   cfg.Bucket,
		region:   region,
		creds: credentials{
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
			SessionToken:    cfg.SessionToken,
		},
		pathStyle: pathStyle,
		inflight:  newByteSemaphore(inflightCap),
	}, nil
}

// objectURL builds the request URL for key, honoring path- vs virtual-host style.
func (s *S3Storage) objectURL(key string) (*url.URL, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("storage: empty key")
	}
	u := *s.endpoint // copy
	key = strings.TrimPrefix(key, "/")
	if s.pathStyle {
		u.Path = "/" + s.bucket + "/" + key
	} else {
		u.Host = s.bucket + "." + s.endpoint.Host
		u.Path = "/" + key
	}
	return &u, nil
}

// newSignedRequest creates an HTTP request for key, signs it, and returns it.
func (s *S3Storage) newSignedRequest(ctx context.Context, method, key string, body []byte) (*http.Request, error) {
	u, err := s.objectURL(key)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	var payloadHash string
	if body != nil {
		rdr = bytes.NewReader(body)
		payloadHash = sha256Hex(body)
	} else {
		payloadHash = emptyPayloadHash
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signRequest(req, payloadHash, s.creds, s.region, "s3", time.Now())
	return req, nil
}

// newStreamingRequest creates a signed PUT for key whose body is streamed
// directly from r (no buffering). It uses X-Amz-Content-Sha256: UNSIGNED-PAYLOAD
// so the payload need not be hashed up front; ContentLength is set from size,
// which S3 requires for a non-chunked PUT.
func (s *S3Storage) newStreamingRequest(ctx context.Context, key string, r io.Reader, size int64) (*http.Request, error) {
	u, err := s.objectURL(key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), r)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	signRequest(req, unsignedPayload, s.creds, s.region, "s3", time.Now())
	return req, nil
}

// retryableStatus reports whether an S3 HTTP status code is a transient failure
// worth retrying (429 throttling or any 5xx). 4xx client errors are not retried.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// doWithRetry runs build()+client.Do under bounded exponential backoff, retrying
// only transient failures (network errors, 5xx, 429). On nil error the returned
// response is owned by the caller; non-retryable non-2xx responses (e.g. 404,
// 4xx) are returned without retry for the caller to interpret. build is invoked
// afresh each attempt so the request (and its signing timestamp) is regenerated.
func (s *S3Storage) doWithRetry(ctx context.Context, op, key string, build func() (*http.Request, error)) (*http.Response, error) {
	var out *http.Response
	err := utils.RetryWithContext(ctx, func() error {
		req, berr := build()
		if berr != nil {
			// Request construction failures are deterministic, not transient.
			return &utils.RetryableError{Err: berr, Retryable: false}
		}
		resp, derr := s.client.Do(req)
		if derr != nil {
			return derr // network/url errors are retryable per utils.IsRetryable
		}
		if retryableStatus(resp.StatusCode) {
			rerr := httpErr(op, key, resp)
			drainAndClose(resp.Body)
			return &utils.RetryableError{Err: rerr, Retryable: true}
		}
		out = resp
		return nil
	}, s3RetryConfig())
	if err != nil {
		return nil, err
	}
	return out, nil
}

// drainAndClose discards and closes a response body so the connection can be
// reused.
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

// httpErr builds an error from a non-2xx response, including a snippet of the body.
func httpErr(op, key string, resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("storage: s3 %s %q: status %d: %s", op, key, resp.StatusCode, strings.TrimSpace(string(snippet)))
}

// Put stores size bytes from r under key via HTTP PUT. When the size is known and
// r is seekable, the body is streamed directly with X-Amz-Content-Sha256:
// UNSIGNED-PAYLOAD so it is never buffered in memory; transient failures are
// retried by rewinding r. Otherwise it falls back to a hard-capped buffered PUT.
// In both paths an upload acquires weight from a global in-flight-bytes semaphore
// so concurrent uploads cannot collectively exhaust memory.
func (s *S3Storage) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	// Reject an over-cap upload before reading when the caller declares a size.
	if size > maxS3UploadBytes {
		return fmt.Errorf("storage: upload for %q is %d bytes, exceeds the %d-byte limit", key, size, int64(maxS3UploadBytes))
	}
	// Streaming fast path: known size + seekable body. Avoids buffering entirely
	// and stays retry-safe by rewinding to the original offset before each send.
	if size >= 0 {
		if seeker, ok := r.(io.Seeker); ok {
			return s.putStreaming(ctx, key, r, seeker, size)
		}
	}
	return s.putBuffered(ctx, key, r, size)
}

// putStreaming streams r (length size) to key without buffering. On a transient
// failure it rewinds r to its starting offset and retries.
func (s *S3Storage) putStreaming(ctx context.Context, key string, r io.Reader, seeker io.Seeker, size int64) error {
	start, err := seeker.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("storage: seeking upload for %q: %w", key, err)
	}
	weight, err := s.inflight.acquire(ctx, size)
	if err != nil {
		return fmt.Errorf("storage: acquiring upload budget for %q: %w", key, err)
	}
	defer s.inflight.release(weight)

	build := func() (*http.Request, error) {
		if _, serr := seeker.Seek(start, io.SeekStart); serr != nil {
			return nil, fmt.Errorf("storage: rewinding upload for %q: %w", key, serr)
		}
		return s.newStreamingRequest(ctx, key, r, size)
	}
	resp, err := s.doWithRetry(ctx, "PUT", key, build)
	if err != nil {
		return fmt.Errorf("storage: s3 PUT %q: %w", key, err)
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return httpErr("PUT", key, resp)
	}
	return nil
}

// putBuffered reads r into memory (hard-capped at maxS3UploadBytes so a hostile
// or buggy reader cannot exhaust memory) and PUTs it with a single-chunk SigV4
// payload hash. Used when size is unknown or r is not seekable.
func (s *S3Storage) putBuffered(ctx context.Context, key string, r io.Reader, size int64) error {
	// Read at most maxS3UploadBytes+1 so an over-cap body is detected even when
	// size is unknown or under-declared, then reject it below.
	body, err := io.ReadAll(io.LimitReader(r, maxS3UploadBytes+1))
	if err != nil {
		return fmt.Errorf("storage: reading upload for %q: %w", key, err)
	}
	if int64(len(body)) > maxS3UploadBytes {
		return fmt.Errorf("storage: upload for %q exceeds the %d-byte limit", key, int64(maxS3UploadBytes))
	}
	if size >= 0 && int64(len(body)) != size {
		return fmt.Errorf("storage: upload size mismatch for %q: got %d, want %d", key, len(body), size)
	}
	weight, err := s.inflight.acquire(ctx, int64(len(body)))
	if err != nil {
		return fmt.Errorf("storage: acquiring upload budget for %q: %w", key, err)
	}
	defer s.inflight.release(weight)

	build := func() (*http.Request, error) {
		return s.newSignedRequest(ctx, http.MethodPut, key, body)
	}
	resp, err := s.doWithRetry(ctx, "PUT", key, build)
	if err != nil {
		return fmt.Errorf("storage: s3 PUT %q: %w", key, err)
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return httpErr("PUT", key, resp)
	}
	return nil
}

// Open returns a reader for key via HTTP GET; the caller closes it.
func (s *S3Storage) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.doWithRetry(ctx, "GET", key, func() (*http.Request, error) {
		return s.newSignedRequest(ctx, http.MethodGet, key, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("storage: s3 GET %q: %w", key, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		drainAndClose(resp.Body)
		return nil, fmt.Errorf("%w: %q", ErrNotExist, key)
	}
	if resp.StatusCode/100 != 2 {
		defer drainAndClose(resp.Body)
		return nil, httpErr("GET", key, resp)
	}
	return resp.Body, nil
}

// Delete removes key via HTTP DELETE. S3 returns 204 whether or not the object
// existed, so absent keys produce no error.
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	resp, err := s.doWithRetry(ctx, "DELETE", key, func() (*http.Request, error) {
		return s.newSignedRequest(ctx, http.MethodDelete, key, nil)
	})
	if err != nil {
		return fmt.Errorf("storage: s3 DELETE %q: %w", key, err)
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return httpErr("DELETE", key, resp)
	}
	return nil
}

// Stat returns the size of key via HTTP HEAD (Content-Length).
func (s *S3Storage) Stat(ctx context.Context, key string) (int64, error) {
	resp, err := s.doWithRetry(ctx, "HEAD", key, func() (*http.Request, error) {
		return s.newSignedRequest(ctx, http.MethodHead, key, nil)
	})
	if err != nil {
		return 0, fmt.Errorf("storage: s3 HEAD %q: %w", key, err)
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("%w: %q", ErrNotExist, key)
	}
	if resp.StatusCode/100 != 2 {
		return 0, httpErr("HEAD", key, resp)
	}
	if resp.ContentLength < 0 {
		return 0, fmt.Errorf("storage: s3 HEAD %q: missing Content-Length", key)
	}
	return resp.ContentLength, nil
}

// LocalPath always returns ("", false): S3 is a remote backend.
func (s *S3Storage) LocalPath(key string) (string, bool) {
	return "", false
}
