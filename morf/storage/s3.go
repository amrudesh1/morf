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
	"time"
)

// defaultS3Region is used when MORF_S3_REGION is unset.
const defaultS3Region = "us-east-1"

// s3HTTPTimeout bounds each S3 HTTP request.
const s3HTTPTimeout = 5 * time.Minute

// ErrNotExist is returned by S3Storage for operations on a missing key.
var ErrNotExist = errors.New("storage: object does not exist")

// S3Storage is an S3-compatible object store backend (AWS S3, MinIO, R2),
// implemented with the standard library and signed with AWS Signature V4.
type S3Storage struct {
	client    *http.Client
	endpoint  *url.URL // scheme://host[:port]
	bucket    string
	region    string
	creds     credentials
	pathStyle bool
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
}

// NewS3StorageFromEnv builds an S3Storage from the MORF_S3_* / AWS_* environment.
func NewS3StorageFromEnv() (*S3Storage, error) {
	cfg := S3Config{
		Endpoint:        os.Getenv("MORF_S3_ENDPOINT"),
		Bucket:          os.Getenv("MORF_S3_BUCKET"),
		Region:          os.Getenv("MORF_S3_REGION"),
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		ForcePathStyle:  envBoolDefault("MORF_S3_FORCE_PATH_STYLE", true),
	}
	return NewS3Storage(cfg)
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
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("storage: MORF_S3_ENDPOINT is required for the s3 backend")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("storage: MORF_S3_BUCKET is required for the s3 backend")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, errors.New("storage: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for the s3 backend")
	}
	ep, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("storage: invalid MORF_S3_ENDPOINT %q: %w", cfg.Endpoint, err)
	}
	if ep.Scheme == "" || ep.Host == "" {
		return nil, fmt.Errorf("storage: MORF_S3_ENDPOINT %q must include scheme and host", cfg.Endpoint)
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = defaultS3Region
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: s3HTTPTimeout}
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
		pathStyle: cfg.ForcePathStyle,
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

// Put stores size bytes from r under key via HTTP PUT. The body is buffered to
// compute the SigV4 payload hash; uploads are bounded so this is acceptable.
func (s *S3Storage) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("storage: reading upload for %q: %w", key, err)
	}
	if size >= 0 && int64(len(body)) != size {
		return fmt.Errorf("storage: upload size mismatch for %q: got %d, want %d", key, len(body), size)
	}
	req, err := s.newSignedRequest(ctx, http.MethodPut, key, body)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
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
	req, err := s.newSignedRequest(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
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
	req, err := s.newSignedRequest(ctx, http.MethodDelete, key, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
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
	req, err := s.newSignedRequest(ctx, http.MethodHead, key, nil)
	if err != nil {
		return 0, err
	}
	resp, err := s.client.Do(req)
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
