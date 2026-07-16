/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"morf/metrics"
	"net/http"

	"github.com/gin-gonic/gin"
)

// defaultMaxBodyBytes bounds request bodies on the JSON mutation routes
// (/jira, /slackscan, and the /patterns CRUD verbs). It is deliberately NOT
// applied to /upload or /bulk-upload, which stream multi-hundred-MiB APK/IPA
// payloads and enforce their own multipart caps (maxUploadSize,
// maxBulkUploadSize). 5 MiB comfortably fits even a large pattern-file body.
const defaultMaxBodyBytes = 5 << 20

// maxBodyBytes resolves the JSON body cap, tunable via MORF_MAX_BODY_BYTES.
// A non-positive value is treated as "use the default" rather than an
// unlimited body, so a misconfigured env var can never silently remove the cap.
func maxBodyBytes() int64 {
	n := envIntDefault("MORF_MAX_BODY_BYTES", defaultMaxBodyBytes)
	if n <= 0 {
		return defaultMaxBodyBytes
	}
	return int64(n)
}

// MaxBodyBytesMiddleware caps the request body for JSON mutation routes.
//
// It rejects up front on a truthful Content-Length (fast path, no bytes read),
// and additionally wraps the body in an http.MaxBytesReader so a chunked or
// lying client is aborted mid-read once it crosses the limit. When the reader
// trips during binding, ShouldBindJSON/ShouldBindBodyWith returns an error and
// the handler's existing 400 path fires — no handler change is required.
func MaxBodyBytesMiddleware(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > limit {
			metrics.RecordError("validation")
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":    "request body too large",
				"max_size": limit,
				"size":     c.Request.ContentLength,
			})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}
