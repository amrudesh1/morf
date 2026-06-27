# Uploading APKs - Video Tutorial Script

## Video Metadata
- **Title**: Uploading and Scanning APKs with MORF
- **Duration**: ~10 minutes
- **Target Audience**: Developers, DevOps engineers

## Script

### Introduction (0:00 - 0:30)

"Welcome back to MORF tutorials. In this video, we'll cover all the different ways to upload and scan APK files with MORF, including web UI, API, and bulk uploads."

### Web UI Upload (0:30 - 3:00)

**[Show upload screen]**

"The simplest way to scan an APK is through the web interface:

1. Navigate to the upload page
2. Select your APK file (drag and drop or click to browse)
3. Optionally configure a webhook URL for notifications
4. Click upload

MORF will immediately return a job ID. You can use this to check the status and retrieve results later. The scan happens asynchronously, so you don't have to wait."

### API Upload (3:00 - 6:00)

**[Show terminal with curl command]**

"For automation, use the REST API. Here's how to upload via API:

```bash
curl -X POST http://localhost:9092/api/upload \
  -F "file=@app.apk" \
  -F "webhook_url=https://example.com/webhook" \
  -F "webhook_secret=my-secret"
```

The response includes a job ID:
```json
{
  "message": "File uploaded successfully. Processing started.",
  "job_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**[Show polling example]**

Then poll for results:
```bash
curl http://localhost:9092/api/results/550e8400-e29b-41d4-a716-446655440000
```

The status will be `queued`, `processing`, `completed`, or `failed`. Once completed, the full results are included."

### Bulk Upload (6:00 - 8:00)

**[Show bulk upload API]**

"For scanning multiple APKs at once, use the bulk upload endpoint:

```bash
curl -X POST http://localhost:9092/api/bulk-upload \
  -F "files=@app1.apk" \
  -F "files=@app2.apk" \
  -F "files=@app3.apk" \
  -F "webhook_url=https://example.com/webhook"
```

You can upload up to 50 files at once. The response includes:
- Total files processed
- Number of successful uploads
- List of job IDs
- Any errors encountered

Each file gets its own job ID, so you can track them individually."

### Webhook Configuration (8:00 - 9:30)

**[Show webhook setup]**

"Instead of polling, configure webhooks to receive notifications when scans complete:

When uploading, include:
- `webhook_url`: Your endpoint URL
- `webhook_secret`: Optional secret for signature verification

When a scan completes, MORF will POST to your webhook:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": { ... },
  "timestamp": "2025-12-21T10:00:00Z"
}
```

The request includes an `X-MORF-Signature` header for verification using HMAC-SHA256."

### Best Practices (9:30 - 10:00)

"Here are some tips for uploading APKs:

1. **File Size**: Large APKs take longer to process
2. **Queue Management**: Check queue depth before bulk uploads
3. **Error Handling**: Always check job status and handle failures
4. **Webhooks**: Use webhooks for production automation
5. **Rate Limiting**: Be mindful of system resources

That's it for uploading APKs. Next, we'll cover understanding and interpreting scan results."

