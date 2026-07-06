# MORF Video Tutorials

This document provides scripts and guides for creating video tutorials for MORF. Each tutorial includes a script, key points to cover, and example scenarios.

## Tutorial 1: Getting Started with MORF

### Duration: 5-7 minutes
### Audience: New users

### Script Outline:

1. **Introduction (30 seconds)**
   - What is MORF?
   - What does it do? (APK security scanning)
   - Why use MORF?

2. **Prerequisites (30 seconds)**
   - Docker installed
   - Basic command-line knowledge
   - An APK file to scan

3. **Quick Start (2 minutes)**
   - Start MORF with Docker Compose
   ```bash
   docker-compose up -d
   ```
   - Verify health check
   ```bash
   curl http://localhost:9092/api/health
   ```
   - Open web UI at http://localhost:9092

4. **First Scan (2 minutes)**
   - Upload an APK file via web UI
   - Show job ID returned
   - Poll for results
   - Show results screen with secrets found

5. **Summary (30 seconds)**
   - Key takeaways
   - Next steps (CLI, API, patterns)

### Key Points:
- Emphasize ease of use
- Show both web UI and API
- Highlight security findings

---

## Tutorial 2: Uploading APKs

### Duration: 4-6 minutes
### Audience: All users

### Script Outline:

1. **Introduction (20 seconds)**
   - Different ways to upload APKs
   - When to use each method

2. **Web UI Upload (1.5 minutes)**
   - Navigate to upload screen
   - Drag and drop APK file
   - Show file validation
   - Show job creation and ID
   - Show processing status

3. **API Upload (1.5 minutes)**
   - Single file upload
   ```bash
   curl -X POST http://localhost:9092/api/upload \
     -F "file=@app.apk"
   ```
   - Show response with job ID
   - Bulk upload
   ```bash
   curl -X POST http://localhost:9092/api/bulk-upload \
     -F "files=@app1.apk" \
     -F "files=@app2.apk"
   ```
   - Show multiple job IDs

4. **Slack Integration (1 minute)**
   - Show Slack scan endpoint
   - Explain use case
   - Show example request

5. **Best Practices (30 seconds)**
   - File naming conventions
   - When to use bulk upload
   - Queue management

### Key Points:
- Show all upload methods
- Emphasize job-based workflow
- Show error handling

---

## Tutorial 3: Understanding Results

### Duration: 6-8 minutes
### Audience: Security analysts, developers

### Script Outline:

1. **Introduction (30 seconds)**
   - What results contain
   - How to interpret findings

2. **Result Structure (2 minutes)**
   - Job status (queued, processing, completed, failed)
   - Result data structure:
     - Package information
     - Secrets found
     - Metadata
     - Components (activities, services, etc.)

3. **Secret Findings (2 minutes)**
   - Secret types (API keys, passwords, tokens)
   - Confidence levels (high, medium, low)
   - Location information (file, line number)
   - Example secret display

4. **Exporting Results (1.5 minutes)**
   - JSON export
   ```bash
   curl "http://localhost:9092/api/results/{jobID}/export?format=json" \
     -o results.json
   ```
   - CSV export
   - PDF export (if implemented)
   - Show exported files

5. **Comparing Scans (1 minute)**
   - Compare two scan results
   ```bash
   curl "http://localhost:9092/api/compare/{jobID1}/{jobID2}"
   ```
   - Show diff (added, removed, unchanged)

6. **Interpreting Results (1 minute)**
   - What to do with findings
   - False positives
   - Remediation steps

### Key Points:
- Detailed explanation of result structure
- Show real examples
- Emphasize actionable insights

---

## Tutorial 4: Using the CLI

### Duration: 5-7 minutes
### Audience: Developers, DevOps engineers

### Script Outline:

1. **Introduction (20 seconds)**
   - CLI vs API vs Web UI
   - When to use CLI

2. **Installation (1 minute)**
   - Build from source
   ```bash
   go build -o morf .
   ```
   - Or use Docker
   ```bash
   docker run morf:latest morf --help
   ```

3. **Basic Commands (2 minutes)**
   - Scan an APK
   ```bash
   morf scan --apk app.apk --output results.json
   ```
   - Show progress
   - Show results

4. **Advanced Options (2 minutes)**
   - Custom patterns
   ```bash
   morf scan --apk app.apk --patterns custom-patterns.yml
   ```
   - Output formats
   - Verbose mode
   - Filter by confidence

5. **Integration Examples (1 minute)**
   - CI/CD integration
   - Script automation
   - Batch processing

6. **Summary (30 seconds)**
   - Key commands
   - Common use cases

### Key Points:
- Show practical examples
- Emphasize automation
- Show integration scenarios

---

## Tutorial 5: API Integration

### Duration: 8-10 minutes
### Audience: Developers, integrators

### Script Outline:

1. **Introduction (30 seconds)**
   - RESTful API overview
   - Authentication (currently none)
   - Base URL and endpoints

2. **API Basics (2 minutes)**
   - OpenAPI specification
   - Request/response format
   - Error handling
   - Correlation IDs

3. **Upload and Poll Workflow (2 minutes)**
   - Upload APK
   ```bash
   curl -X POST http://localhost:9092/api/upload \
     -F "file=@app.apk"
   ```
   - Get job ID
   - Poll for results
   ```bash
   curl http://localhost:9092/api/results/{jobID}
   ```
   - Handle status transitions

4. **Webhooks (2 minutes)**
   - Set up webhook URL
   ```bash
   curl -X POST http://localhost:9092/api/upload \
     -F "file=@app.apk" \
     -F "webhook_url=https://example.com/webhook" \
     -F "webhook_secret=my-secret"
   ```
   - Show webhook payload
   - Verify signature
   - Handle webhook delivery

5. **Pattern Management API (1.5 minutes)**
   - List patterns
   ```bash
   curl http://localhost:9092/api/patterns
   ```
   - Create/update patterns
   - Test patterns

6. **Error Handling (1 minute)**
   - Common errors
   - Retry logic
   - Rate limiting (if implemented)

7. **Code Examples (1 minute)**
   - Python example
   - JavaScript example
   - Go example

8. **Summary (30 seconds)**
   - Key endpoints
   - Best practices
   - Documentation links

### Key Points:
- Show complete workflows
- Emphasize webhooks for async processing
- Provide code examples in multiple languages

---

## Production Tips

### Recording Setup:
- Use screen recording software (OBS, Camtasia, etc.)
- Record at 1080p minimum
- Use clear, readable fonts
- Show terminal/command line clearly
- Use consistent color scheme

### Audio:
- Clear narration
- Explain what you're doing
- Avoid background noise
- Use good microphone

### Editing:
- Add captions/subtitles
- Add chapter markers
- Add callouts for important points
- Keep videos concise
- Add links to documentation

### Publishing:
- Upload to YouTube/Vimeo
- Embed in documentation
- Create playlist for all tutorials
- Add timestamps in description
- Include download links for example files

---

## Example Files for Tutorials

### Sample APK Files:
- Create test APKs with known secrets
- Include various secret types
- Use realistic package names
- Include metadata

### Sample Scripts:
- Python upload script
- JavaScript polling script
- Bash automation script
- CI/CD integration examples

---

## Tutorial Checklist

Before publishing each tutorial:

- [ ] Script reviewed
- [ ] All commands tested
- [ ] Example files prepared
- [ ] Screenshots/recordings done
- [ ] Audio quality checked
- [ ] Captions added
- [ ] Links verified
- [ ] Documentation updated with video links

