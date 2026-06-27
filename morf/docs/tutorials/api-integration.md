# API Integration - Video Tutorial Script

## Video Metadata
- **Title**: MORF API Integration Guide
- **Duration**: ~15 minutes
- **Target Audience**: Developers, integration engineers

## Script

### Introduction (0:00 - 0:30)

"Welcome to MORF API integration. We'll cover how to integrate MORF into your applications and workflows using the REST API."

### API Overview (0:30 - 2:00)

**[Show API documentation]**

"MORF provides a comprehensive REST API:

- **Base URL**: `http://localhost:9092/api`
- **Format**: JSON request/response
- **Authentication**: Currently not required (public API)
- **Rate Limiting**: Not currently enforced

All endpoints return correlation IDs in the `X-Request-ID` header for tracing."

### Uploading Files (2:00 - 5:00)

**[Show code examples]**

"Here's how to upload an APK in different languages:

**Python**:
```python
import requests

files = {'file': open('app.apk', 'rb')}
data = {
    'webhook_url': 'https://example.com/webhook',
    'webhook_secret': 'my-secret'
}

response = requests.post(
    'http://localhost:9092/api/upload',
    files=files,
    data=data
)

job_id = response.json()['job_id']
print(f"Job ID: {job_id}")
```

**JavaScript/Node.js**:
```javascript
const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');

const form = new FormData();
form.append('file', fs.createReadStream('app.apk'));
form.append('webhook_url', 'https://example.com/webhook');

const response = await axios.post(
  'http://localhost:9092/api/upload',
  form,
  { headers: form.getHeaders() }
);

const jobId = response.data.job_id;
console.log(`Job ID: ${jobId}`);
```

**Go**:
```go
file, _ := os.Open("app.apk")
defer file.Close()

body := &bytes.Buffer{}
writer := multipart.NewWriter(body)
part, _ := writer.CreateFormFile("file", "app.apk")
io.Copy(part, file)
writer.WriteField("webhook_url", "https://example.com/webhook")
writer.Close()

req, _ := http.NewRequest("POST", "http://localhost:9092/api/upload", body)
req.Header.Set("Content-Type", writer.FormDataContentType())
resp, _ := http.DefaultClient.Do(req)
```

### Polling for Results (5:00 - 8:00)

**[Show polling implementation]**

"Poll for results until completion:

**Python**:
```python
import time

def poll_results(job_id, max_wait=600):
    start_time = time.time()
    while time.time() - start_time < max_wait:
        response = requests.get(
            f'http://localhost:9092/api/results/{job_id}'
        )
        data = response.json()
        
        if data['status'] == 'completed':
            return data['result']
        elif data['status'] == 'failed':
            raise Exception(f"Job failed: {data.get('error')}")
        
        time.sleep(5)  # Poll every 5 seconds
    
    raise TimeoutError("Job did not complete in time")

results = poll_results(job_id)
```

**JavaScript**:
```javascript
async function pollResults(jobId, maxWait = 600000) {
  const startTime = Date.now();
  
  while (Date.now() - startTime < maxWait) {
    const response = await axios.get(
      `http://localhost:9092/api/results/${jobId}`
    );
    
    if (response.data.status === 'completed') {
      return response.data.result;
    } else if (response.data.status === 'failed') {
      throw new Error(`Job failed: ${response.data.error}`);
    }
    
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  
  throw new Error('Job did not complete in time');
}
```"

### Webhook Integration (8:00 - 11:00)

**[Show webhook handler]**

"Instead of polling, use webhooks:

**Python Flask**:
```python
from flask import Flask, request
import hmac
import hashlib

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('X-MORF-Signature')
    payload = request.data
    secret = 'my-secret'
    
    # Verify signature
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if signature != f'sha256={expected}':
        return 'Invalid signature', 401
    
    data = request.json
    job_id = data['job_id']
    status = data['status']
    
    if status == 'completed':
        results = data['result']
        process_results(results)
    elif status == 'failed':
        handle_failure(data['error'])
    
    return 'OK', 200
```

**Node.js Express**:
```javascript
const express = require('express');
const crypto = require('crypto');

app.post('/webhook', (req, res) => {
  const signature = req.headers['x-morf-signature'];
  const payload = JSON.stringify(req.body);
  const secret = 'my-secret';
  
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  if (signature !== `sha256=${expected}`) {
    return res.status(401).send('Invalid signature');
  }
  
  const { job_id, status, result, error } = req.body;
  
  if (status === 'completed') {
    processResults(result);
  } else if (status === 'failed') {
    handleFailure(error);
  }
  
  res.send('OK');
});
```"

### Error Handling (11:00 - 13:00)

**[Show error handling]**

"Handle errors properly:

**HTTP Errors**:
- `400`: Bad request (invalid file, etc.)
- `404`: Job not found
- `429`: Rate limited (queue full)
- `500`: Server error
- `503`: Service unavailable

**Python Example**:
```python
try:
    response = requests.post(url, files=files)
    response.raise_for_status()
    job_id = response.json()['job_id']
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 429:
        retry_after = e.response.headers.get('Retry-After')
        print(f"Queue full, retry after {retry_after} seconds")
    else:
        print(f"Error: {e.response.json()}")
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")
```

**Job Status Errors**:
```python
response = requests.get(f'/api/results/{job_id}')
data = response.json()

if data['status'] == 'failed':
    error = data.get('error', 'Unknown error')
    print(f"Job failed: {error}")
    # Handle failure (retry, alert, etc.)
```"

### Advanced Features (13:00 - 14:30)

**[Show advanced API usage]**

"Advanced API features:

**Bulk Upload**:
```python
files = [
    ('files', open('app1.apk', 'rb')),
    ('files', open('app2.apk', 'rb')),
]

response = requests.post(
    'http://localhost:9092/api/bulk-upload',
    files=files
)

job_ids = response.json()['job_ids']
```

**Export Results**:
```python
response = requests.get(
    f'http://localhost:9092/api/results/{job_id}/export',
    params={'format': 'csv'}
)

with open('results.csv', 'wb') as f:
    f.write(response.content)
```

**Compare Scans**:
```python
response = requests.get(
    f'http://localhost:9092/api/compare/{job_id1}/{job_id2}'
)

comparison = response.json()
print(f"Added: {comparison['added_count']}")
print(f"Removed: {comparison['removed_count']}")
```"

### Best Practices (14:30 - 15:00)

"API integration best practices:

1. **Use Webhooks**: Prefer webhooks over polling
2. **Handle Errors**: Always check status codes and job status
3. **Retry Logic**: Implement retries for transient failures
4. **Timeout**: Set appropriate timeouts
5. **Logging**: Log correlation IDs for debugging
6. **Rate Limiting**: Be mindful of API usage

That's MORF API integration! Check the OpenAPI spec for complete documentation."

