/*
 * k6 Load Test Script for MORF
 * 
 * This script performs load testing on the MORF API endpoints:
 * - 100 concurrent uploads
 * - 1000 total scans
 * - Measures: p50/p95/p99 latency, throughput, error rate
 * 
 * Usage:
 *   k6 run k6-script.js
 * 
 * With custom options:
 *   k6 run --vus 100 --iterations 1000 k6-script.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const uploadSuccessRate = new Rate('upload_success');
const uploadDuration = new Trend('upload_duration');
const resultPollDuration = new Trend('result_poll_duration');
const totalScanDuration = new Trend('total_scan_duration');
const errorCounter = new Counter('errors_total');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 50 },   // Ramp up to 50 users
    { duration: '1m', target: 100 },   // Ramp up to 100 users
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '30s', target: 0 },   // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<60000', 'p(99)<90000'], // 95% < 60s, 99% < 90s
    'http_req_failed': ['rate<0.01'],                      // Error rate < 1%
    'upload_success': ['rate>0.95'],                      // Upload success > 95%
  },
};

// Base URL - change this to your MORF instance
const BASE_URL = __ENV.MORF_URL || 'http://localhost:9092';

// Generate a simple test APK file content (mock)
function generateMockAPK() {
  // In a real scenario, you would use an actual APK file
  // For testing, we'll use a minimal valid ZIP structure
  const zipHeader = 'PK\x03\x04'; // ZIP file header
  const content = zipHeader + 'test-apk-content-' + Math.random().toString(36);
  return content;
}

// Upload APK and get job ID
function uploadAPK() {
  const url = `${BASE_URL}/api/upload`;
  
  const formData = {
    file: http.file(generateMockAPK(), 'test.apk', 'application/vnd.android.package-archive'),
  };

  const params = {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    tags: { name: 'UploadAPK' },
  };

  const startTime = Date.now();
  const response = http.post(url, formData, params);
  const duration = Date.now() - startTime;

  uploadDuration.add(duration);
  
  const success = check(response, {
    'upload status is 202': (r) => r.status === 202,
    'response has job_id': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.job_id !== undefined;
      } catch (e) {
        return false;
      }
    },
  });

  uploadSuccessRate.add(success);
  
  if (!success) {
    errorCounter.add(1);
    console.error(`Upload failed: ${response.status} - ${response.body}`);
  }

  let jobId = null;
  try {
    const body = JSON.parse(response.body);
    jobId = body.job_id;
  } catch (e) {
    console.error('Failed to parse upload response:', e);
  }

  return { jobId, status: response.status, success };
}

// Poll for results
function pollResults(jobId, maxAttempts = 60) {
  const url = `${BASE_URL}/api/results/${jobId}`;
  let attempts = 0;
  const pollStartTime = Date.now();

  while (attempts < maxAttempts) {
    const startTime = Date.now();
    const response = http.get(url, { tags: { name: 'PollResults' } });
    const duration = Date.now() - startTime;
    
    resultPollDuration.add(duration);

    const checkResult = check(response, {
      'poll status is 200': (r) => r.status === 200,
    });

    if (!checkResult) {
      errorCounter.add(1);
      break;
    }

    try {
      const body = JSON.parse(response.body);
      const status = body.status || body.data?.status;

      if (status === 'completed' || status === 'failed') {
        const totalDuration = Date.now() - pollStartTime;
        totalScanDuration.add(totalDuration);
        return { status, body, totalDuration };
      }
    } catch (e) {
      console.error('Failed to parse poll response:', e);
      errorCounter.add(1);
      break;
    }

    attempts++;
    sleep(2); // Wait 2 seconds between polls
  }

  errorCounter.add(1);
  return { status: 'timeout', totalDuration: Date.now() - pollStartTime };
}

// Main test function
export default function () {
  // Upload APK
  const { jobId, success } = uploadAPK();
  
  if (!success || !jobId) {
    return;
  }

  // Poll for results
  const result = pollResults(jobId);
  
  // Verify final result
  check(result, {
    'scan completed or failed': (r) => r.status === 'completed' || r.status === 'failed',
    'total duration < 10 minutes': (r) => r.totalDuration < 600000,
  });

  // Small delay between iterations
  sleep(1);
}

// Setup function (runs once before all VUs)
export function setup() {
  // Health check
  const healthUrl = `${BASE_URL}/api/health`;
  const healthResponse = http.get(healthUrl);
  
  if (healthResponse.status !== 200) {
    throw new Error(`Health check failed: ${healthResponse.status}`);
  }

  console.log(`MORF instance is healthy at ${BASE_URL}`);
  return { baseUrl: BASE_URL };
}

// Teardown function (runs once after all VUs)
export function teardown(data) {
  console.log(`Load test completed for ${data.baseUrl}`);
}

