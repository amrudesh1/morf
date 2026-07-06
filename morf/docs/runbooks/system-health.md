# MORF - System Health Check

## Quick Health Check

### 1. Health Endpoint
```bash
curl http://localhost:8080/api/health
```

Expected response:
```json
{
  "message": "ok",
  "timestamp": 1234567890
}
```

### 2. Metrics Endpoint
```bash
curl http://localhost:8080/api/metrics
```

Check key metrics:
- `morf_scans_total` - Total scans by status
- `morf_active_scans` - Currently active scans
- `morf_errors_total` - Total errors by type
- `morf_queue_depth` - Current queue depth

### 3. Database Health
```bash
# Check database connection pool
curl http://localhost:8080/api/metrics | grep morf_db_pool_connections
```

### 4. System Resources
```bash
# CPU usage
top

# Memory usage
free -h

# Disk usage
df -h

# Check workspace directory
du -sh /tmp/morf/jobs/*
```

## Detailed Health Checks

### Scan Performance
1. **Check scan success rate**
   ```promql
   rate(morf_scans_total{status="success"}[5m]) / rate(morf_scans_total[5m]) * 100
   ```
   Should be > 99%

2. **Check scan latency**
   ```promql
   histogram_quantile(0.95, rate(morf_scan_duration_seconds_bucket{phase="total"}[5m]))
   ```
   Should be < 90s

3. **Check active scans**
   ```promql
   morf_active_scans
   ```
   Should match expected concurrency

### Error Rate
1. **Check total error rate**
   ```promql
   sum(rate(morf_errors_total[5m]))
   ```
   Should be < 10 errors/sec

2. **Check error breakdown**
   ```promql
   sum by (type) (rate(morf_errors_total[5m]))
   ```
   Review error types

### Resource Usage
1. **Check queue depth**
   ```promql
   morf_queue_depth
   ```
   Should be < 100

2. **Check database connections**
   ```promql
   morf_db_pool_connections
   ```
   Should not exceed pool limits

3. **Check tool execution times**
   ```promql
   histogram_quantile(0.95, rate(morf_tool_execution_duration_seconds_bucket[5m]))
   ```
   Review slow tools

## Health Check Script

```bash
#!/bin/bash

HEALTH_URL="http://localhost:8080/api/health"
METRICS_URL="http://localhost:8080/api/metrics"

echo "=== MORF Health Check ==="
echo ""

# Health endpoint
echo "1. Health Endpoint:"
curl -s $HEALTH_URL | jq .
echo ""

# Active scans
echo "2. Active Scans:"
curl -s $METRICS_URL | grep morf_active_scans | grep -v "#"
echo ""

# Error rate
echo "3. Error Rate (last 5m):"
ERROR_RATE=$(curl -s $METRICS_URL | grep 'morf_errors_total' | awk '{sum+=$2} END {print sum}')
echo "Total errors: $ERROR_RATE"
echo ""

# Queue depth
echo "4. Queue Depth:"
curl -s $METRICS_URL | grep morf_queue_depth | grep -v "#"
echo ""

# Database connections
echo "5. Database Connections:"
curl -s $METRICS_URL | grep morf_db_pool_connections | grep -v "#"
echo ""

echo "=== Health Check Complete ==="
```

## Automated Health Monitoring

### Prometheus Alerts
Monitor these alerts:
- `HighScanFailureRate` - Scan failures > 1%
- `HighScanLatency` - p95 latency > 90s
- `HighQueueDepth` - Queue depth > 100
- `DatabaseConnectionErrors` - Database errors detected
- `HighErrorRate` - Error rate > 10/sec

### Grafana Dashboards
Review these dashboards regularly:
- Scan Performance - Monitor latency and throughput
- Reliability - Monitor success rate and errors
- Resources - Monitor queue depth and connections
- HTTP Metrics - Monitor API performance

