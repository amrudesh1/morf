# Production Monitoring and Validation Guide

This guide provides a comprehensive checklist and procedures for monitoring and validating MORF in production environments.

## Pre-Deployment Checklist

### Infrastructure Readiness
- [ ] Database backups configured and tested
- [ ] Redis persistence enabled and tested
- [ ] Monitoring stack deployed (Prometheus, Grafana)
- [ ] Log aggregation configured (ELK, Loki, etc.)
- [ ] Alerting configured and tested
- [ ] SSL/TLS certificates valid and configured
- [ ] Resource limits set appropriately
- [ ] Health checks configured
- [ ] Horizontal scaling configured
- [ ] Disaster recovery plan documented

### Application Readiness
- [ ] All migrations tested and ready
- [ ] Configuration validated
- [ ] Secrets properly configured
- [ ] Feature flags set correctly
- [ ] Rollback plan documented

## Monitoring Setup

### 1. Prometheus Configuration

Ensure Prometheus is scraping MORF metrics:

```yaml
scrape_configs:
  - job_name: 'morf'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - morf
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: morf
    metrics_path: '/api/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
```

### 2. Grafana Dashboards

Import the following dashboards:
- Scan Performance (`morf/grafana/dashboards/scan-performance.json`)
- Reliability (`morf/grafana/dashboards/reliability.json`)
- Resources (`morf/grafana/dashboards/resources.json`)
- HTTP Metrics (`morf/grafana/dashboards/http-metrics.json`)

### 3. Alerting Rules

Configure alerts from `morf/prometheus/alerts.yml`:
- Scan failures > 1%
- p95 latency > 90s
- Queue depth > 100
- Database connection errors
- High error rate (> 10/sec)
- Tool execution failures
- No scans received (stale metrics)
- High HTTP 5xx rate

## Validation Procedures

### Phase 1: Initial Deployment (0-2 hours)

#### Health Checks
```bash
# Check health endpoint
curl https://morf.example.com/api/health

# Expected response:
{
  "message": "ok",
  "status": "healthy",
  "database": "healthy",
  "redis": "healthy",
  "timestamp": 1703174400
}
```

#### Component Verification
```bash
# Check database connectivity
kubectl exec -n morf deployment/morf -- morf health-check db

# Check Redis connectivity
kubectl exec -n morf deployment/morf -- morf health-check redis

# Check metrics endpoint
curl https://morf.example.com/api/metrics | grep morf_
```

#### Test Scan
```bash
# Upload test APK
curl -X POST https://morf.example.com/api/upload \
  -F "file=@test.apk"

# Poll for results
JOB_ID="<job-id-from-upload>"
curl https://morf.example.com/api/results/$JOB_ID
```

### Phase 2: Early Monitoring (2-24 hours)

#### Metrics to Monitor

**Performance Metrics:**
- p50 latency: Should be < 35s
- p95 latency: Should be < 60s
- p99 latency: Should be < 90s
- Throughput: Should be > 150 scans/hour

**Reliability Metrics:**
- Success rate: Should be > 99%
- Error rate: Should be < 0.5%
- Job completion rate: Should be > 99.9%

**Resource Metrics:**
- CPU utilization: Should be 70-80%
- Memory usage: Should be < 3GB per pod
- Queue depth: Should be < 20 jobs (p95)

#### Log Analysis
```bash
# Check for errors
kubectl logs -n morf deployment/morf | grep ERROR

# Check for warnings
kubectl logs -n morf deployment/morf | grep WARN

# Check correlation IDs
kubectl logs -n morf deployment/morf | grep "request_id"
```

#### Database Health
```sql
-- Check job completion rate
SELECT 
  COUNT(*) as total_jobs,
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
  SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
  (SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) as success_rate
FROM scan_jobs
WHERE created_at > NOW() - INTERVAL 24 HOUR;

-- Check for duplicate scans
SELECT apk_hash, COUNT(*) as count
FROM package_data
GROUP BY apk_hash
HAVING COUNT(*) > 1;
```

#### Redis Health
```bash
# Check Redis memory usage
redis-cli INFO memory

# Check queue depth
redis-cli LLEN morf:job_queue

# Check DLQ depth
redis-cli LLEN morf:dlq
```

### Phase 3: Extended Monitoring (24-48 hours)

#### Performance Validation

**Load Testing:**
```bash
# Run load test with k6
k6 run --vus 10 --duration 5m load-test.js

# Monitor metrics during load test
watch -n 5 'curl -s https://morf.example.com/api/metrics | grep morf_http_request_duration'
```

**Throughput Validation:**
- Submit 100 test scans
- Monitor completion time
- Verify all scans complete successfully
- Check for any performance degradation

#### Error Analysis

**Error Rate Monitoring:**
```bash
# Query Prometheus for error rate
rate(morf_errors_total[5m])

# Check error types
sum by (type) (rate(morf_errors_total[5m]))
```

**Failed Job Analysis:**
```bash
# Get failed jobs from DLQ
curl https://morf.example.com/api/dlq

# Analyze failure reasons
kubectl logs -n morf deployment/morf | grep "job failed" | tail -20
```

#### Resource Validation

**CPU and Memory:**
```bash
# Check resource usage
kubectl top pods -n morf

# Check for OOM kills
kubectl get events -n morf --field-selector reason=OOMKilling
```

**Queue Depth:**
```bash
# Monitor queue depth over time
watch -n 5 'curl -s https://morf.example.com/api/metrics | grep morf_queue_depth'
```

### Phase 4: Production Validation (48+ hours)

#### User Feedback
- [ ] Collect user feedback
- [ ] Monitor support tickets
- [ ] Check user satisfaction metrics

#### Performance Trends
- [ ] Compare metrics to baseline
- [ ] Identify any degradation
- [ ] Document performance improvements

#### Reliability Trends
- [ ] Track error rates over time
- [ ] Monitor success rates
- [ ] Document any issues

## Validation Criteria

### Success Criteria (Must Meet All)

1. **Performance:**
   - p95 latency < 60s ✅
   - p99 latency < 90s ✅
   - Throughput > 150 scans/hour ✅

2. **Reliability:**
   - Success rate > 99% ✅
   - Error rate < 0.5% ✅
   - Job completion rate > 99.9% ✅

3. **Availability:**
   - Uptime > 99.9% ✅
   - No critical incidents ✅

4. **Resource Usage:**
   - CPU utilization 70-80% ✅
   - Memory usage < 3GB per pod ✅
   - Queue depth < 20 jobs (p95) ✅

### Warning Signs (Investigate Immediately)

- Error rate > 1%
- p95 latency > 90s
- Queue depth > 100 jobs
- Database connection errors
- Redis connection errors
- High memory usage (> 90%)
- High CPU usage (> 90%)

## Monitoring Dashboard

### Key Metrics to Display

1. **Overview Panel:**
   - Total scans (24h)
   - Success rate
   - Average latency
   - Active scans

2. **Performance Panel:**
   - Latency percentiles (p50, p95, p99)
   - Throughput (scans/hour)
   - Request duration histogram

3. **Reliability Panel:**
   - Success/failure rate
   - Error rate by type
   - Job status breakdown

4. **Resource Panel:**
   - CPU usage
   - Memory usage
   - Queue depth
   - Database connections

5. **Alerts Panel:**
   - Active alerts
   - Recent alerts
   - Alert history

## Troubleshooting Guide

### High Latency
1. Check queue depth
2. Check worker count
3. Check database performance
4. Check Redis performance
5. Check for stuck jobs

### High Error Rate
1. Check error logs
2. Check DLQ for failed jobs
3. Check database connectivity
4. Check Redis connectivity
5. Check for resource constraints

### Queue Backlog
1. Increase worker count
2. Scale horizontally
3. Check for stuck jobs
4. Check worker health
5. Review job processing time

### Database Issues
1. Check connection pool
2. Check query performance
3. Check for locks
4. Review slow query log
5. Check database resources

## Reporting

### Daily Reports

Generate daily reports with:
- Total scans
- Success rate
- Average latency
- Error breakdown
- Resource usage
- Active alerts

### Weekly Reports

Generate weekly reports with:
- Performance trends
- Reliability trends
- User feedback summary
- Incident summary
- Improvement recommendations

## Sign-Off

### Production Ready Checklist

- [ ] All success criteria met
- [ ] No critical alerts
- [ ] Performance within targets
- [ ] Reliability within targets
- [ ] User feedback positive
- [ ] Documentation complete
- [ ] Team trained
- [ ] Rollback plan tested

**Sign-off Date:** _______________

**Sign-off By:** _______________

---

## Next Steps

After successful validation:
1. Proceed with full production rollout (Phase 10.9)
2. Continue monitoring
3. Gather user feedback
4. Plan improvements

