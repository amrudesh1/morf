# Full Production Rollout Guide

This guide provides step-by-step instructions for rolling out MORF to 100% of production instances after successful canary deployment and validation.

## Prerequisites

Before starting the full rollout:

- [ ] Canary deployment successful (10% traffic for 48+ hours)
- [ ] All validation criteria met (see `production-monitoring.md`)
- [ ] No critical issues identified
- [ ] Performance metrics within targets
- [ ] Team approval obtained
- [ ] Rollback plan tested and ready
- [ ] Communication plan prepared

## Rollout Strategy

### Option 1: Gradual Rollout (Recommended)

**Phase 1: 25% Traffic (Day 1)**
- Increase canary to 25% of traffic
- Monitor for 4-6 hours
- Validate metrics

**Phase 2: 50% Traffic (Day 1-2)**
- Increase to 50% of traffic
- Monitor for 8-12 hours
- Validate metrics

**Phase 3: 75% Traffic (Day 2)**
- Increase to 75% of traffic
- Monitor for 8-12 hours
- Validate metrics

**Phase 4: 100% Traffic (Day 2-3)**
- Complete rollout to 100%
- Monitor for 24 hours
- Final validation

### Option 2: Immediate Rollout

Only use if:
- Canary has been stable for 7+ days
- All metrics exceed targets
- Team confidence is very high

## Rollout Steps

### Step 1: Pre-Rollout Checklist

```bash
# Verify canary metrics
curl https://morf.example.com/api/metrics | grep morf_

# Check canary health
curl https://morf-canary.example.com/api/health

# Verify no critical alerts
# Check Grafana/Prometheus dashboards

# Backup current production state
kubectl get deployment morf -n morf-production -o yaml > morf-backup-$(date +%Y%m%d).yaml
```

### Step 2: Update Production Deployment

#### For Kubernetes (Gradual Rollout)

```bash
# Update production deployment image
kubectl set image deployment/morf morf=morf:latest -n morf-production

# Monitor rollout status
kubectl rollout status deployment/morf -n morf-production

# Watch pods
kubectl get pods -n morf-production -w
```

#### For Istio (Traffic Splitting)

```yaml
# Update VirtualService to increase canary weight
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: morf-vs
  namespace: morf-production
spec:
  hosts:
  - morf.example.com
  http:
  - route:
    - destination:
        host: morf-service
        port:
          number: 80
      weight: 75  # Gradually increase from 90 to 0
    - destination:
        host: morf-canary-service
        port:
          number: 80
      weight: 25  # Gradually increase from 10 to 100
```

#### For Docker Compose

```bash
# Pull latest image
docker pull morf:latest

# Update docker-compose.yml with new image

# Rolling restart (one instance at a time)
docker-compose up -d --scale morf=3 --no-deps morf

# Wait for health check
sleep 30
curl http://localhost:9092/api/health

# Continue with next instance
```

### Step 3: Monitor Initial Rollout

**First 15 Minutes:**
```bash
# Check health endpoints
watch -n 5 'curl -s https://morf.example.com/api/health | jq'

# Monitor error rate
watch -n 5 'curl -s https://morf.example.com/api/metrics | grep morf_errors_total'

# Check queue depth
watch -n 5 'curl -s https://morf.example.com/api/metrics | grep morf_queue_depth'

# Monitor pod status
kubectl get pods -n morf-production -w
```

**Key Metrics to Watch:**
- Error rate (should remain < 0.5%)
- Latency (p95 should remain < 60s)
- Success rate (should remain > 99%)
- Queue depth (should remain < 20)
- Resource usage (CPU, memory)

### Step 4: Validate Functionality

```bash
# Test upload endpoint
curl -X POST https://morf.example.com/api/upload \
  -F "file=@test.apk"

# Get job ID from response
JOB_ID="<job-id>"

# Poll for results
for i in {1..30}; do
  STATUS=$(curl -s https://morf.example.com/api/results/$JOB_ID | jq -r '.status')
  echo "Job status: $STATUS"
  if [ "$STATUS" == "completed" ]; then
    echo "Job completed successfully"
    break
  fi
  sleep 10
done

# Verify results
curl -s https://morf.example.com/api/results/$JOB_ID | jq '.result'
```

### Step 5: Performance Validation

```bash
# Run load test
k6 run --vus 20 --duration 10m load-test.js

# Monitor metrics during load test
watch -n 5 'curl -s https://morf.example.com/api/metrics | grep morf_http_request_duration_seconds'
```

**Expected Results:**
- p50 latency: < 35s
- p95 latency: < 60s
- p99 latency: < 90s
- Error rate: < 0.5%
- Success rate: > 99%

### Step 6: Complete Rollout

Once validated at current percentage:

```bash
# For Kubernetes - complete rollout
kubectl rollout status deployment/morf -n morf-production

# For Istio - increase to 100%
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: morf-vs
  namespace: morf-production
spec:
  hosts:
  - morf.example.com
  http:
  - route:
    - destination:
        host: morf-canary-service
        port:
          number: 80
      weight: 100
EOF

# Remove old production deployment (after validation)
# kubectl delete deployment morf -n morf-production
```

### Step 7: Post-Rollout Monitoring

**First Hour:**
- Monitor every 5 minutes
- Check all metrics
- Watch for any anomalies

**First 24 Hours:**
- Monitor every 15 minutes
- Check error logs
- Review user feedback
- Validate performance

**First Week:**
- Daily monitoring
- Weekly reports
- User feedback collection
- Performance analysis

## Rollback Procedure

### Immediate Rollback (If Critical Issues)

```bash
# Kubernetes rollback
kubectl rollout undo deployment/morf -n morf-production
kubectl rollout status deployment/morf -n morf-production

# Or restore from backup
kubectl apply -f morf-backup-YYYYMMDD.yaml

# Istio rollback
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: morf-vs
  namespace: morf-production
spec:
  hosts:
  - morf.example.com
  http:
  - route:
    - destination:
        host: morf-service
        port:
          number: 80
      weight: 100
EOF
```

### Rollback Criteria

Rollback immediately if:
- Error rate > 5%
- p95 latency > 120s
- Success rate < 95%
- Critical security issue discovered
- Data corruption detected
- Service unavailable

## Communication Plan

### Pre-Rollout
- [ ] Notify team of rollout schedule
- [ ] Post in team chat
- [ ] Update status page (if applicable)

### During Rollout
- [ ] Provide status updates every 15 minutes
- [ ] Share metrics dashboard
- [ ] Report any issues immediately

### Post-Rollout
- [ ] Announce successful rollout
- [ ] Share performance metrics
- [ ] Document lessons learned

## Success Criteria

### Technical Success
- [ ] All instances running new version
- [ ] No increase in error rate
- [ ] Performance within targets
- [ ] No critical issues
- [ ] All health checks passing

### Business Success
- [ ] User satisfaction maintained
- [ ] No service disruption
- [ ] Performance improvements realized
- [ ] Feature adoption successful

## Post-Rollout Tasks

### Immediate (First 24 Hours)
- [ ] Monitor all metrics
- [ ] Review error logs
- [ ] Collect user feedback
- [ ] Document any issues

### Short-term (First Week)
- [ ] Performance analysis
- [ ] User feedback analysis
- [ ] Incident review (if any)
- [ ] Documentation updates

### Long-term (First Month)
- [ ] Performance trends analysis
- [ ] Cost analysis
- [ ] User satisfaction survey
- [ ] Lessons learned session

## Monitoring Dashboard

### Key Metrics to Display

1. **Rollout Status:**
   - Percentage of traffic on new version
   - Number of instances updated
   - Rollout progress

2. **Performance Comparison:**
   - Latency (old vs new)
   - Throughput (old vs new)
   - Error rate (old vs new)

3. **Health Status:**
   - Service health
   - Component health
   - Active alerts

## Troubleshooting

### Common Issues

**High Error Rate:**
1. Check error logs
2. Review recent changes
3. Check dependencies
4. Consider rollback

**Performance Degradation:**
1. Check resource usage
2. Review query performance
3. Check for bottlenecks
4. Consider scaling

**Service Unavailable:**
1. Check pod status
2. Check health endpoints
3. Review recent changes
4. Immediate rollback

## Sign-Off

### Rollout Complete Checklist

- [ ] 100% of traffic on new version
- [ ] All metrics within targets
- [ ] No critical issues
- [ ] User feedback positive
- [ ] Documentation updated
- [ ] Team notified

**Rollout Completed:** _______________

**Completed By:** _______________

**Next Review:** _______________

---

## Next Steps

After successful rollout:
1. Continue monitoring
2. Gather user feedback
3. Plan next improvements
4. Document lessons learned
5. Update runbooks

