# MORF - Scaling Guide

## Horizontal Scaling

### Docker Compose
```yaml
services:
  morf:
    deploy:
      replicas: 3
    environment:
      - DATABASE_URL=${DATABASE_URL}
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: morf
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: morf
        image: morf:latest
```

## Vertical Scaling

### Increase Resources
```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```

## Database Scaling

### Connection Pool Tuning
```go
sqlDB.SetMaxOpenConns(workerCount * 3)
sqlDB.SetMaxIdleConns(workerCount)
sqlDB.SetConnMaxLifetime(10 * time.Minute)
sqlDB.SetConnMaxIdleTime(5 * time.Minute)
```

### Database Replication
- Set up read replicas for query scaling
- Use connection pooling
- Monitor connection metrics

## Monitoring Scaling

### Key Metrics
- `morf_queue_depth` - Should stay low
- `morf_active_scans` - Should match replicas
- `morf_db_pool_connections` - Monitor pool usage
- `morf_scan_duration_seconds` - Should not increase

### Scaling Triggers
- Queue depth > 50
- p95 latency > 60s
- CPU usage > 70%
- Memory usage > 80%

## Auto-scaling

### Kubernetes HPA
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: morf-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: morf
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Load Balancing

### Nginx Configuration
```nginx
upstream morf {
    least_conn;
    server morf-1:8080;
    server morf-2:8080;
    server morf-3:8080;
}

server {
    listen 80;
    location / {
        proxy_pass http://morf;
    }
}
```

## Scaling Considerations

### State Management
- Use shared storage for workspaces (if needed)
- Use job queue (Redis) for distributed processing
- Avoid in-memory state

### Database
- Use connection pooling
- Monitor connection limits
- Consider read replicas

### Resources
- Monitor CPU and memory
- Set appropriate limits
- Plan for peak load

