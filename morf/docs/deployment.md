# MORF Deployment Guide

This guide covers deploying MORF in various environments, from local development to production Kubernetes clusters.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Configuration](#configuration)
6. [Database Setup](#database-setup)
7. [Redis Setup](#redis-setup)
8. [Monitoring Setup](#monitoring-setup)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **CPU**: Minimum 2 cores, recommended 4+ cores
- **Memory**: Minimum 4GB, recommended 8GB+
- **Disk**: Minimum 20GB free space
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, or similar), macOS, or Windows with WSL2

### Software Requirements

- **Docker**: 20.10+ (for containerized deployment)
- **Docker Compose**: 1.29+ (for local development)
- **Kubernetes**: 1.24+ (for Kubernetes deployment)
- **Go**: 1.21+ (for building from source)
- **MySQL**: 8.0+ or **SQLite** 3.x (for database)
- **Redis**: 7.0+ (for job queue)

### External Tools

MORF requires the following tools (included in Docker image):
- **apktool**: For APK decompilation
- **apkanalyzer**: For APK analysis
- **aapt**: Android Asset Packaging Tool
- **ripgrep**: For pattern scanning
- **Java**: OpenJDK 11+ (for running apktool and apkanalyzer)

## Local Development

### Quick Start with Docker Compose (macOS)

The easiest way to run MORF locally on macOS is using Docker Compose.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/morf.git
   cd MORF
   ```

2. **Start all services** (MySQL, Redis, Backend, Frontend):
   ```bash
   # Using the helper script (recommended)
   ./run-local.sh start

   # Or using docker-compose directly
   docker-compose up -d

   # Or with macOS optimizations
   docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d
   ```

3. **Verify deployment**:
   ```bash
   # Check service status
   ./run-local.sh status

   # Or manually
   curl http://localhost:9092/api/health
   ```

4. **Access the application**:
   - **Frontend**: http://localhost
   - **Backend API**: http://localhost:9092/api
   - **Health Check**: http://localhost:9092/api/health
   - **Metrics**: http://localhost:9092/api/metrics

### Service Details

- **MySQL**: Port 3306, Database: `morf`, User: `morf`, Password: `morf_password`
- **Redis**: Port 6379, No password (local development)
- **Backend**: Port 9092
- **Frontend**: Port 80

### Common Commands

```bash
# Start services
./run-local.sh start

# Stop services
./run-local.sh stop

# Restart services
./run-local.sh restart

# View logs
./run-local.sh logs

# View logs for specific service
./run-local.sh logs morf-backend

# Rebuild services
./run-local.sh rebuild

# Reset database (⚠️ deletes all data)
./run-local.sh reset-db
```

### Troubleshooting

See the README for local setup and troubleshooting.

### Manual Setup (Alternative)

If you prefer to set environment variables manually:

```bash
export DATABASE_URL="morf:morf_password@tcp(localhost:3306)/morf?charset=utf8mb4&parseTime=True&loc=Local"
export REDIS_URL="redis://localhost:6379"
docker-compose up -d
```

### Building from Source

1. **Install Go dependencies**:
   ```bash
   cd morf
   go mod download
   ```

2. **Build the binary**:
   ```bash
   go build -o morf .
   ```

3. **Run the server**:
   ```bash
   ./morf server
   ```

## Docker Deployment

### Single Container Deployment

1. **Build the image**:
   ```bash
   docker build -t morf:latest -f morf/Dockerfile morf/
   ```

2. **Run the container**:
   ```bash
   docker run -d \
     --name morf \
     -p 9092:9092 \
     -e DATABASE_URL="mysql://user:password@host:3306/morf" \
     -e REDIS_URL="redis://host:6379" \
     -v morf-uploads:/app/uploads \
     --security-opt seccomp=./morf/seccomp/seccomp-apktool.json \
     --memory="8g" \
     --cpus="4.0" \
     morf:latest
   ```

### Docker Compose Deployment

1. **Create docker-compose.yml**:
   ```yaml
   version: '3.8'
   
   services:
     redis:
       image: redis:7-alpine
       ports:
         - "6379:6379"
       volumes:
         - redis-data:/data
       command: redis-server --appendonly yes
       healthcheck:
         test: ["CMD", "redis-cli", "ping"]
         interval: 10s
         timeout: 5s
         retries: 5
   
     morf:
       build:
         context: ./morf
         dockerfile: Dockerfile
       environment:
         - DATABASE_URL=${DATABASE_URL}
         - REDIS_URL=redis:6379
       ports:
         - "9092:9092"
       volumes:
         - ./uploads:/app/uploads
       depends_on:
         redis:
           condition: service_healthy
       deploy:
         resources:
           limits:
             cpus: '4.0'
             memory: 8G
           reservations:
             cpus: '1.0'
             memory: 2G
       security_opt:
         - seccomp:./morf/seccomp/seccomp-apktool.json
       ulimits:
         nofile:
           soft: 1024
           hard: 2048
         nproc:
           soft: 512
           hard: 1024
   
   volumes:
     redis-data:
   ```

2. **Start services**:
   ```bash
   docker-compose up -d
   ```

## Kubernetes Deployment

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: morf
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: morf-config
  namespace: morf
data:
  GIN_MODE: "release"
  LOG_LEVEL: "info"
```

### Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: morf-secrets
  namespace: morf
type: Opaque
stringData:
  DATABASE_URL: "mysql://user:password@mysql-service:3306/morf"
  REDIS_URL: "redis://redis-service:6379"
```

### Redis Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: morf
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-data
          mountPath: /data
        command:
        - redis-server
        - --appendonly
        - "yes"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: redis-data
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
  namespace: morf
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: morf
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### MORF Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: morf
  namespace: morf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: morf
  template:
    metadata:
      labels:
        app: morf
    spec:
      containers:
      - name: morf
        # Replace OWNER with your GitHub owner. The release workflow pushes
        # ghcr.io/<owner>/morf; a bare `morf:latest` resolves to
        # docker.io/library/morf and ImagePullBackOffs.
        image: ghcr.io/OWNER/morf:stable
        ports:
        - containerPort: 9092
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: morf-secrets
              key: DATABASE_URL
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: morf-secrets
              key: REDIS_URL
        envFrom:
        - configMapRef:
            name: morf-config
        livenessProbe:
          httpGet:
            path: /api/live
            port: 9092
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/ready
            port: 9092
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "8Gi"
            cpu: "4"
        volumeMounts:
        - name: uploads
          mountPath: /app/uploads
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: morf-uploads-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: morf-service
  namespace: morf
spec:
  selector:
    app: morf
  ports:
  - port: 80
    targetPort: 9092
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: morf-uploads-pvc
  namespace: morf
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: 100Gi
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: morf-hpa
  namespace: morf
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
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 2
        periodSeconds: 15
      selectPolicy: Max
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | Database connection string | - | Yes* |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` | Yes |
| `GIN_MODE` | Gin framework mode (`debug`/`release`) | `debug` | No |
| `LOG_LEVEL` | Logging level (`debug`/`info`/`warn`/`error`) | `info` | No |
| `PORT` | Server port | `9092` | No |
| `WORKER_COUNT` | Number of worker goroutines | Auto-calculated | No |

*Database is optional if not using database features

### Database Connection Strings

**MySQL**:
```
mysql://username:password@host:port/database
```

**SQLite**:
```
sqlite:///path/to/database.db
```

**PostgreSQL** (if supported):
```
postgres://username:password@host:port/database
```

### Redis Connection Strings

**Standard**:
```
redis://localhost:6379
```

**With Password**:
```
redis://:password@localhost:6379
```

**With Database**:
```
redis://localhost:6379/0
```

## Database Setup

### MySQL Setup

1. **Create database**:
   ```sql
   CREATE DATABASE morf CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'morf'@'%' IDENTIFIED BY 'secure_password';
   GRANT ALL PRIVILEGES ON morf.* TO 'morf'@'%';
   FLUSH PRIVILEGES;
   ```

2. **Run migrations**:
   ```bash
   # Migrations are automatically run on startup
   # Or manually:
   mysql -u morf -p morf < morf/db/migrations/004_normalize_schema.sql
   mysql -u morf -p morf < morf/db/migrations/005_add_indexes.sql
   ```

### SQLite Setup

SQLite databases are created automatically. No manual setup required.

## Redis Setup

### Standalone Redis

1. **Install Redis**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install redis-server
   
   # macOS
   brew install redis
   ```

2. **Start Redis**:
   ```bash
   redis-server
   ```

3. **Verify**:
   ```bash
   redis-cli ping
   # Should return: PONG
   ```

### Redis with Persistence

Edit `/etc/redis/redis.conf`:
```
appendonly yes
appendfsync everysec
```

### Redis Cluster (Production)

For production, use Redis Sentinel or Redis Cluster for high availability.

## Monitoring Setup

### Prometheus

1. **Add Prometheus to docker-compose.yml**:
   ```yaml
   prometheus:
     image: prom/prometheus:latest
     ports:
       - "9090:9090"
     volumes:
       - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
       - prometheus-data:/prometheus
     command:
       - '--config.file=/etc/prometheus/prometheus.yml'
   ```

2. **Create prometheus.yml**:
   ```yaml
   global:
     scrape_interval: 15s
   
   scrape_configs:
     - job_name: 'morf'
       static_configs:
         - targets: ['morf-backend:9092']
   ```

### Grafana

1. **Add Grafana to docker-compose.yml**:
   ```yaml
   grafana:
     image: grafana/grafana:latest
     ports:
       - "3000:3000"
     volumes:
       - grafana-data:/var/lib/grafana
       - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
     environment:
       - GF_SECURITY_ADMIN_PASSWORD=admin
   ```

2. **Import dashboards**:
   - Copy dashboard JSON files from `morf/grafana/dashboards/` to Grafana

### Alerts

Prometheus alerts are configured in `morf/prometheus/alerts.yml`. See the alerts file for details.

## Troubleshooting

### Common Issues

#### Database Connection Errors

**Problem**: `database connection lost`

**Solutions**:
1. Verify `DATABASE_URL` is correct
2. Check database is running: `mysql -u user -p -e "SELECT 1"`
3. Verify network connectivity
4. Check firewall rules

#### Redis Connection Errors

**Problem**: `failed to connect to Redis`

**Solutions**:
1. Verify `REDIS_URL` is correct
2. Check Redis is running: `redis-cli ping`
3. Verify network connectivity
4. Check Redis authentication if enabled

#### Job Queue Full

**Problem**: `Queue is full, please try again later`

**Solutions**:
1. Increase worker count
2. Scale horizontally (add more instances)
3. Check for stuck jobs in DLQ
4. Increase queue depth limit (default: 1000)

#### High Memory Usage

**Problem**: Container killed due to OOM

**Solutions**:
1. Increase memory limits
2. Reduce worker count
3. Enable job result cleanup
4. Monitor for memory leaks

### Logs

**View logs**:
```bash
# Docker
docker logs morf

# Kubernetes
kubectl logs -n morf deployment/morf

# Follow logs
kubectl logs -n morf deployment/morf -f
```

### Health Checks

**Check health**:
```bash
curl http://localhost:9092/api/health
```

**Check readiness**:
```bash
curl http://localhost:9092/api/ready
```

**Check liveness**:
```bash
curl http://localhost:9092/api/live
```

### Performance Tuning

1. **Worker Count**: Adjust based on CPU cores (default: `min(max(2, cpuCount * 2), 10)`)
2. **Database Pool**: Automatically tuned based on worker count
3. **Queue Depth**: Monitor and adjust backpressure threshold
4. **Memory**: Increase for large APK files

## Production Checklist

- [ ] Database backups configured
- [ ] Redis persistence enabled
- [ ] Monitoring and alerting set up
- [ ] Log aggregation configured
- [ ] SSL/TLS certificates configured
- [ ] Resource limits set appropriately
- [ ] Health checks configured
- [ ] Horizontal scaling configured
- [ ] Disaster recovery plan documented
- [ ] Security hardening applied (seccomp, non-root user)
- [ ] Regular security updates scheduled

## Support

For issues and questions:
- GitHub Issues: https://github.com/your-org/morf/issues
- Documentation: https://morf.example.com/docs
- Email: support@morf.example.com

