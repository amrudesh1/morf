# MORF - Service Restart Procedures

## Restarting MORF Service

### Docker Container
```bash
# Stop container
docker stop morf

# Start container
docker start morf

# Restart container
docker restart morf

# View logs
docker logs -f morf
```

### Docker Compose
```bash
# Restart service
docker-compose restart morf

# Restart with rebuild
docker-compose up -d --build morf

# View logs
docker-compose logs -f morf
```

### Systemd Service
```bash
# Restart service
sudo systemctl restart morf

# Check status
sudo systemctl status morf

# View logs
sudo journalctl -u morf -f
```

### Kubernetes Deployment
```bash
# Restart deployment
kubectl rollout restart deployment/morf

# Check rollout status
kubectl rollout status deployment/morf

# View logs
kubectl logs -f deployment/morf
```

## Graceful Shutdown

MORF supports graceful shutdown:
1. Stops accepting new requests
2. Waits for active scans to complete (with timeout)
3. Closes database connections
4. Cleans up workspaces
5. Exits gracefully

### Graceful Shutdown Signals
- `SIGTERM` - Standard termination signal
- `SIGINT` - Interrupt signal (Ctrl+C)

## Restart After Configuration Changes

### Environment Variables
```bash
# Update environment variables
export DATABASE_URL="new_url"
export PORT=9092

# Restart service
docker restart morf
```

### Configuration Files
```bash
# Update configuration
vim config.yml

# Restart service
docker restart morf
```

## Restart After Code Updates

### Docker
```bash
# Build new image
docker build -t morf:latest .

# Stop old container
docker stop morf

# Start new container
docker run -d --name morf morf:latest
```

### Docker Compose
```bash
# Rebuild and restart
docker-compose up -d --build
```

## Restart Database

### MySQL
```bash
# Restart MySQL
sudo systemctl restart mysql

# Check connection
mysql -u user -p -e "SELECT 1"
```

### SQLite
SQLite doesn't require restart, but you can verify:
```bash
# Check database file
ls -lh morf.db

# Verify integrity
sqlite3 morf.db "PRAGMA integrity_check;"
```

## Troubleshooting Restart Issues

### Container Won't Start
1. Check logs: `docker logs morf`
2. Verify configuration
3. Check port conflicts: `netstat -tulpn | grep 8080`
4. Check disk space: `df -h`

### Service Won't Stop
1. Force stop: `docker kill morf`
2. Check for stuck processes: `ps aux | grep morf`
3. Kill processes: `pkill -9 morf`

### Database Connection After Restart
1. Wait for database to be ready
2. Check database URL
3. Verify network connectivity
4. Review connection pool settings

## Post-Restart Verification

1. **Check health endpoint**
   ```bash
   curl http://localhost:8080/api/health
   ```

2. **Check metrics**
   ```bash
   curl http://localhost:8080/api/metrics | grep morf_scans_total
   ```

3. **Test scan**
   ```bash
   curl -X POST -F "file=@test.apk" http://localhost:8080/api/upload
   ```

4. **Monitor logs**
   ```bash
   docker logs -f morf
   ```

