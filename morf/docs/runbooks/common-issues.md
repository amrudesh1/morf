# MORF - Common Issues and Solutions

## Table of Contents
1. [Scan Failures](#scan-failures)
2. [Database Connection Issues](#database-connection-issues)
3. [High Latency](#high-latency)
4. [Tool Execution Failures](#tool-execution-failures)
5. [Memory Issues](#memory-issues)
6. [Disk Space Issues](#disk-space-issues)

## Scan Failures

### Symptoms
- Scans returning errors
- High failure rate in metrics
- Error logs showing scan failures

### Diagnosis
1. Check metrics: `morf_scans_total{status="failed"}`
2. Review logs for specific error messages
3. Check tool execution metrics: `morf_tool_execution_duration_seconds`

### Solutions
1. **Decompilation Failures**
   - Verify APK file is not corrupted
   - Check disk space availability
   - Review apktool logs
   - Ensure sufficient memory (2GB+ per scan)

2. **Pattern Scan Failures**
   - Verify pattern files are valid YAML
   - Check ripgrep is installed and accessible
   - Review pattern file permissions

3. **Metadata Extraction Failures**
   - Verify apkanalyzer.jar is present
   - Check Java is installed and accessible
   - Review output directory permissions

## Database Connection Issues

### Symptoms
- Database errors in logs
- High `morf_errors_total{type="database"}` metric
- Service unavailable responses

### Diagnosis
1. Check database connection pool: `morf_db_pool_connections`
2. Review database logs
3. Test database connectivity manually

### Solutions
1. **Connection Pool Exhausted**
   - Increase `MaxOpenConns` in database configuration
   - Reduce concurrent scans
   - Check for connection leaks

2. **Connection Timeout**
   - Verify database is accessible
   - Check network connectivity
   - Review database server load

3. **Authentication Failures**
   - Verify DATABASE_URL is correct
   - Check database credentials
   - Review database user permissions

## High Latency

### Symptoms
- p95 latency > 90s
- Slow scan completion times
- Timeout errors

### Diagnosis
1. Check scan duration metrics: `morf_scan_duration_seconds`
2. Review tool execution times: `morf_tool_execution_duration_seconds`
3. Check system resources (CPU, memory, disk I/O)

### Solutions
1. **Slow Decompilation**
   - Check CPU usage
   - Verify sufficient memory
   - Consider parallel processing improvements

2. **Slow Pattern Scanning**
   - Review number of patterns
   - Check file system performance
   - Consider batch scanning optimizations

3. **Slow Metadata Extraction**
   - Check apkanalyzer performance
   - Review output directory I/O
   - Verify Java heap size

## Tool Execution Failures

### Symptoms
- High `morf_errors_total{type="tool_execution"}` metric
- Tool timeout errors
- Missing tool errors

### Diagnosis
1. Check tool execution metrics
2. Review tool logs
3. Verify tools are installed and accessible

### Solutions
1. **Tool Not Found**
   - Verify tools are installed: apktool.jar, apkanalyzer.jar, aapt, ripgrep
   - Check PATH environment variable
   - Verify tool file permissions

2. **Tool Timeout**
   - Increase timeout values for large APKs
   - Check system resources
   - Review tool performance

3. **Tool Execution Errors**
   - Review tool-specific logs
   - Check input file validity
   - Verify tool versions are compatible

## Memory Issues

### Symptoms
- OOM (Out of Memory) errors
- High memory usage
- System slowdowns

### Diagnosis
1. Check system memory usage
2. Review memory metrics
3. Check for memory leaks

### Solutions
1. **Insufficient Memory**
   - Increase container/pod memory limits
   - Reduce concurrent scans
   - Optimize memory usage in code

2. **Memory Leaks**
   - Review workspace cleanup
   - Check for goroutine leaks
   - Review object lifecycle

## Disk Space Issues

### Symptoms
- Disk full errors
- File write failures
- Workspace creation failures

### Diagnosis
1. Check disk usage: `df -h`
2. Review workspace directory size
3. Check cleanup processes

### Solutions
1. **Disk Full**
   - Clean up old workspaces: `/tmp/morf/jobs/*`
   - Increase disk space
   - Implement automatic cleanup

2. **Workspace Cleanup Failures**
   - Verify cleanup is running
   - Check file permissions
   - Review cleanup logs

