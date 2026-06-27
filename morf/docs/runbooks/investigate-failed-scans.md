# MORF - Investigating Failed Scans

## Overview
This runbook helps diagnose and fix failed APK scans.

## Step 1: Identify Failed Scans

### Check Metrics
```promql
# Failed scans in last hour
sum(increase(morf_scans_total{status="failed"}[1h]))

# Failure rate
rate(morf_scans_total{status="failed"}[5m]) / rate(morf_scans_total[5m]) * 100
```

### Check Logs
```bash
# Search for failed scans
grep -i "failed\|error" /var/log/morf.log | tail -100

# Search by job ID
grep "job_id.*<job-id>" /var/log/morf.log
```

## Step 2: Classify Failure Type

### Decompilation Failures
**Symptoms:**
- Error: "Error while decompiling APK sources"
- Error: "Error while decompiling APK resources"
- Metric: `morf_errors_total{type="decompilation"}`

**Common Causes:**
1. Corrupted APK file
2. Insufficient memory
3. Disk space full
4. apktool version incompatibility

**Investigation:**
```bash
# Check APK file
file test.apk
unzip -t test.apk

# Check disk space
df -h /tmp

# Check memory
free -h

# Check apktool version
java -jar /app/tools/apktool.jar --version
```

**Solutions:**
1. Verify APK file integrity
2. Increase memory limits
3. Free up disk space
4. Update apktool version

### Metadata Extraction Failures
**Symptoms:**
- Error: "Error while extracting metadata from the APK file"
- Metric: `morf_errors_total{type="metadata_extraction"}`

**Common Causes:**
1. apkanalyzer.jar missing or corrupted
2. Java not available
3. Output directory permissions
4. APK file format issues

**Investigation:**
```bash
# Check apkanalyzer
ls -lh /app/tools/apkanalyzer.jar

# Check Java
java -version

# Check output directory
ls -ld /tmp/morf/jobs/*/output

# Test apkanalyzer manually
java -cp /app/tools/apkanalyzer.jar sk.styk.martin.bakalarka.execute.Main -analyze --in /path/to/apk --out /tmp/test
```

**Solutions:**
1. Verify apkanalyzer.jar exists
2. Install/update Java
3. Fix directory permissions
4. Verify APK format

### Pattern Scan Failures
**Symptoms:**
- No secrets found when expected
- Error: "Error unmarshaling YAML file"
- Metric: `morf_errors_total{type="pattern_scan"}`

**Common Causes:**
1. Pattern files corrupted
2. ripgrep not available
3. Invalid regex patterns
4. File system issues

**Investigation:**
```bash
# Check pattern files
ls -lh /app/patterns/*.yml
cat /app/patterns/high-confidence.yml | head -20

# Check ripgrep
which rg
rg --version

# Test pattern file
rg -n --file /app/patterns/high-confidence.yml /tmp/test
```

**Solutions:**
1. Verify pattern files are valid YAML
2. Install ripgrep
3. Fix regex patterns
4. Check file system

### Package Extraction Failures
**Symptoms:**
- Error: "Error while getting APK version etc"
- Metric: `morf_errors_total{type="package_extraction"}`

**Common Causes:**
1. aapt not available
2. APK file corrupted
3. Invalid APK format

**Investigation:**
```bash
# Check aapt
which aapt
aapt version

# Test aapt manually
aapt dump badging test.apk
```

**Solutions:**
1. Install Android SDK tools
2. Verify APK file
3. Check APK format

## Step 3: Review Specific Job

### Get Job Details
```bash
# Find job workspace
ls -la /tmp/morf/jobs/

# Check job logs
grep "<job-id>" /var/log/morf.log

# Check workspace contents
ls -la /tmp/morf/jobs/<job-id>/
```

### Check Workspace
```bash
# Check input
ls -lh /tmp/morf/jobs/<job-id>/input/

# Check output
ls -lh /tmp/morf/jobs/<job-id>/output/

# Check source files
ls -lh /tmp/morf/jobs/<job-id>/output/apk/source/

# Check resources
ls -lh /tmp/morf/jobs/<job-id>/output/apk/appres/
```

## Step 4: Reproduce Issue

### Manual Reproduction
```bash
# Create test job context
export JOB_ID="test-$(date +%s)"
mkdir -p /tmp/morf/jobs/$JOB_ID/{input,output}

# Copy APK
cp test.apk /tmp/morf/jobs/$JOB_ID/input/

# Run tools manually
java -jar /app/tools/apktool.jar d -r test.apk -o /tmp/test-source
java -jar /app/tools/apktool.jar d -s test.apk -o /tmp/test-res
aapt dump badging test.apk
```

## Step 5: Fix and Verify

### Apply Fix
Based on investigation, apply appropriate fix:
1. Update configuration
2. Fix file permissions
3. Update tools
4. Increase resources

### Verify Fix
```bash
# Test with same APK
curl -X POST -F "file=@test.apk" http://localhost:8080/api/upload

# Monitor metrics
watch -n 1 'curl -s http://localhost:8080/api/metrics | grep morf_scans_total'

# Check logs
tail -f /var/log/morf.log
```

## Common Patterns

### Pattern 1: Intermittent Failures
- Check system resources (CPU, memory, disk)
- Review concurrent scan limits
- Check for resource contention

### Pattern 2: Consistent Failures
- Check tool versions
- Verify configuration
- Review APK file format

### Pattern 3: Timeout Failures
- Increase timeout values
- Check system performance
- Review APK size

## Prevention

### Monitoring
- Set up alerts for failure rate
- Monitor error metrics
- Review logs regularly

### Testing
- Test with various APK sizes
- Test with different APK formats
- Test concurrent scans

### Maintenance
- Keep tools updated
- Monitor disk space
- Review resource limits

