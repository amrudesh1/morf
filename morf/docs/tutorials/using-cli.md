# Using CLI - Video Tutorial Script

## Video Metadata
- **Title**: MORF CLI - Command Line Interface Guide
- **Duration**: ~10 minutes
- **Target Audience**: Developers, DevOps engineers, automation enthusiasts

## Script

### Introduction (0:00 - 0:30)

"Welcome to the MORF CLI tutorial. The command-line interface is perfect for automation, CI/CD integration, and batch processing."

### Installation (0:30 - 1:30)

**[Show installation steps]**

"Install MORF CLI:

**From Source**:
```bash
git clone https://github.com/your-org/morf.git
cd morf
go build -o morf .
sudo mv morf /usr/local/bin/
```

**From Binary**:
Download the latest release and add to PATH.

Verify installation:
```bash
morf --version
```"

### Basic Commands (1:30 - 4:00)

**[Show CLI help]**

"View available commands:
```bash
morf --help
```

**Scan an APK**:
```bash
morf cli --apk=app.apk
```

This scans the APK and prints results to stdout.

**Save to file**:
```bash
morf cli --apk=app.apk --output=results.json
```

**Use database**:
```bash
morf cli --apk=app.apk --use-db --database-url="mysql://..."
```

This stores results in the database for tracking."

### Advanced Options (4:00 - 7:00)

**[Show advanced options]**

"MORF CLI supports many options:

**Pattern Files**:
```bash
morf cli --apk=app.apk --patterns=/path/to/patterns
```

**Output Format**:
```bash
morf cli --apk=app.apk --format=json
morf cli --apk=app.apk --format=csv
```

**Verbose Output**:
```bash
morf cli --apk=app.apk --verbose
```

**Skip Metadata**:
```bash
morf cli --apk=app.apk --skip-metadata
```

**Custom Workspace**:
```bash
morf cli --apk=app.apk --workspace=/tmp/custom
```"

### Automation Examples (7:00 - 9:30)

**[Show automation scripts]**

"Here are practical automation examples:

**Batch Processing**:
```bash
#!/bin/bash
for apk in *.apk; do
  morf cli --apk="$apk" --output="results/${apk%.apk}.json"
done
```

**CI/CD Integration**:
```yaml
# GitHub Actions example
- name: Scan APK
  run: |
    morf cli --apk=app.apk --output=results.json
    if grep -q '"secretCount": [1-9]' results.json; then
      echo "Secrets found! Failing build."
      exit 1
    fi
```

**Scheduled Scanning**:
```bash
# Cron job
0 2 * * * morf cli --apk=/backup/app.apk --use-db
```"

### Tips and Best Practices (9:30 - 10:00)

"CLI best practices:

1. **Use Database**: Enable `--use-db` for tracking
2. **Output Files**: Always save results for audit trails
3. **Error Handling**: Check exit codes in scripts
4. **Performance**: Use workspace for faster repeated scans
5. **Automation**: Integrate into your build pipeline

That's the MORF CLI! Perfect for automation and integration."

