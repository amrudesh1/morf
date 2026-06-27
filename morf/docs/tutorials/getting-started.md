# Getting Started with MORF - Video Tutorial Script

## Video Metadata
- **Title**: Getting Started with MORF - Mobile Security Scanning
- **Duration**: ~8 minutes
- **Target Audience**: Security engineers, developers new to MORF

## Script

### Introduction (0:00 - 0:30)

**[Screen: MORF logo and title]**

"Welcome to MORF - the Mobile Reconnaissance Framework. In this tutorial, we'll get you up and running with MORF to scan Android APK files for security vulnerabilities and sensitive information.

MORF is a powerful tool that helps you identify API keys, credentials, and other secrets that might be embedded in your mobile applications. Let's get started!"

### What is MORF? (0:30 - 1:30)

**[Screen: MORF features overview]**

"MORF is a comprehensive security scanning tool specifically designed for Android APK files. Here's what it does:

- **Scans APK files** for embedded secrets like API keys, tokens, and credentials
- **Extracts metadata** including package information, permissions, and components
- **Identifies security issues** through pattern matching
- **Generates detailed reports** with actionable findings
- **Integrates with CI/CD** pipelines for automated scanning

MORF uses advanced decompilation techniques and pattern matching to find sensitive information that shouldn't be in your mobile apps."

### Installation (1:30 - 3:00)

**[Screen: Installation steps]**

"Let's install MORF. The easiest way is using Docker:

**[Show terminal]**

First, clone the repository:
```bash
git clone https://github.com/your-org/morf.git
cd morf
```

Next, set up your environment variables. Create a `.env` file:
```bash
DATABASE_URL=mysql://user:password@localhost:3306/morf
REDIS_URL=redis://localhost:6379
```

Now, start MORF using Docker Compose:
```bash
docker-compose up -d
```

That's it! MORF is now running. Let's verify it's working:
```bash
curl http://localhost:9092/api/health
```

You should see a healthy status response."

### First Scan (3:00 - 6:00)

**[Screen: Web UI]**

"Now let's perform your first scan. Open your browser and navigate to:
```
http://localhost:9092
```

**[Show upload screen]**

You'll see the MORF upload interface. Here's how to scan an APK:

1. **Select Platform**: Choose Android (APK files)
2. **Upload File**: Click the upload area or drag and drop your APK file
3. **Wait for Processing**: MORF will decompile and scan your APK
4. **View Results**: Once complete, you'll see detailed scan results

**[Show results screen]**

The results screen shows:
- **Secrets Found**: List of all sensitive information detected
- **Metadata**: Package information, permissions, components
- **Confidence Levels**: High or low confidence findings
- **File Locations**: Where each secret was found

**[Show a specific secret finding]**

Each finding includes:
- The secret type (e.g., AWS API Key)
- The actual secret value
- File location and line number
- Confidence level

This helps you quickly identify and fix security issues."

### Understanding Results (6:00 - 7:00)

**[Screen: Results details]**

"Let's understand what MORF found:

**High Confidence Findings**: These are almost certainly real secrets that need immediate attention. Examples include AWS keys, API tokens, and private keys.

**Low Confidence Findings**: These might be false positives - things that look like secrets but aren't. Review these carefully.

**Metadata**: MORF also extracts useful information about your app:
- Package name and version
- Required permissions
- Activities, services, and content providers
- Resource information

You can export results in JSON, CSV, or PDF format for further analysis or reporting."

### Next Steps (7:00 - 8:00)

**[Screen: Summary slide]**

"Congratulations! You've completed your first MORF scan. Here's what to do next:

1. **Review Findings**: Go through all detected secrets and remove them from your code
2. **Fix Issues**: Update your app to use secure storage or environment variables
3. **Re-scan**: After making changes, scan again to verify fixes
4. **Set Up CI/CD**: Integrate MORF into your build pipeline for automated scanning
5. **Explore Advanced Features**: Check out pattern management, webhooks, and API integration

For more tutorials, visit our documentation at morf.example.com/docs

Thanks for watching, and happy scanning!"

## Key Points to Highlight

- Simple installation process
- Easy-to-use web interface
- Clear, actionable results
- Multiple export formats
- CI/CD integration capabilities

## Visual Elements Needed

- MORF logo and branding
- Terminal screenshots
- Web UI screenshots
- Example scan results
- Architecture diagram

