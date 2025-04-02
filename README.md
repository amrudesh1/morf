<div align="center">
  
# MORF

<img src="https://github.com/amrudesh1/morf/blob/main/frontend/src/assets/morf.png" width="200" alt="MORF Logo"/>

### Mobile Reconnaissance Framework

**A powerful offensive security toolkit for mobile application analysis**

[![License](https://img.shields.io/github/license/amrudesh1/morf?style=for-the-badge&logo=opensourceinitiative&logoColor=white&color=0080ff)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/amrudesh1/morf?style=for-the-badge&logo=git&logoColor=white&color=0080ff)](https://github.com/amrudesh1/morf/commits/main)
[![Language](https://img.shields.io/github/languages/top/amrudesh1/morf?style=for-the-badge&color=0080ff)](https://github.com/amrudesh1/morf)
[![BlackHat Arsenal](https://img.shields.io/badge/BlackHat-Arsenal-blue?style=for-the-badge&color=0080ff)](https://www.blackhat.com/asia-23/arsenal/schedule/#morf---mobile-reconnaissance-framework-31292)

<p><b>Find Secrets. Protect Apps. Stay Secure.</b></p>

</div>

## 📋 Table of Contents

- [💡 Overview](#-overview)
- [🚀 Quick Start](#-quick-start)
- [🔍 Key Features](#-key-features)
- [🏗️ Architecture](#️-architecture)
- [📋 Common Use Cases](#-common-use-cases)
- [📦 Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Method 1: Docker (Recommended)](#method-1-docker-recommended)
  - [Method 2: Run Script](#method-2-run-script)
  - [Environment Configuration](#environment-configuration)
- [🖥️ Usage](#️-usage)
  - [Web Interface](#web-interface)
  - [Command Line Interface](#command-line-interface)
- [🏆 Conference Recognition](#-conference-recognition)
- [🛣️ Development Roadmap](#️-development-roadmap)
- [👨‍💻 Authors](#-authors)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

## 💡 Overview

MORF is an advanced **mobile security analysis tool** that automatically discovers sensitive information within Android and iOS applications. Designed for security professionals, penetration testers, and developers, MORF provides comprehensive insights into mobile app security posture.

<p align="center">
  <img src="https://github.com/amrudesh1/MORF/assets/20198748/1fec6d18-e279-4a8a-b63c-01a1d66c20a2" width="800" alt="MORF Demo"/>
</p>

## 🚀 Quick Start

MORF can be up and running in seconds using Docker or the included run script:

```bash
# Clone the repository and enter directory
git clone https://github.com/amrudesh1/morf && cd morf

# Option 1: Using the run script (recommended)
chmod +x run.sh && ./run.sh

# Option 2: Using Docker Compose
docker-compose up --build
```

Then simply visit **[http://localhost](http://localhost)** in your browser and upload an APK or IPA file to begin analysis!

<br>

## 🔍 Key Features

MORF offers comprehensive security analysis capabilities for mobile applications:

| Feature | Description |
|---------|-------------|
| **🔐 Secret & API Key Detection** | Automatically discovers hardcoded credentials, API keys, and tokens throughout the application code and resources |
| **📱 Component Analysis** | Extracts activities, services, receivers, and content providers, highlighting security risks in app structure |
| **🛡️ Permission Analysis** | Identifies overprivileged applications and highlights dangerous permission combinations |
| **🔗 Deeplink Inspection** | Maps URL schemes and deeplink patterns that could potentially be exploited |
| **📊 Metadata Collection** | Gathers extensive app metadata for security assessment and threat modeling |
| **📜 Version Comparison** | Tracks security changes between app versions to identify fixes and regressions |

<br>

## 🏗️ Architecture

MORF combines a Go backend with an Angular frontend for powerful analysis with an intuitive interface:

<p align="center">
  <img src="https://github.com/amrudesh1/MORF/assets/20198748/f5bcdbbf-68ea-41bc-9c12-3f6d07e9049d" width="800" alt="MORF Architecture"/>
</p>

<br>

## 📋 Common Use Cases

| Use Case | Description |
|----------|-------------|
| **🕵️ Security Audits** | Pre-release scanning to identify security issues before apps reach production |
| **🔍 Competitive Analysis** | Understand security implementations in competitor applications |
| **⚙️ CI/CD Integration** | Automate security checks in your build pipeline with MORF's CLI capabilities |
| **👨‍🏫 Security Education** | Train developers on secure mobile development using real-world examples |

<br>

## 📦 Installation

### Prerequisites

- **Docker** (recommended for simplest installation)
- Alternatively: **Go** and **Node.js** for development setup

### Method 1: Docker (Recommended)

```bash
git clone https://github.com/amrudesh1/morf
cd morf
docker-compose up --build
```

### Method 2: Run Script

```bash
git clone https://github.com/amrudesh1/morf
cd morf
chmod +x run.sh
./run.sh
```

### Environment Configuration

MORF requires the `DATABASE_URL` environment variable to connect to your database:

```bash
# macOS/Linux
export DATABASE_URL="root@tcp(localhost:3306)/Secrets?charset=utf8mb4&parseTime=True&loc=Local"

# Windows (CMD)
set DATABASE_URL=root@tcp(localhost:3306)/Secrets?charset=utf8mb4&parseTime=True&loc=Local

# Windows (PowerShell)
$env:DATABASE_URL = "root@tcp(localhost:3306)/Secrets?charset=utf8mb4&parseTime=True&loc=Local"
```

> **Note**: Docker Compose will automatically use the environment variables set on your host machine.

<br>

## 🖥️ Usage

### Web Interface

After starting MORF, access the intuitive web interface at [http://localhost](http://localhost) and follow these steps:

1. Upload your APK or IPA file using the drag-and-drop interface
2. Wait for MORF to process and analyze the application
3. Explore the detailed results, including:
   - Discovered secrets and API keys
   - Component security analysis
   - Permission assessment
   - Deeplink mapping
   - Comprehensive metadata

### Command Line Interface

MORF also provides a powerful CLI for automation and integration:

```bash
# Basic scan with console output
./morf cli --apk-path=/path/to/app.apk

```

<br>

## 🏆 Conference Recognition

### Conference Appearances

<table>
<tr>
<td align="center" width="50%">
<h3>BlackHat Asia 2023</h3>
<p>MORF was presented at the Arsenal section, showcasing its capabilities in mobile application security analysis and secret detection.</p>
<p><a href="https://www.blackhat.com/asia-23/arsenal/schedule/#morf---mobile-reconnaissance-framework-31292">View Presentation</a></p>
</td>
<td align="center" width="50%">
<h3>BlackHat US 2023</h3>
<p>MORF was featured at BlackHat US 2023 Arsenal, demonstrating advanced mobile security reconnaissance techniques to security professionals.</p>
<p><a href="https://www.blackhat.com/us-23/arsenal/schedule/index.html#morf---mobile-reconnaissance-framework-32370">View Presentation</a></p>
</td>
</tr>
<tr>
<td align="center" width="50%">
<h3>BlackHat Europe 2024</h3>
<p>MORF continues to gain recognition with its selection for BlackHat Europe 2024 Arsenal, highlighting its ongoing development and relevance in mobile security.</p>
<p><a href="https://www.blackhat.com/eu-24/arsenal/schedule/index.html#morf---mobile-reconnaissance-framework-42172">View Presentation</a></p>
</td>
<td align="center" width="50%">
<h3>BlackHat Asia 2025</h3>
<p>Looking ahead, MORF has been selected for BlackHat Asia 2025 Arsenal, demonstrating its continued evolution and importance in the mobile security landscape.</p>
<p><a href="https://www.blackhat.com/asia-25/arsenal/schedule/#morf---mobile-reconnaissance-framework-43910">View Presentation</a></p>
</td>
</tr>
</table>

<br>

## 🛣️ Development Roadmap

<div style="background-color: #f0f8ff; padding: 20px; border-radius: 8px; border-left: 5px solid #4caf50; margin-bottom: 20px;">
<h3>✅ v1.0 - Initial Release</h3>
<ul>
<li>APK scanning and analysis</li>
<li>Secret detection</li>
<li>Basic web interface</li>
</ul>
</div>

<div style="background-color: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 5px solid #9e9e9e; margin-bottom: 20px;">
<h3>⏳ v1.1 - Enhanced iOS Support</h3>
<ul>
<li>Improved IPA analysis</li>
<li>iOS-specific pattern detection</li>
<li>Swift/Objective-C code scanning</li>
</ul>
</div>

<div style="background-color: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 5px solid #9e9e9e; margin-bottom: 20px;">
<h3>⏳ v1.2 - Reporting Enhancements</h3>
<ul>
<li>PDF export functionality</li>
<li>Compliance reporting</li>
<li>Historical comparison views</li>
</ul>
</div>

<div style="background-color: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 5px solid #9e9e9e; margin-bottom: 20px;">
<h3>⏳ v2.0 - Advanced Analysis</h3>
<ul>
<li>Machine learning-based vulnerability detection</li>
<li>Dynamic code analysis</li>
<li>Advanced threat modeling</li>
</ul>
</div>

<br>

## 👨‍💻 Authors

<div align="center">

| <img src="https://github.com/amrudesh1.png" width="100" height="100" style="border-radius:50%"><br>[**@amrudesh1**](https://github.com/amrudesh1) | <img src="https://github.com/abhi-r3v0.png" width="100" height="100" style="border-radius:50%"><br>[**@abhi-r3v0**](https://github.com/abhi-r3v0) | <img src="https://github.com/himanshudas.png" width="100" height="100" style="border-radius:50%"><br>[**@himanshudas**](https://github.com/himanshudas) |
|:---:|:---:|:---:|

</div>

<br>

## 📄 License

MORF is released under the MIT License. See the [LICENSE](LICENSE) file for more details.

<br>

## 🙏 Acknowledgments

- [**Secrets Patterns Database**](https://github.com/mazen160/secrets-patterns-db) - Pattern database used by MORF for secret detection
- **Open Source Security Community** - For inspiration, feedback and support
- **All Contributors** - Everyone who has contributed code, feedback, and ideas to the MORF project

---

<div align="center">
  <a href="#morf">
    <img src="https://img.shields.io/badge/back%20to%20top-%E2%86%A9-blue?style=for-the-badge" alt="Back to top" />
  </a>
</div>
