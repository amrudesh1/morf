# MORF - Mobile Reconnaissance Framework

MORF is a tool designed to scan mobile applications for sensitive information and security vulnerabilities.

## Features

- APK file analysis
- Metadata extraction
- Secret scanning
- Database storage (SQLite or MySQL)
- Report generation
- Slack integration
- JIRA integration

## Project Structure

```
morf/
├── apk/                  # APK analysis functionality
│   ├── analysis.go       # Main analysis logic
│   ├── metadata.go       # Metadata extraction
│   └── packageparse.go   # Package information parsing
├── cmd/                  # Command-line interface
│   └── cli.go            # CLI command implementation
├── core/                 # Core functionality
│   └── analysis/         # Analysis algorithms
├── db/                   # Database functionality
│   └── db.go             # Database connection and operations
├── models/               # Data models
│   ├── JiraModel.go      # JIRA integration model
│   ├── MetaDataModel.go  # Metadata model
│   ├── PackageDataModel.go # Package data model
│   ├── SecretModel.go    # Secret scanning model
│   ├── package_info.go   # Package info interface
│   └── slack.go          # Slack integration models
├── patterns/             # Pattern matching
│   └── git-leaks.yml     # Git leaks patterns
├── router/               # API routing
│   └── routers.go        # Router configuration
├── tools/                # External tools
│   └── aapt              # Android Asset Packaging Tool
├── utils/                # Utility functions
│   ├── command.go        # Command execution utilities
│   ├── database.go       # Database utilities
│   ├── directory_parser.go # Directory parsing utilities
│   ├── error.go          # Error handling utilities
│   ├── hash.go           # Hashing utilities
│   ├── report.go         # Report generation utilities
│   └── slack.go          # Slack integration utilities
├── go.mod                # Go module file
├── go.sum                # Go module checksums
├── main.go               # Main entry point
└── README.md             # This file
```

## Usage

### CLI Mode

```bash
./morf cli -a path/to/apk/file.apk
```

### Server Mode

```bash
./morf server -p 8080 -d sqlite
```

## Database Support

MORF supports both SQLite and MySQL databases:

- SQLite (default): `./morf server -d sqlite`
- MySQL: `./morf server -d mysql -u "mysql://user:password@localhost:3306/morf"`

## Dependencies

- Go 1.21+
- AAPT (Android Asset Packaging Tool)
- SQLite or MySQL

## License

Licensed under the Apache License, Version 2.0.
