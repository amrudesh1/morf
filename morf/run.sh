#!/bin/bash

# MORF - Mobile Reconnaissance Framework
# Run script for easy execution

# Set up colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}MORF - Mobile Reconnaissance Framework${NC}"
echo "----------------------------------------"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed or not in PATH${NC}"
    echo "Please install Go from https://golang.org/dl/"
    exit 1
fi

# Check if AAPT is installed
if ! command -v aapt &> /dev/null; then
    echo -e "${YELLOW}Warning: AAPT is not installed or not in PATH${NC}"
    echo "Using bundled AAPT in tools directory if available"
fi

# Build the application
echo -e "${GREEN}Building MORF...${NC}"
go build -o morf main.go

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed${NC}"
    exit 1
fi

# Make the binary executable
chmod +x morf

echo -e "${GREEN}Build successful!${NC}"
echo ""
echo "Usage:"
echo "  ./morf cli -a path/to/apk/file.apk       # Run in CLI mode"
echo "  ./morf server -p 8080 -d sqlite          # Run in server mode with SQLite"
echo "  ./morf server -p 8080 -d mysql -u \"mysql://user:password@localhost:3306/morf\"  # Run with MySQL"
echo ""

# Check for command line arguments
if [ "$1" == "cli" ] || [ "$1" == "server" ]; then
    echo -e "${GREEN}Running MORF with provided arguments...${NC}"
    ./morf "$@"
fi

exit 0
