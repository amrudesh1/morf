#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building and starting MORF backend${NC}"
echo -e "${BLUE}=======================================${NC}"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    exit 1
fi

# Navigate to the morf directory
cd "$(dirname "$0")/morf"

# Clean any previous builds
echo -e "${BLUE}Cleaning previous builds...${NC}"
rm -f morf main

# Update dependencies
echo -e "${BLUE}Updating dependencies...${NC}"
go mod tidy -v

# Build with verbose output
echo -e "${GREEN}Building backend...${NC}"
go build -v -o morf main.go
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build backend${NC}"
    exit 1
fi

# Run the server
echo -e "${GREEN}Starting server...${NC}"
./morf server
