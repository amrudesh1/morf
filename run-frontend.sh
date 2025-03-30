#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting MORF frontend${NC}"
echo -e "${BLUE}=======================================${NC}"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed${NC}"
    exit 1
fi

# Check if Angular CLI is installed
if ! command -v ng &> /dev/null; then
    echo -e "${RED}Error: Angular CLI is not installed${NC}"
    echo -e "${BLUE}Installing Angular CLI...${NC}"
    npm install -g @angular/cli
fi

# Navigate to the frontend directory
cd "$(dirname "$0")/frontend"

# Install dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
npm install

# Start the Angular development server
echo -e "${GREEN}Starting Angular development server...${NC}"
ng serve --open
