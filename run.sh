#!/bin/bash

# MORF - Mobile Reconnaissance Framework
# Run script to start both backend and frontend

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting MORF - Mobile Reconnaissance Framework${NC}"
echo -e "${BLUE}=======================================${NC}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Start backend in background
echo -e "${GREEN}Starting backend server...${NC}"
"$SCRIPT_DIR/run-backend.sh" &
BACKEND_PID=$!
echo -e "${BLUE}Backend PID: $BACKEND_PID${NC}"

# Wait for backend to start
echo -e "${BLUE}Waiting for backend to start...${NC}"
sleep 2

# Start frontend
echo -e "${GREEN}Starting frontend server...${NC}"
"$SCRIPT_DIR/run-frontend.sh"

# Cleanup on exit
function cleanup {
    echo -e "${BLUE}Shutting down servers...${NC}"
    kill $BACKEND_PID
    exit 0
}

# Register cleanup function
trap cleanup EXIT

# Wait for frontend to exit
wait
