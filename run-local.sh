#!/bin/bash

# MORF - Local Development Runner for macOS
# This script helps run MORF locally using Docker Compose

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  MORF - Local Development Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    echo -e "${YELLOW}Please start Docker Desktop and try again${NC}"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: docker-compose is not installed${NC}"
    exit 1
fi

# Function to start services
start_services() {
    echo -e "${GREEN}Starting MORF services...${NC}"
    
    # Check if macOS optimizations file exists
    if [ -f "docker-compose.local.yml" ]; then
        echo -e "${BLUE}Using macOS optimizations...${NC}"
        docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d
    else
        docker-compose up -d
    fi
    
    echo -e "${GREEN}Waiting for services to be healthy...${NC}"
    sleep 5
    
    # Wait for MySQL
    echo -e "${BLUE}Waiting for MySQL...${NC}"
    for i in {1..30}; do
        if docker-compose exec -T mysql mysqladmin ping -h localhost -u root -pmorf_root_password --silent 2>/dev/null; then
            echo -e "${GREEN}MySQL is ready${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}MySQL failed to start${NC}"
            exit 1
        fi
        sleep 2
    done
    
    # Wait for Redis
    echo -e "${BLUE}Waiting for Redis...${NC}"
    for i in {1..30}; do
        if docker-compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
            echo -e "${GREEN}Redis is ready${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}Redis failed to start${NC}"
            exit 1
        fi
        sleep 2
    done
    
    # Wait for backend
    echo -e "${BLUE}Waiting for backend...${NC}"
    for i in {1..60}; do
        if curl -s http://localhost:9092/api/health > /dev/null 2>&1; then
            echo -e "${GREEN}Backend is ready${NC}"
            break
        fi
        if [ $i -eq 60 ]; then
            echo -e "${YELLOW}Backend is taking longer than expected. Check logs with: docker-compose logs morf-backend${NC}"
            break
        fi
        sleep 2
    done
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  MORF is running!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}Frontend:${NC}  http://localhost"
    echo -e "${BLUE}Backend API:${NC}  http://localhost:9092/api"
    echo -e "${BLUE}Health Check:${NC}  http://localhost:9092/api/health"
    echo -e "${BLUE}Metrics:${NC}  http://localhost:9092/api/metrics"
    echo ""
    echo -e "${YELLOW}View logs:${NC}  docker-compose logs -f"
    echo -e "${YELLOW}Stop services:${NC}  docker-compose down"
    echo ""
}

# Function to stop services
stop_services() {
    echo -e "${YELLOW}Stopping MORF services...${NC}"
    docker-compose down
    echo -e "${GREEN}Services stopped${NC}"
}

# Function to show status
show_status() {
    echo -e "${BLUE}MORF Service Status:${NC}"
    echo ""
    docker-compose ps
    echo ""
    
    # Check health endpoints
    echo -e "${BLUE}Health Checks:${NC}"
    if curl -s http://localhost:9092/api/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend is healthy${NC}"
        curl -s http://localhost:9092/api/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:9092/api/health
    else
        echo -e "${RED}✗ Backend is not responding${NC}"
    fi
    echo ""
}

# Function to show logs
show_logs() {
    if [ -z "$1" ]; then
        docker-compose logs -f
    else
        docker-compose logs -f "$1"
    fi
}

# Function to rebuild services
rebuild_services() {
    echo -e "${YELLOW}Rebuilding MORF services...${NC}"
    docker-compose build --no-cache
    echo -e "${GREEN}Rebuild complete${NC}"
}

# Function to reset database
reset_database() {
    echo -e "${YELLOW}Resetting database...${NC}"
    read -p "This will delete all data. Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v mysql
        docker volume rm morf_mysql-data 2>/dev/null || true
        docker-compose up -d mysql
        echo -e "${GREEN}Database reset complete${NC}"
    else
        echo -e "${BLUE}Cancelled${NC}"
    fi
}

# Main menu
case "${1:-start}" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        sleep 2
        start_services
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    rebuild)
        rebuild_services
        start_services
        ;;
    reset-db)
        reset_database
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs [service]|rebuild|reset-db}"
        echo ""
        echo "Commands:"
        echo "  start      - Start all services"
        echo "  stop       - Stop all services"
        echo "  restart    - Restart all services"
        echo "  status     - Show service status"
        echo "  logs       - Show logs (optionally for specific service)"
        echo "  rebuild    - Rebuild and restart services"
        echo "  reset-db   - Reset database (deletes all data)"
        exit 1
        ;;
esac

