#!/bin/bash

echo "MORF Project Cleanup Script"
echo "=========================="
echo

# Function to format sizes
format_size() {
    local size=$1
    if [ $size -ge 1048576 ]; then
        echo "$(($size/1048576))MB"
    elif [ $size -ge 1024 ]; then
        echo "$(($size/1024))KB"
    else
        echo "${size}B"
    fi
}

# Function to get directory size
get_size() {
    local size=$(du -s "$1" 2>/dev/null | cut -f1)
    echo $size
}

# Function to ask yes/no question
ask() {
    local prompt=$1
    local default=${2:-"n"}
    
    while true; do
        if [ "$default" = "y" ]; then
            read -p "$prompt [Y/n] " yn
            yn=${yn:-"y"}
        else
            read -p "$prompt [y/N] " yn
            yn=${yn:-"n"}
        fi
        
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Check Angular cache
if [ -d "frontend/.angular" ]; then
    size=$(get_size "frontend/.angular")
    echo "Found Angular cache: $(format_size $size)"
    if ask "Remove Angular cache?"; then
        rm -rf frontend/.angular
        echo "✓ Angular cache removed"
    fi
fi

# Check node_modules
if [ -d "frontend/node_modules" ]; then
    size=$(get_size "frontend/node_modules")
    echo "Found frontend node_modules: $(format_size $size)"
    if ask "Remove frontend node_modules?"; then
        rm -rf frontend/node_modules
        echo "✓ Frontend node_modules removed"
    fi
fi

# Check log files
if [ -d "morf/log" ]; then
    size=$(get_size "morf/log")
    echo "Found log files: $(format_size $size)"
    if ask "Remove log files?"; then
        rm -rf morf/log/*.log
        echo "✓ Log files removed"
    fi
fi

# Git optimization
if [ -d ".git" ]; then
    size=$(get_size ".git")
    echo "Git repository size: $(format_size $size)"
    if ask "Optimize Git repository? (This will compress history but keep all commits)"; then
        echo "Optimizing Git repository..."
        git gc --aggressive
        git prune
        echo "✓ Git repository optimized"
    fi
fi

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p morf/log
touch morf/log/.gitkeep

echo
echo "Cleanup complete!"
echo "Run 'npm install' in the frontend directory when needed to reinstall dependencies."
