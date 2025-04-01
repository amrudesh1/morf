#!/bin/bash

echo "MORF Project Auto Cleanup Script"
echo "==============================="
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

# Function to clean directory and report
clean_dir() {
    local dir=$1
    local desc=$2
    
    if [ -d "$dir" ]; then
        local size=$(get_size "$dir")
        echo "Removing $desc: $(format_size $size)"
        rm -rf "$dir"
        echo "✓ $desc removed"
    else
        echo "× $desc not found"
    fi
}

# Clean Angular cache
clean_dir "frontend/.angular" "Angular cache"

# Clean node_modules
clean_dir "frontend/node_modules" "Frontend node_modules"

# Clean log files
if [ -d "morf/log" ]; then
    size=$(get_size "morf/log")
    echo "Cleaning log files: $(format_size $size)"
    rm -rf morf/log/*.log
    echo "✓ Log files removed"
fi

# Git optimization
if [ -d ".git" ]; then
    size=$(get_size ".git")
    echo "Optimizing Git repository ($(format_size $size))..."
    git gc --aggressive
    git prune
    new_size=$(get_size ".git")
    echo "✓ Git repository optimized: $(format_size $size) → $(format_size $new_size)"
fi

# Clean DS_Store files
echo "Removing .DS_Store files..."
find . -name ".DS_Store" -delete
echo "✓ .DS_Store files removed"

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p morf/log
touch morf/log/.gitkeep

echo
echo "Cleanup complete!"
echo "Run 'npm install' in the frontend directory when needed to reinstall dependencies."
