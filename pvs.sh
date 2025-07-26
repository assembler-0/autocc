#!/bin/bash

# Check if build directory is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <build_directory>"
    echo "Example: $0 /path/to/build"
    exit 1
fi

BUILD_DIR="$1"

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory '$BUILD_DIR' does not exist!"
    exit 1
fi

echo "Starting PVS-Studio analysis for build directory: $BUILD_DIR"
echo "=========================================="

# Run PVS-Studio analyzer with maximum settings
echo "Running PVS-Studio analyzer..."
pvs-studio-analyzer trace  -o PVS-Studio.log -- cmake --build "$BUILD_DIR"


# Check if analysis was successful
if [ $? -ne 0 ]; then
    echo "Error: PVS-Studio analysis failed!"
    exit 1
fi

echo "Analysis complete! Converting log to HTML report..."

# Convert log to HTML with maximum verbosity
plog-converter -t fullhtml -a "GA:1,2,3;OP:1,2,3;64:1,2,3;CS:1,2,3" -o report.html PVS-Studio.log

# Check if conversion was successful
if [ $? -eq 0 ]; then
    echo "=========================================="
    echo "SUCCESS! Report generated: report.html"
    echo "Log file available at: PVS-Studio.log"
    
    # Show some stats if possible
    if command -v wc &> /dev/null && [ -f "PVS-Studio.log" ]; then
        echo "Log file size: $(wc -l < PVS-Studio.log) lines"
    fi
else
    echo "Error: Failed to convert log to HTML report!"
    exit 1
fi