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
echo "Activating PVS free license"
pvs-studio-analyzer credentials PVS-Studio Free FREE-FREE-FREE-FREE
# Clean previous build artifacts
echo "Cleaning previous build artifacts..."
cmake --build "$BUILD_DIR" --target clean

# Step 1: Trace the compilation (records how files are compiled)
echo "Step 1: Tracing compilation process..."
pvs-studio-analyzer trace -o strace_out -- cmake --build "$BUILD_DIR"

# Check if tracing was successful
if [ $? -ne 0 ]; then
    echo "Error: PVS-Studio tracing failed!"
    exit 1
fi

# Verify the executable was built
if [ ! -f "$BUILD_DIR/autocc" ]; then
    echo "Error: Executable 'autocc' not found - build failed!"
    echo "Cannot proceed with analysis if compilation failed"
    exit 1
fi

echo "✓ Build successful, proceeding with static analysis..."

# Step 2: Run the actual static analysis
echo "Step 2: Running PVS-Studio static analysis..."
pvs-studio-analyzer analyze -o PVS-Studio.log -j$(nproc)

# Check if analysis was successful
if [ $? -ne 0 ]; then
    echo "Error: PVS-Studio analysis failed!"
    echo "This might be due to license issues or configuration problems"
    exit 1
fi

# Debug: Check what's actually in the analysis log
echo "Checking analysis results..."
if [ -f "PVS-Studio.log" ]; then
    log_size=$(wc -l < PVS-Studio.log)
    echo "Analysis log has $log_size lines"

    # Look for actual issues
    if [ "$log_size" -gt 0 ]; then
        echo "Sample from analysis log:"
        head -5 PVS-Studio.log

        # Count potential issues
        issue_count=$(grep -c "error\|warning" PVS-Studio.log 2>/dev/null || echo "0")
        echo "Potential issues found: $issue_count"
    else
        echo "Analysis log is empty - no issues found or analysis didn't run"
    fi
else
    echo "Error: Analysis log not created!"
    exit 1
fi

# Step 3: Convert to HTML report
echo "Step 3: Converting to HTML report..."
plog-converter -t fullhtml -a "GA:1,2,3;OP:1,2,3;64:1,2,3;CS:1,2,3" -o report.html PVS-Studio.log

# Check if conversion was successful
if [ $? -eq 0 ]; then
    echo "=========================================="
    echo "SUCCESS! Files generated:"
    echo "  - HTML Report: report.html"
    echo "  - Analysis Log: PVS-Studio.log"
    echo "  - Compile Trace: compile_trace.log"

    # Check if HTML actually has content
    if [ -f "report.html" ]; then
        html_size=$(wc -c < report.html)
        if [ "$html_size" -gt 1000 ]; then
            echo "✓ HTML report contains content ($html_size bytes)"
        else
            echo "⚠ HTML report seems small ($html_size bytes) - might be empty"
            echo "This could mean no issues were found (which is good!)"
        fi
    fi
else
    echo "Error: Failed to convert log to HTML report!"
    echo "Check if PVS-Studio.log contains valid analysis results"
    exit 1
fi