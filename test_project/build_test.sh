#!/bin/bash

echo "=== AutoCC Enhanced Features Test ==="
echo ""

# Check if autocc is available
if ! command -v autocc &> /dev/null; then
    echo "❌ autocc not found. Please build and install autocc first."
    echo "   Run: mkdir build && cd build && cmake .. && make && sudo make install"
    exit 1
fi

echo "✅ autocc found: $(autocc version)"
echo ""

# Clean any existing configuration
echo "🧹 Cleaning any existing configuration..."
rm -rf .autocc_cache .autocc_build autocc.toml
echo ""

# Step 1: Auto configuration
echo "📝 Step 1: Running auto configuration..."
autocc autoconfig
echo ""

# Step 2: Setup
echo "⚙️  Step 2: Setting up build environment..."
autocc setup
echo ""

# Step 3: Test normal build
echo "🔨 Step 3: Testing normal build (all files)..."
autocc
echo ""

# Step 4: Enable cherry-pick mode
echo "🍒 Step 4: Enabling cherry-pick mode..."
autocc cherry-pick on
echo ""

# Step 5: Show available files
echo "📁 Available source files:"
find src -name "*.cpp" -type f | sort
echo ""

echo "🎯 Step 5: Interactive file selection..."
echo "   This will open the FTXUI interface where you can:"
echo "   - Use arrow keys or j/k to navigate"
echo "   - Press Space to select/deselect files"
echo "   - Type to search for files"
echo "   - Press 'a' to select all, 'd' to deselect all"
echo "   - Press Enter or Escape to confirm"
echo ""
echo "   Recommended: Select only main.cpp, utils.cpp, and logger.cpp"
echo "   (Skip extra.cpp to demonstrate cherry-picking)"
echo ""

read -p "Press Enter to start interactive selection..."

autocc select
echo ""

# Step 6: Build with selected files
echo "🔨 Step 6: Building with selected files..."
autocc
echo ""

# Step 7: Test smart include detection
echo "🧠 Step 7: Testing smart include detection..."
autocc smart-includes on
autocc
echo ""

# Step 8: Show configuration
echo "📋 Step 8: Current configuration:"
if [ -f autocc.toml ]; then
    cat autocc.toml
else
    echo "No autocc.toml found"
fi
echo ""

# Step 9: Test the built executable
echo "🚀 Step 9: Testing the built executable..."
if [ -f .autocc_build/a.out ]; then
    echo "Running executable:"
    ./.autocc_build/a.out
else
    echo "❌ Executable not found"
fi
echo ""

echo "✅ Test completed!"
echo ""
echo "🎉 New features demonstrated:"
echo "   ✅ FTXUI interactive file selection"
echo "   ✅ Cherry-pick mode"
echo "   ✅ Smart include detection"
echo "   ✅ Enhanced TOML configuration"
echo "   ✅ Persistent file selection"
echo ""
echo "📚 For more information, see the README.md file"