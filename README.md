# AutoCC v0.2.0 - Enhanced C++ Build System

AutoCC is an intelligent C++ build system that automatically detects dependencies and builds your project with minimal configuration. Version 0.2.0 introduces major enhancements including FTXUI integration for interactive file selection and smart include detection.

## 🚀 New Features in v0.2.0

### 🎯 Cherry-Pick Mode
- **Interactive File Selection**: Use `autocc select` to choose which source files to compile
- **Visual Interface**: Beautiful FTXUI-based interface with search and keyboard navigation
- **Persistent Selection**: Your file choices are saved and reused across builds

### 🧠 Smart Include Detection
- **Deep Analysis**: Scans include dependencies up to configurable depth
- **Missing Include Detection**: Identifies and reports missing header files
- **Automatic Include Path Discovery**: Finds and adds necessary include directories
- **Configurable Depth**: Set maximum include depth with `max_include_depth` setting

### 🎨 Enhanced Configuration
- **TOML Configuration**: Full TOML support with new features
- **Cherry-Pick Settings**: Enable/disable cherry-pick mode
- **Smart Include Settings**: Configure include detection behavior
- **Backward Compatibility**: All existing configurations continue to work

## 📦 Installation

### Prerequisites
- CMake 3.30+
- C++23 compatible compiler
- FTXUI library
- fmt library
- nlohmann/json
- toml11
- xxhash
- OpenSSL

### Build
```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## 🛠️ Usage

### Basic Usage
```bash
# Initialize project
autocc autoconfig

# Setup build environment
autocc setup

# Build project
autocc
```

### Cherry-Pick Mode
```bash
# Enable cherry-pick mode
autocc cherry-pick on

# Select files interactively
autocc select

# Build with selected files
autocc
```

### Smart Include Detection
```bash
# Enable smart include detection
autocc smart-includes on

# Build with enhanced include analysis
autocc
```

### Configuration
Edit `autocc.toml` to customize settings:
```toml
[project]
name = "my_project"
build_dir = ".build"

[compilers]
cxx = "clang++"
cc = "clang"
as = "nasm"

[flags]
cxxflags = "-std=c++23 -O2"
cflags = "-std=c11 -O2"
ldflags = ""

[features]
use_pch = true
cherry_pick_mode = false
smart_include_detection = true
max_include_depth = 10

[paths]
include_dirs = ["-Iinclude", "-I/usr/local/include"]
external_libs = ["-lssl", "-lcrypto"]
selected_files = ["src/main.cpp", "src/utils.cpp"]
```

## 🎮 Interactive File Selection

When using `autocc select`, you get a beautiful terminal interface:

- **Navigation**: Use arrow keys or `j`/`k` to move
- **Selection**: Press `Space` to toggle file selection
- **Search**: Type to filter files
- **Bulk Actions**: Press `a` to select all, `d` to deselect all
- **Confirm**: Press `Enter` or `Escape` to finish

## 🔧 Commands

| Command | Description |
|---------|-------------|
| `autocc` | Build project (default command) |
| `autocc autoconfig` | Interactive configuration setup |
| `autocc setup` | Prepare build environment |
| `autocc select` | Interactive file selection |
| `autocc cherry-pick on/off` | Enable/disable cherry-pick mode |
| `autocc smart-includes on/off` | Enable/disable smart include detection |
| `autocc clean` | Remove build artifacts |
| `autocc wipe` | Remove all autocc files |
| `autocc fetch` | Update library database |
| `autocc help` | Show help |
| `autocc version` | Show version |

## 🧪 Example Project

Create a simple test project:

```bash
mkdir test_project && cd test_project

# Create source files
echo '#include <iostream>
int main() { std::cout << "Hello from main.cpp" << std::endl; return 0; }' > main.cpp

echo '#include <string>
std::string get_message() { return "Hello from utils.cpp"; }' > utils.cpp

echo '#pragma once
#include <string>
std::string get_message();' > utils.h

# Initialize autocc
autocc autoconfig
autocc setup

# Try cherry-pick mode
autocc cherry-pick on
autocc select  # Choose which files to compile
autocc         # Build with selected files
```

## 🔍 Smart Include Detection Features

The smart include detection system provides:

- **Dependency Analysis**: Maps include relationships
- **Missing Header Detection**: Identifies unresolved includes
- **Include Path Optimization**: Automatically adds necessary `-I` flags
- **Depth Control**: Configurable recursion depth to prevent infinite loops
- **Performance Metrics**: Reports analysis statistics

## 🐛 Troubleshooting

### FTXUI Issues
- Ensure FTXUI is properly installed
- Check terminal compatibility (most modern terminals work)

### Include Detection Issues
- Use `autocc smart-includes off` to disable if causing problems
- Check `max_include_depth` setting if analysis is too slow
- Review missing include warnings in build output

### Cherry-Pick Issues
- Ensure project is set up with `autocc setup`
- Check file permissions for cache directory
- Use `autocc wipe` to reset if cache is corrupted

## 🤝 Contributing

Contributions are welcome! Please check the existing issues and pull requests before submitting new ones.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.