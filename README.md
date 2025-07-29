# 🚀 AUTOCC

> A fast, minimal low-level build system with intelligent target management

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.3-green.svg)](autocc.cc)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

---

## ✨ Features

- **🎯 Incremental Builds** - For lightning fast rebuilds
- **⚡ Parallel Compilation** - Multi-threaded compilation by default
- **🎪 Multi-Target Support** - Build multiple executables from a single project with target-specific configurations
- **🔧 Smart Auto-detection** - Automatically discovers local headers, system libraries, and build targets
- **📊 Extensible Knowledge Base** - Uses [JSON database](autocc.base.json) for library detection rules that update without recompilation
- **🧠 Pre-Compiled Headers** - Automatically generates PCH for common headers to speed up compilation
- **🎯 Target Discovery** - Intelligently discovers main() functions and suggests build targets
- **🤖 Automated setup** - with `autoconfig` setting up a project becomes easy

---

## 🏃‍♂️ Quick Start

### Prerequisites
```bash
cmake >= 3.30
C++20 standard support 
fmt library
xxhash library
OpenSSL library
git
```

### Installation
```bash
# Clone the repository
git clone https://github.com/assembler-0/autocc.git
cd autocc

# Build with cmake
mkdir build && cd build
cmake .. && make

# Or if you already have autocc:
autocc setup && autocc
```

---

## 📋 Sample Workflow

### 1. Initial Setup & Target Discovery
```bash
# Generate config with intelligent target discovery
autocc autoconfig   # or 'autocc ac'
# This will:
# - Scan your project for main() functions
# - Suggest build targets automatically
# - Detect headers and libraries
# - Create autocc.toml with smart defaults
```

### 2. Sync Configuration
```bash
autocc setup       # or 'autocc sync' or 'autocc sc'
# Converts autocc.toml to internal build cache
```

### 3. Build Your Project
```bash
# Build default target
autocc

# Build specific target
autocc my_target

# Build with target name
autocc test_suite
```

---

## ⚙️ Configuration (autocc.toml)

### Basic Configuration
```toml
[project]
build_dir = '.autocc_build'
default_target = 'main'      # Which target to build by default

[compilers]
as = 'nasm'                  # Your assembler
cc = 'clang'                 # Your C compiler
cxx = 'clang++'              # Your C++ compiler

[features]
use_pch = true               # Use Pre-Compiled Headers for faster builds

[flags]
cflags = '-march=native -std=c11 -O2 -pipe'
cxxflags = '-march=native -std=c++23 -O2 -pipe'
ldflags = '-lfmt -lssl -lcrypto -lxxhash'

[paths]
external_libs = ['-lm', '-lz', '-lpthread']    # System libraries
include_dirs = ['-I./include', '-I./third_party'] # Include directories
exclude_patterns = ['test_*.cpp', '*_benchmark.cpp'] # Files to exclude globally

# 🎯 Target Configuration (Multiple Executables)
[[targets]]
name = 'main'
main_file = 'src/main.cpp'
sources = ['src/main.cpp', 'src/utils.cpp', 'src/core.cpp']
output_name = 'my_app'
exclude_patterns = []        # Target-specific excludes

[[targets]]
name = 'test'
main_file = 'tests/test_main.cpp'
sources = ['tests/test_main.cpp', 'tests/unit_tests.cpp', 'src/utils.cpp']
output_name = 'test_runner'
exclude_patterns = ['*_integration.cpp']

[[targets]]
name = 'benchmark'
main_file = 'benchmark/bench_main.cpp'
sources = ['benchmark/bench_main.cpp', 'src/core.cpp']
output_name = 'benchmarks'
exclude_patterns = []
```

---

## ✅ Available Commands

```bash
➜  ~ autocc help
[INFO] AutoCC v0.1.3 - A smarter C++ build system

Usage: autocc [command|target_name]

Commands:
  <none>               Builds the default target using cached settings
  <target_name>        Builds the specified target (e.g., 'autocc test')
  ac/autoconfig        Creates 'autocc.toml' with intelligent target discovery
  setup/sync/sc        Converts 'autocc.toml' to internal build cache
  clean                Removes the build directory
  wipe                 Removes all autocc generated files (cache, build dir, db)
  fetch                Download/update the library detection database
  version              Show current version and build date
  help                 Shows this help message

```

---

## 🎯 Target System

AutoCC's target system allows you to build multiple executables from a single project:

### Automatic Target Discovery
- **Main Detection**: Scans for `main()` functions automatically
- **Pattern Recognition**: Identifies test files, benchmark files, etc.
- **Smart Suggestions**: Recommends source files for each target
- **Interactive Setup**: Guides you through target configuration

### Target Features
- **Isolated Builds**: Each target compiles only its specified sources
- **Custom Output Names**: Different executable names per target
- **Target-Specific Excludes**: Fine-grained control over what gets compiled
- **Default Target**: Set which target builds with just `autocc`

---

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test thoroughly
4. Ensure all targets build: `autocc test && autocc benchmark`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to your branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Project Structure
```
autocc/
├── zsh/       
│   └── _autocc              # auto suggestions for zsh (not working)
├── include/       
│   ├── httplib.h            # http for downloading
│   ├── json.hpp             # json for caching and db
│   ├── toml.hpp             # toml for config
│   ├── utils.hpp            # Utility functions
│   └── log.hpp              # Logging system
├── autocc.cc                # autocc main C++ file
├── autocc.base.json         # Library detection database
├── pvs.sh                   # Shell script for PVS-Studio static analyzer
├── autocc.toml              # Autocc configuration
├── CMakeLists.txt           # CMake configuration
└── ...                      # Misc. files
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/assembler-0/autocc/issues)
- **Discussions**: [GitHub Discussions](https://github.com/assembler-0/autocc/discussions)
- **Email**: diaviekone13@gmail.com

---

<div align="center">
  <strong>⭐ Star this project if you find it helpful!</strong>
  <br><br>
</div>