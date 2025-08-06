# 🚀 AUTOCC

> A fast, minimal low-level build system with intelligent target management

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.6-green.svg)](autocc.cc)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

---
## 🎊 What's new? (v0.1.6-2)
- **Optimization** - Introduce parallel processing to many functions.
- **Enhanced execution pipeline** - Safer and faster execution.
- **Added target types** - Extend capability for future upgrades.
- **Refactored codebase** - A Cleaner, more efficient codebase.
- **Added new fields in user configuration** - Adapting new changes.
- **Install targets safer** - Smarter installation.
## ✨ Features

- **🎯 Incremental Builds** - For lightning fast rebuilds
- **⚡ Parallel Compilation** - Multi-threaded compilation by default
- **🎪 Multi-Target Support** - Build multiple targets from a single project with target-specific configurations
- **✅ Multi-Target Type** - Build multiple executable/dynamic libraries/static libraries from a single file;
- **🔧 Smart Auto-detection** - Automatically discovers local headers, system libraries, and build targets
- **📊 Extensible Knowledge Base** - Uses [JSON database](autocc.base.json) for library detection rules that update without recompilation
- **🧠 Pre-Compiled Headers** - Automatically generates PCH for common headers to speed up compilation
- **🎯 Target Discovery** - Intelligently discovers main() functions and suggests build targets
- **🤖 Automated setup** - with `autoconfig` setting up a project becomes easy
- **✅ TUI-Based selector** - using `edit` to edit configuration files without any external edtior

---

## 🏃‍♂️ Quick Start

### Prerequisites
```bash
cmake >= 3.30
C++23 standard support 
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
cmake .. && make # -DWALL=ON for all possible warnings -DARM=ON for no optimization -DNUSE_TUI=ON for disabling ftxui

# Or if you already have autocc:
autocc setup && autocc
```
### ZSH autocompletion
```bash
# to install _autocc completetion for zsh, in the project ROOT, run:
chmod + x ./zsh/install.sh && ./zsh/install.sh 
# to uninstall
chmod + x ./zsh/install.sh && ./zsh/uninstall.sh 
```
### target_compile_definitions() 
```cmake
target_compile_definitions(autocc PUBLIC
        # -DLOG_DISABLE -- disable logging
        # -DLOG_DISABLE_INFO -- disable info
        # -DLOG_DISABLE_COLORS -- disable colors
        -DLOG_ENABLE_FILE # -- enable file logging
        # -DLOG_DISABLE_TIMESTAMP -- disable timestamps
        # -DVERBOSE -- enable verbose logging
)
```
---

## 📋 Sample Workflow

### 1. Initial Setup & Target Discovery
```bash
# Generate config with intelligent target discovery
autocc autoconfig   # or 'autocc ac', use --default to skip all and use builtin configuration
# This will:
# - Scan your project for main() functions
# - Suggest build targets automatically
# - Detect headers and libraries
# - Create autocc.toml with smart defaults
autocc edit # or 'autocc select'
# this edits sources to build
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

### 4. Install your project
```bash
# install default target (may need root privileges)
autocc install # for default target
# install specific target 
autocc install my_target
# install all targets 
autocc install <target> --prefix=<path to install> # to install to a specific path
```

---

## ⚙️ Configuration (autocc.toml)

### Basic Configuration
```toml
# AUTOCC 0.1.6
# CONFIGURATION FILE 'autocc.toml' IS WRITTEN BY AUTOCC 0.1.6, MAKE SURE YOU HAVE AN APPROPRIATE AUTOCC BUILD.
# COPYRIGHT (C) assembler-0 2025
[compilers]
ar = 'ar'  # your archiver
as = 'nasm'  # your assembler
cc = 'clang'  # your C compiler
cxx = 'clang++' # your C++ compiler
launcher = 'ccache' # your launcer
sl = 'clang++'  # your dynamic linker

[features]
use_pch = true  # use precompiled header

[paths]
exclude_patterns = []  # global exclude pattern
include_dirs = [ 'include', '.', 'include/imgui', 'include/imgui/backends' ] # global include directories

[project]
build_dir = '.autocc_build'  # project build directory
default_target = 'sift' # default target

[[targets]]
cflags = '-std=c11' # cflags
cxxflags = '-std=c++23' # c++ flags
exclude_patterns = [] # target exclude patten
external_libs = [ '-ldl', '-lz', '-llzma', '-lpthread', '-lm', '-lglfw', '-lGL' ] # external library
ldflags = '' # Linker flags
main_file = './src/main.cpp' # main file
name = 'main' # target name
output_name = 'main' # target output name
sources = [
    './asm/3np1.asm',
    './asm/aesDEC.asm',
    './asm/aesENC.asm',
    './asm/avx.asm',
    './asm/branch.asm',
    # snip...
    './src/lzma.module.cpp',
    './src/main.cpp',
    './src/systemMonitor.manage.cpp'
]
type = 'SLibrary' # Or 'Executable' 'SLibrary' 'DLlibrary'
```

---

## ✅ Available Commands

```bash
AutoCC 0.1.6-2 compiled on Aug  5 2025 at 13:14:43

Usage: autocc [command] (target_name)

Commands:
  <none> or <target>   Builds the default target, or a specified target.
  ac/autoconfig        Creates 'autocc.toml' via an interactive prompt.
  setup/sync/sc        Converts 'autocc.toml' to the internal build cache.
  edit/select          Open a TUI to visually select source files for targets (could be disabled).
  clean                Removes the build directory.
  wipe                 Removes all autocc generated files (cache, build dir, db).
  fetch                Download/update the library detection database.
  version              Show current version and build date.
  help                 Shows this help message.
  install <target>     Install specified target to system binary dir.
Flags:
  --default            For 'autocc autoconfig', use default settings.
  --prefix             For 'autocc install', install to a specific path.
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
│   ├── install.sh           # Install script for _autocc
│   ├── uninstall.sh         # Uninstall script for _autocc
│   └── _autocc              # auto suggestions for zsh
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

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

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