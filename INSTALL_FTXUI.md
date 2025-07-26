# Installing FTXUI for AutoCC

AutoCC v0.2.0 requires the FTXUI library for its interactive file selection feature. Here's how to install it on different systems.

## Ubuntu/Debian

```bash
# Install dependencies
sudo apt update
sudo apt install cmake build-essential libssl-dev

# Install FTXUI
git clone https://github.com/ArthurSonzogni/ftxui.git
cd ftxui
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

## Arch Linux

```bash
# Install from AUR
yay -S ftxui

# Or install manually
sudo pacman -S cmake base-devel openssl
git clone https://github.com/ArthurSonzogni/ftxui.git
cd ftxui
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## macOS

```bash
# Using Homebrew
brew install ftxui

# Or install manually
brew install cmake openssl
git clone https://github.com/ArthurSonzogni/ftxui.git
cd ftxui
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

## Fedora/RHEL/CentOS

```bash
# Install dependencies
sudo dnf install cmake gcc-c++ openssl-devel

# Install FTXUI
git clone https://github.com/ArthurSonzogni/ftxui.git
cd ftxui
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

## Building AutoCC with FTXUI

After installing FTXUI, build AutoCC:

```bash
# Clone AutoCC repository
git clone <your-repo-url>
cd autocc

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## Troubleshooting

### FTXUI not found
If CMake can't find FTXUI, you may need to set the CMAKE_PREFIX_PATH:

```bash
cmake -DCMAKE_PREFIX_PATH=/usr/local/lib/cmake/ftxui ..
```

### Library not found at runtime
If you get library errors when running autocc, you may need to update the library path:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### Terminal compatibility
FTXUI works best with modern terminals that support:
- True color (24-bit colors)
- Unicode characters
- Mouse events (optional)

Recommended terminals:
- iTerm2 (macOS)
- Alacritty
- Kitty
- GNOME Terminal
- Konsole
- Windows Terminal (Windows)

## Alternative: Build without FTXUI

If you can't install FTXUI, you can still use AutoCC without the interactive file selection:

```bash
# Edit CMakeLists.txt to comment out FTXUI
# find_package(ftxui REQUIRED)
# target_link_libraries(autocc ftxui::screen ftxui::dom ftxui::component)

# Build without FTXUI
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

Note: Without FTXUI, the `autocc select` command will not work, but all other features will function normally.