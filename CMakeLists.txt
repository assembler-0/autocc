cmake_minimum_required(VERSION 3.30)
project(autocc LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

# Build options
option(USE_TUI "Enable TUI interface using FTXUI" ON)
option(WALL "Enable all warnings" OFF)
option(ARM "Build for ARM architecture" OFF)

# Default flags for normal build
set(CMAKE_CXX_FLAGS "-O3 -march=native -mtune=native")

# Override flags based on build options
if(WALL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -Wno-exit-time-destructors -Wno-global-constructors -Wno-missing-prototypes")
endif()

if(ARM)
    # ARM architecture - remove aggressive optimization flags
    string(REPLACE "-march=native -mtune=native" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    # Optionally add ARM-specific flags
    # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a")
endif()

# Add executable once
add_executable(autocc autocc.cc)

# Include directories
target_include_directories(autocc PUBLIC "include")

# Common compile definitions
target_compile_definitions(autocc PUBLIC
        -DLOG_ENABLE_FILE
        # -DLOG_DISABLE
        # -DLOG_DISABLE_INFO
        # -DLOG_DISABLE_COLORS
        # -DLOG_DISABLE_TIMESTAMP
)

# Conditionally link FTXUI and define USE_TUI only if TUI is enabled
if(USE_TUI)
    find_package(ftxui 6.1 REQUIRED)
    target_link_libraries(autocc ftxui::component ftxui::dom)
    target_compile_definitions(autocc PUBLIC -DUSE_TUI)
else()
    # Optionally: define something like -DUSE_CLI or just do nothing
    message(STATUS "TUI disabled: -DUSE_TUI will not be defined")
endif()

# Always link these libraries
target_link_libraries(autocc fmt xxhash ssl crypto)

# Install
install(TARGETS autocc DESTINATION ${CMAKE_INSTALL_BINDIR})