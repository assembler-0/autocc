cmake_minimum_required(VERSION 3.30)
project(autocc LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)

# Build options
option(NUSE_TUI "Disable TUI interface (Not USE TUI)" OFF)  # OFF by default → TUI enabled unless turned ON
option(WALL "Enable all warnings" OFF)
option(ARM "Build for ARM architecture" OFF)

# Default flags
set(CMAKE_CXX_FLAGS "-O3 -march=native -mtune=native" CACHE STRING "C++ Compiler Flags")

# Warnings
if(WALL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -Wno-exit-time-destructors -Wno-global-constructors -Wno-missing-prototypes")
endif()

# ARM adjustments
if(ARM)
    string(REPLACE "-march=native -mtune=native" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    # Optionally add cross-compile flags if needed
endif()

# Create executable once
add_executable(autocc autocc.cc)

# Common include directories
target_include_directories(autocc PUBLIC include)

# Common compile definitions
target_compile_definitions(autocc PUBLIC
        -DLOG_ENABLE_FILE
        -DAGGRESSIVE # skips files more aggressively, actually saves ram
        #-DVERBOSE
)

# Only enable TUI if NUSE_TUI is NOT enabled
if(NOT NUSE_TUI)
    find_package(ftxui 6.1 REQUIRED)
    target_link_libraries(autocc ftxui::component ftxui::dom)
    target_compile_definitions(autocc PUBLIC -DUSE_TUI)
else()
    message(STATUS "NUSE_TUI=ON: Disabling TUI interface. ftxui will not be used.")
endif()

# Always link these
target_link_libraries(autocc fmt xxhash ssl crypto)

# Install
install(TARGETS autocc DESTINATION ${CMAKE_INSTALL_BINDIR})