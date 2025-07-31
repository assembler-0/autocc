cmake_minimum_required(VERSION 3.30)
project(autocc LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

# Default flags for normal build
set(CMAKE_CXX_FLAGS "-O3 -march=native -mtune=native")

# Override flags based on build options
if(WALL)
    set(CMAKE_CXX_FLAGS "-O3 -march=native -mtune=native -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -Wno-exit-time-destructors -Wno-global-constructors -Wno-missing-prototypes")
endif()

if(ARM)
    # ARM architecture - remove optimization flags that can cause issues
    set(CMAKE_CXX_FLAGS "")
endif()

find_package(ftxui 6.1 REQUIRED)
add_executable(autocc autocc.cc)
target_link_libraries(autocc fmt xxhash ssl crypto ftxui::component ftxui::dom)
target_include_directories(autocc PUBLIC "include")
target_compile_definitions(autocc PUBLIC
        # -DLOG_DISABLE
        # -DLOG_DISABLE_INFO
        # -DLOG_DISABLE_COLORS
        -DLOG_ENABLE_FILE
        # -DLOG_DISABLE_TIMESTAMP
)
install(TARGETS autocc DESTINATION ${CMAKE_INSTALL_BINDIR})