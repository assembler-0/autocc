cmake_minimum_required(VERSION 3.30)
project(autocc LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-O3 -march=native -mtune=native")

# Find FTXUI
find_package(ftxui REQUIRED)

add_executable(autocc autocc.cc)
target_link_libraries(autocc 
    fmt 
    stdc++fs 
    xxhash 
    ssl 
    crypto
    ftxui::screen
    ftxui::dom
    ftxui::component
)
target_include_directories(autocc PUBLIC "include")
install(TARGETS autocc DESTINATION ${CMAKE_INSTALL_BINDIR})
