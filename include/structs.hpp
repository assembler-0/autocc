#pragma once
#include <string>
#include <vector>
#include <optional>
struct InstallOptions {
    std::string prefix = "/usr/local";
    std::string bin_dir = "bin";
    std::string lib_dir = "lib";
    std::string include_dir = "include";
    bool dry_run = false;
    bool force = false;
    bool create_symlinks = false;
    bool system_install = true; // false for user install (~/.local)
};
struct Target {
    std::string type = "Executable";
    std::string name;
    std::string main_file;
    std::vector<std::string> sources;
    std::string output_name;
    std::vector<std::string> exclude_patterns;
    std::optional<std::string> cflags = "-std=c11";
    std::optional<std::string> cxxflags = "-std=c++20";
    std::optional<std::string> ldflags;
    std::vector<std::string> external_libs; // Per-target external libraries
};

struct Config {
    std::string cc = "clang";
    std::string cxx = "clang++";
    std::string as = "nasm";
    std::string launcher;
    std::string ar = "ar";
    std::string shared = "clang++";
    std::string build_dir = ".autocc_build";
    bool use_pch = true;
    std::vector<std::string> include_dirs;
    std::vector<std::string> exclude_patterns;
    std::vector<Target> targets;
    std::string default_target;
};