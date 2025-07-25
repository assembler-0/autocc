// utils.hpp
#pragma once

#include <string>
#include <cstdio>
#include <memory>
#include <array>
#include <stdexcept>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <fstream>
#include <sstream>

#include "log.hpp"

namespace fs = std::filesystem;

// A struct to hold the result of a command execution
struct CommandResult {
    int exit_code;
    std::string stdout_output;
    std::string stderr_output;
};

// Executes a command and captures its exit code, stdout, and stderr.
[[nodiscard]]
inline CommandResult execute(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string stdout_result;
    std::string stderr_result;

    // Create temporary files for stdout and stderr
    fs::path stdout_path = fs::temp_directory_path() / "autocc_stdout.log";
    fs::path stderr_path = fs::temp_directory_path() / "autocc_stderr.log";

    // Construct the command to redirect stdout and stderr to files
    std::string full_cmd = cmd + " > " + stdout_path.string() + " 2> " + stderr_path.string();

    int exit_code = system(full_cmd.c_str());

    // Read stdout from file
    if (fs::exists(stdout_path)) {
        std::ifstream stdout_file(stdout_path);
        std::stringstream ss_stdout;
        ss_stdout << stdout_file.rdbuf();
        stdout_result = ss_stdout.str();
        fs::remove(stdout_path);
    }

    // Read stderr from file
    if (fs::exists(stderr_path)) {
        std::ifstream stderr_file(stderr_path);
        std::stringstream ss_stderr;
        ss_stderr << stderr_file.rdbuf();
        stderr_result = ss_stderr.str();
        fs::remove(stderr_path);
    }

    return {exit_code, stdout_result, stderr_result};
}


// A more robust recursive file finder that avoids specified directories correctly.
inline std::vector<fs::path> find_source_files(const fs::path& dir, const std::unordered_set<std::string>& ignored_dirs) {
    std::vector<fs::path> files;
    if (!fs::exists(dir)) return files;

    // in utils.hpp, inside find_source_files function
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
            // **THE MORE COMPATIBLE FALLBACK**
            // Check if any component of the full path is an ignored directory.
            bool is_in_ignored_dir = false;
            for (const auto& part : entry.path()) {
                if (ignored_dirs.contains(part.string())) {
                    is_in_ignored_dir = true;
                    break;
                }
            }
            if (is_in_ignored_dir) {
                continue; // Skip this entry entirely.
            }

            if (entry.is_regular_file()) {
                if (const std::string ext = entry.path().extension().string();
                    ext == ".cpp" || ext == ".c" || ext == ".cc" || ext == ".s" ||
                    ext == ".S" || ext == ".asm" || ext == ".c++" || ext == ".cxx") {
                    files.push_back(entry.path());
                }
            }
        }
    } catch(const fs::filesystem_error& e) {
        out::warn("Filesystem error while scanning: {}", e.what());
    }
    return files;
}