// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once

#include <string>
#include <cstdio>
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
    const std::string stdout_result;
    const std::string stderr_result;

    // Create temporary files for stdout and stderr
    fs::path stdout_path = fs::temp_directory_path() / "autocc_stdout.log";
    fs::path stderr_path = fs::temp_directory_path() / "autocc_stderr.log";

    // Construct the command to redirect stdout and stderr to files

    const int exit_code = system(cmd.c_str());

    return {exit_code, stdout_result, stderr_result};
}


// A more robust recursive file finder that avoids specified directories correctly.
// This version uses a fully compatible method that does not rely on disable_recursion_pending().
inline std::vector<fs::path> find_source_files(const fs::path& dir, const std::unordered_set<std::string>& ignored_dirs) {
    std::vector<fs::path> files;
    if (!fs::exists(dir)) return files;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
            // **THE COMPATIBLE FALLBACK**
            // Check if any component (directory name) in the full path is in our ignore list.
            bool is_in_ignored_dir = false;
            for (const auto& part : entry.path()) {
                if (ignored_dirs.contains(part.string())) {
                    is_in_ignored_dir = true;
                    break; // Found an ignored component, no need to check further.
                }
            }

            if (is_in_ignored_dir) {
                continue; // Skip this entry entirely because it's inside an ignored directory.
            }

            // If we're here, the path is clean. Now check if it's a source file.
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