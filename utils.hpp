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
    std::string stderr_output;
};

// Executes a command and captures its exit code and stderr.
[[nodiscard]]
inline CommandResult execute(const std::string& cmd) {
    fs::path stderr_path = fs::temp_directory_path() / "autocc_stderr.log";
    std::string full_cmd = cmd + " 2> " + stderr_path.string();

    int exit_code = system(full_cmd.c_str());

    std::string stderr_output;
    if (fs::exists(stderr_path)) {
        std::ifstream stderr_file(stderr_path);
        std::stringstream buffer;
        buffer << stderr_file.rdbuf();
        stderr_output = buffer.str();
        fs::remove(stderr_path);
    }

    return {exit_code, stderr_output};
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