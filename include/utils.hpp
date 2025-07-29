// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once

#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <thread>

#include "log.hpp"

namespace fs = std::filesystem;

// A struct to hold the result of a command execution
struct CommandResult {
    int exit_code;
    std::string stdout_output;
    std::string stderr_output;
};

// Executes a command and captures its exit code, stdout, and stderr.
[[nodiscard]] inline CommandResult execute(const std::string& cmd) {
    // Create temporary files for stdout and stderr
    fs::path stdout_path = fs::temp_directory_path() / ("autocc_stdout_" + std::to_string(getpid()) + ".log");
    fs::path stderr_path = fs::temp_directory_path() / ("autocc_stderr_" + std::to_string(getpid()) + ".log");

    // Construct the command to redirect stdout and stderr to files
    std::string full_cmd = fmt::format("{} > {} 2> {}", cmd, stdout_path.string(), stderr_path.string());

    const int exit_code = system(full_cmd.c_str());

    // Read the captured output
    std::string stdout_result, stderr_result;

    if (std::ifstream stdout_file(stdout_path); stdout_file.is_open()) {
        stdout_result.assign(std::istreambuf_iterator(stdout_file),
                           std::istreambuf_iterator<char>());
    }

    if (std::ifstream stderr_file(stderr_path); stderr_file.is_open()) {
        stderr_result.assign(std::istreambuf_iterator<char>(stderr_file),
                           std::istreambuf_iterator<char>());
    }

    // Clean up temp files
    fs::remove(stdout_path);
    fs::remove(stderr_path);

    return {exit_code, stdout_result, stderr_result};
}

inline bool matches_pattern(const std::string& filename, const std::string& pattern) {
    // Simple glob-like matching for now (supports * wildcard)
    if (pattern.find('*') == std::string::npos) {
        // No wildcard, exact match
        return filename == pattern;
    }

    // Handle patterns like "test_*.cpp" or "*_test.cpp"
    if (pattern.front() == '*') {
        const std::string suffix = pattern.substr(1);
        return filename.size() >= suffix.size() &&
               filename.substr(filename.size() - suffix.size()) == suffix;
    }

    if (pattern.back() == '*') {
        const std::string prefix = pattern.substr(0, pattern.size() - 1);
        return filename.size() >= prefix.size() &&
               filename.substr(0, prefix.size()) == prefix;
    }

    // For patterns with * in the middle, use basic approach
    const size_t star_pos = pattern.find('*');
    const std::string prefix = pattern.substr(0, star_pos);
    const std::string suffix = pattern.substr(star_pos + 1);

    return filename.size() >= prefix.size() + suffix.size() &&
           filename.substr(0, prefix.size()) == prefix &&
           filename.substr(filename.size() - suffix.size()) == suffix;
}

inline std::vector<fs::path> find_source_files(const fs::path& dir,
                                              const std::unordered_set<std::string>& ignored_dirs,
                                              const std::vector<std::string>& exclude_patterns = {}) {
    std::vector<fs::path> files;
    if (!fs::exists(dir)) return files;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
            // Check if any component in the path is in ignored dirs
            bool is_in_ignored_dir = false;
            for (const auto& part : entry.path()) {
                if (ignored_dirs.contains(part.string())) {
                    is_in_ignored_dir = true;
                    break;
                }
            }

            if (is_in_ignored_dir) {
                continue;
            }

            // Check if it's a source file
            if (entry.is_regular_file()) {
                if (const std::string ext = entry.path().extension().string();
                    ext == ".cpp" || ext == ".c" || ext == ".cc" || ext == ".s" ||
                    ext == ".S" || ext == ".asm" || ext == ".c++" || ext == ".cxx") {

                    // NEW: Check exclude patterns
                    const std::string filename = entry.path().filename().string();
                    bool should_exclude = false;

                    for (const auto& pattern : exclude_patterns) {
                        if (matches_pattern(filename, pattern)) {
                            should_exclude = true;
                            out::warn("Excluding file '{}' (matches pattern '{}')", filename, pattern);
                            break;
                        }
                    }

                    if (!should_exclude) {
                        files.push_back(entry.path());
                    }
                }
            }
        }
    } catch(const fs::filesystem_error& e) {
        out::warn("Filesystem error while scanning: {}", e.what());
    }
    return files;
}

