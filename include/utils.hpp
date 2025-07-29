// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once

#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <cstring>
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
inline CommandResult execute_vec(const std::vector<std::string>& args) {
    int stdout_pipe[2], stderr_pipe[2];
    pipe(stdout_pipe);
    pipe(stderr_pipe);

    pid_t pid = fork();
    if (pid == 0) {
        // Child
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);

        std::vector<char*> argv;
        for (const auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127); // exec failed
    }

    // Parent
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    std::string stdout_result, stderr_result;
    char buf[4096];
    ssize_t n;
    while ((n = read(stdout_pipe[0], buf, sizeof(buf))) > 0)
        stdout_result.append(buf, n);
    while ((n = read(stderr_pipe[0], buf, sizeof(buf))) > 0)
        stderr_result.append(buf, n);
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return {WEXITSTATUS(status), stdout_result, stderr_result};
}

// Simple whitespace split (does not handle quotes/escapes)
inline std::vector<std::string> split_command(const std::string& cmd) {
    std::istringstream iss(cmd);
    std::vector<std::string> args;
    std::string arg;
    while (iss >> arg) args.push_back(arg);
    return args;
}

// Replacement for old execute()
[[nodiscard]] inline CommandResult execute(const std::string& cmd) {
    return execute_vec(split_command(cmd));
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

