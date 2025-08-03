// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once

#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <sys/stat.h>

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

    const pid_t pid = fork();
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

inline bool isCommandExecutable(const std::string& command) {
    // 1. Input validation: reject empty or dangerous patterns
    if (command.empty()) {
        return false;
    }

    // Reject commands with null bytes or control characters
    if (command.find('\0') != std::string::npos ||
        std::ranges::any_of(command, [](const char c) { return c < 32 || c > 126; })) {
        return false;
    }

    // Prevent obvious traversal in direct paths (not foolproof, but adds safety)
    if (std::regex traversal_pattern(R"(\.\./|\.\.$|^/[^/]*\.\./)"); std::regex_search(command, traversal_pattern)) {
        // Allow if it's a relative executable like "./script", but not "../"
        if (command.find("../") != std::string::npos) {
            return false;
        }
        if (command == ".." || command == "../") {
            return false;
        }
    }

    std::vector<std::string> search_paths;

    // 2. If command contains '/' -> treat as path (absolute or relative)
    if (command.find('/') != std::string::npos) {
        search_paths.emplace_back(""); // Will test the command directly
    } else {
        // Else, search in PATH
        const char* path_env = std::getenv("PATH");
        if (!path_env) return false;

        std::string path_str(path_env);
        std::regex token_regex("[^:]+");
        auto begin = std::sregex_iterator(path_str.begin(), path_str.end(), token_regex);
        auto end = std::sregex_iterator();

        for (std::sregex_iterator i = begin; i != end; ++i) {
            std::string dir = i->str();

            // Sanitize PATH entry (prevent weird stuff)
            if (dir.empty() || dir.length() >= PATH_MAX) {
                continue;
            }

            // Prevent traversal in PATH entries
            if (dir.find("..") != std::string::npos) {
                continue;
            }

            search_paths.push_back(dir);
        }
    }

    // 3. Try each possible path
    for (const auto& dir : search_paths) {
        std::string full_path = dir.empty() ? command : dir + "/" += command;

        // Skip if path is too long
        if (full_path.length() >= PATH_MAX) {
            continue;
        }

        // 4. Resolve symbolic links and get canonical path (avoid loops)
        char resolved_path[PATH_MAX];
        if (realpath(full_path.c_str(), resolved_path) == nullptr) {
            continue; // Doesn't exist, broken symlink, or access denied
        }

        // 5. Stat the file to ensure it's a regular file or symlink to one
        struct stat sb{};
        if (stat(resolved_path, &sb) != 0) {
            continue;
        }

        if (!S_ISREG(sb.st_mode)) {
            continue; // Not a regular file (e.g., directory, device)
        }

        // 6. Check execute permission for user
        if (access(resolved_path, X_OK) == 0) {
            return true;
        }
    }

    return false;
}

// Helper function to avoid code duplication
namespace search {
    inline void validateFileAndPatterns(const std::filesystem::path& filePath, const std::vector<std::string>& patterns) {
        // Validate patterns
        if (patterns.empty()) {
            throw std::invalid_argument("Patterns vector cannot be empty");
        }

        for (const auto& pattern : patterns) {
            if (pattern.empty()) {
                throw std::invalid_argument("Pattern cannot be empty");
            }
        }

        if (filePath.empty()) {
            throw std::invalid_argument("File path cannot be empty");
        }

        std::error_code ec;
        if (!std::filesystem::exists(filePath, ec)) {
            throw std::runtime_error("File does not exist: " + filePath.string());
        }

        if (ec) {
            throw std::system_error(ec, "Error checking file existence");
        }

        if (!std::filesystem::is_regular_file(filePath, ec)) {
            throw std::runtime_error("Path is not a regular file: " + filePath.string());
        }

        if (ec) {
            throw std::system_error(ec, "Error checking file type");
        }
    }
}

// Original function (updated to use helper)
inline bool searchPatternInFile(const std::filesystem::path& filePath, const std::string& pattern) {
    const std::vector patterns = {pattern};
    search::validateFileAndPatterns(filePath, patterns);

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filePath.string());
    }

    try {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find(pattern) != std::string::npos) {
                return true;
            }
        }

        if (file.bad()) {
            throw std::runtime_error("Error occurred while reading file: " + filePath.string());
        }
    }
    catch (const std::ios_base::failure& e) {
        throw std::runtime_error("I/O error while reading file: " + std::string(e.what()));
    }

    return false;
}

// New overloaded function
inline bool searchPatternInFile(const std::filesystem::path& filePath, const std::vector<std::string>& patterns) {
    search::validateFileAndPatterns(filePath, patterns);

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filePath.string());
    }

    try {
        std::string line;
        while (std::getline(file, line)) {
            for (const auto& pattern : patterns) {
                if (line.find(pattern) != std::string::npos) {
                    return true;  // Return true if ANY pattern is found
                }
            }
        }

        if (file.bad()) {
            throw std::runtime_error("Error occurred while reading file: " + filePath.string());
        }
    }
    catch (const std::ios_base::failure& e) {
        throw std::runtime_error("I/O error while reading file: " + std::string(e.what()));
    }

    return false;
}
