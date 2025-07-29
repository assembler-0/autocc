// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once
#include <cstdlib>
#include <string>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <unistd.h> // getpid
#include <fcntl.h>
#include <sys/wait.h>
#include "log.hpp"

namespace fs = std::filesystem;

struct CommandResult {
    int exit_code;
    std::string stdout_output;
    std::string stderr_output;
};

namespace fs = std::filesystem;

class TempFile {
public:
    explicit TempFile(const fs::path& base) {
        path_ = base.string() + "_" + std::to_string(getpid()) + "_" +
                std::to_string(rand() % 1000000) + ".tmp";
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    const fs::path& path() const { return path_; }

    // Prevent copying
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    TempFile(TempFile&& other) noexcept : path_(std::move(other.path_)) {
        other.path_ = "";
    }

private:
    fs::path path_;
};

[[nodiscard]] inline CommandResult execute(const std::string& cmd) {

    auto contains_shell_metachar = [](const std::string& s) {
        const char* unsafe[] = {";", "&", "|", "$(", "`", "<", ">", "<<", ">>", "\\n", "\\r", nullptr};
        for (const char** p = unsafe; *p; ++p) {
            if (s.find(*p) != std::string::npos) {
                return true;
            }
        }
        return false;
    };

    if (contains_shell_metachar(cmd)) {
        return { -1, "", "Error: Command contains potentially dangerous shell metacharacters." };
    }

    const auto trimmed_cmd = [](const std::string& s) -> std::string {
        const size_t start = s.find_first_not_of(" \t\n\r");
        const size_t end = s.find_last_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        return s.substr(start, end - start + 1);
    }(cmd);

    if (trimmed_cmd.empty()) {
        return { -1, "", "Error: Empty command." };
    }

    // 🔒 3. Use RAII temp files
    static std::once_flag seed_flag;
    std::call_once(seed_flag, [] { srand(static_cast<unsigned>(time(nullptr))); });

    const TempFile stdout_file(fs::temp_directory_path() / "autocc_stdout");
    const TempFile stderr_file(fs::temp_directory_path() / "autocc_stderr");

    auto shell_escape = [](const std::string& s) -> std::string {
        std::string result;
        result += "'";
        for (const char c : s) {
            if (c == '\'') {
                result += "'\\''";
            } else {
                result += c;
            }
        }
        result += "'";
        return result;
    };

    const std::string escaped_stdout = shell_escape(stdout_file.path().string());
    const std::string escaped_stderr = shell_escape(stderr_file.path().string());
    const std::string escaped_cmd = shell_escape(trimmed_cmd);

    // Build full command: <cmd> > stdout 2> stderr
    const std::string full_cmd = escaped_cmd + " > " + escaped_stdout + " 2> " + escaped_stderr;

    // 🔒 5. Use system() safely (still not perfect, but better)
    const int exit_code = system(full_cmd.c_str());

    // Handle system() failure
    if (exit_code == -1) {
        return { -1, "", std::string("Error: system() failed: ") + strerror(errno) };
    }

    // 🔒 6. Decode actual exit code (from waitpid format)
    int real_exit_code;
    if (WIFEXITED(exit_code)) {
        real_exit_code = WEXITSTATUS(exit_code);
    } else {
        real_exit_code = -1; // Signal or abnormal termination
    }

    // 🔒 7. Read output files with size limits and error handling
    auto read_file_safely = [](const fs::path& p, const size_t max_size = 10 * 1024 * 1024) -> std::string {
        std::error_code ec;
        if (!fs::exists(p, ec) || fs::is_directory(p, ec)) {
            return ""; // File doesn't exist or is dir
        }

        const uintmax_t file_size = fs::file_size(p, ec);
        if (ec || file_size > max_size) {
            return "(output too large or unreadable)";
        }

        std::ifstream file(p, std::ios::binary);
        if (!file.is_open()) {
            return "(failed to open)";
        }

        std::string content;
        content.resize(file_size);
        file.read(&content[0], static_cast<std::streamsize>(file_size));
        if (!file) {
            return "(read error)";
        }
        return content;
    };

    const std::string stdout_result = read_file_safely(stdout_file.path());
    const std::string stderr_result = read_file_safely(stderr_file.path());

    return { real_exit_code, stdout_result, stderr_result };
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

