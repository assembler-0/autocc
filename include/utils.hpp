#pragma once
#include <string>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <sys/stat.h>
#include <poll.h>
#include <fcntl.h>
#include <unordered_map>
#include <future>
#include <sys/mman.h>

namespace fs = std::filesystem;

// A struct to hold the result of a command execution
struct CommandResult {
    int exit_code{};
    std::string stdout_output;
    std::string stderr_output;
};

// Executes a command and captures its exit code, stdout, and stderr.
class ExecutionCache {
    struct CacheEntry {
        CommandResult result;
        std::chrono::steady_clock::time_point timestamp;
    };

    mutable std::shared_mutex cache_mutex;
    std::unordered_map<std::string, CacheEntry> cache;
    static constexpr auto CACHE_DURATION = std::chrono::minutes(5);

public:
    std::optional<CommandResult> get(const std::string& cmd) const {
        std::shared_lock lock(cache_mutex);
        if (const auto it = cache.find(cmd); it != cache.end()) {
            if (const auto age = std::chrono::steady_clock::now() - it->second.timestamp; age < CACHE_DURATION) {
                return it->second.result;
            }
        }
        return std::nullopt;
    }

    void put(const std::string& cmd, const CommandResult& result) {
        std::unique_lock lock(cache_mutex);
        cache[cmd] = {result, std::chrono::steady_clock::now()};

        // Periodic cleanup (every 100 entries)
        if (cache.size() % 100 == 0) {
            const auto now = std::chrono::steady_clock::now();
            for (auto it = cache.begin(); it != cache.end();) {
                if (now - it->second.timestamp > CACHE_DURATION) {
                    it = cache.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
};

inline ExecutionCache& getExecutionCache() {
    static ExecutionCache execution_cache;
    return execution_cache;
}

static bool isInIgnoredDirectory(const fs::path& path, const std::unordered_set<std::string>& ignored_dirs_set) {
    return std::ranges::any_of(path, [&ignored_dirs_set](const auto& component) {
        return ignored_dirs_set.contains(component.string());
    });
}

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


class Strings {
public:

    static bool matches_pattern(const std::string_view filename, const std::string_view pattern) {
        auto filename_it = filename.begin();
        auto pattern_it = pattern.begin();

        auto filename_star_it = filename.end(); // Pointers for backtracking
        auto pattern_star_it = pattern.end();

        while (filename_it != filename.end()) {
            if (pattern_it != pattern.end() && *pattern_it == '*') {
                // Wildcard found. Store current positions for backtracking.
                pattern_star_it = pattern_it;
                filename_star_it = filename_it;
                ++pattern_it; // Move pattern past '*'
            } else if (pattern_it != pattern.end() && (*pattern_it == '?' || *pattern_it == *filename_it)) {
                // Characters match (or '?' wildcard).
                ++filename_it;
                ++pattern_it;
            } else if (pattern_star_it != pattern.end()) {
                // Mismatch, but we have a '*' to backtrack to.
                // The '*' will match one more character of the filename.
                pattern_it = pattern_star_it + 1;
                ++filename_star_it;
                filename_it = filename_star_it;
            } else {
                // Mismatch with no '*' to backtrack to.
                return false;
            }
        }

        while (pattern_it != pattern.end() && *pattern_it == '*') {
            ++pattern_it;
        }

        return pattern_it == pattern.end();
    }

    static bool searchPatternInFile(const std::filesystem::path& filePath, const std::string& pattern) {
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
    static bool searchPatternInFile(const std::filesystem::path& filePath, const std::vector<std::string>& patterns) {
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

    static std::vector<std::string> split_string(const std::string& cmd) {
        if (cmd.empty()) return {};

        std::vector<std::string> args;
        args.reserve(8); // Most commands have < 8 args

        std::string current_arg;
        current_arg.reserve(256);

        bool in_quotes = false;
        bool in_single_quotes = false;
        bool escape_next = false;

        for (const char c : cmd) {
            if (escape_next) {
                current_arg += c;
                escape_next = false;
                continue;
            }

            if (c == '\\' && !in_single_quotes) {
                escape_next = true;
                continue;
            }

            if (c == '"' && !in_single_quotes) {
                in_quotes = !in_quotes;
                continue;
            }

            if (c == '\'' && !in_quotes) {
                in_single_quotes = !in_single_quotes;
                continue;
            }

            if (std::isspace(c) && !in_quotes && !in_single_quotes) {
                if (!current_arg.empty()) {
                    args.push_back(std::move(current_arg));
                    current_arg.clear();
                    current_arg.reserve(256);
                }
                continue;
            }

            current_arg += c;
        }

        if (!current_arg.empty()) {
            args.push_back(std::move(current_arg));
        }

        return args;
    }

};

class AsyncPipeReader {
public:
    static std::pair<std::string, std::string> readPipes(const int stdout_fd, const int stderr_fd) {
        // Set pipes to non-blocking mode
        fcntl(stdout_fd, F_SETFL, O_NONBLOCK);
        fcntl(stderr_fd, F_SETFL, O_NONBLOCK);

        PipeData stdout_data{stdout_fd, {}};
        PipeData stderr_data{stderr_fd, {}};

        // Pre-allocate buffers
        stdout_data.buffer.reserve(8192);
        stderr_data.buffer.reserve(4096);

        std::array<char, 8192> read_buffer{};

        // Use poll for efficient I/O multiplexing
        while (!stdout_data.finished || !stderr_data.finished) {
            std::array<pollfd, 2> fds = {{
                {stdout_fd, POLLIN, 0},
                {stderr_fd, POLLIN, 0}
            }};

            if (const int poll_result = poll(fds.data(), 2, 100); poll_result > 0) {
                if (fds[0].revents & POLLIN) {
                    if (!readFromPipe(stdout_data, read_buffer)) {
                        stdout_data.finished = true;
                    }
                }
                if (fds[1].revents & POLLIN) {
                    if (!readFromPipe(stderr_data, read_buffer)) {
                        stderr_data.finished = true;
                    }
                }

                // Check for pipe closure
                if (fds[0].revents & (POLLHUP | POLLERR)) stdout_data.finished = true;
                if (fds[1].revents & (POLLHUP | POLLERR)) stderr_data.finished = true;
            } else if (poll_result == 0) {
                // Timeout - check if pipes are still open
                if (!isPipeOpen(stdout_fd)) stdout_data.finished = true;
                if (!isPipeOpen(stderr_fd)) stderr_data.finished = true;
            }
        }

        return {std::move(stdout_data.buffer), std::move(stderr_data.buffer)};
    }

private:
    struct PipeData {
        int fd;
        std::string buffer;
        bool finished = false;
    };

    static bool readFromPipe(PipeData& pipe_data, std::array<char, 8192>& buffer) {
        const ssize_t bytes_read = read(pipe_data.fd, buffer.data(), buffer.size());
        if (bytes_read > 0) {
            pipe_data.buffer.append(buffer.data(), bytes_read);
            return true;
        }
        return bytes_read == 0; // EOF
    }

    static bool isPipeOpen(const int fd) {
        return fcntl(fd, F_GETFD) != -1;
    }
};

class Execution {
public:
    static bool isFileExecutable(const std::string& path) {
        char resolved_path[PATH_MAX];
        if (realpath(path.c_str(), resolved_path) == nullptr) {
            return false;
        }

        struct stat sb{};
        if (stat(resolved_path, &sb) != 0) {
            return false;
        }

        if (!S_ISREG(sb.st_mode)) {
            return false;
        }

        if (access(resolved_path, X_OK) == 0) {
            return true;
        }

        return false;
    }

    static bool isCommandExecutable(const std::string& command) {
        if (command.empty() || command.find('\0') != std::string::npos) {
            return false;
        }

        if (command.find("../") != std::string::npos) {
            return false;
        }

        if (command.find('/') != std::string::npos) {
            return isFileExecutable(command);
        }

        const char* path_env = std::getenv("PATH");
        if (!path_env) {
            return false; // No PATH variable set.
        }

        const std::string path_str(path_env);
        std::stringstream ss(path_str);
        std::string dir;

        while (std::getline(ss, dir, ':')) {
            if (dir.empty() || dir.find("..") != std::string::npos) {
                continue;
            }

            std::string full_path = dir + "/" + command;

            if (full_path.length() >= PATH_MAX) {
                continue;
            }

            if (isFileExecutable(full_path)) {
                return true;
            }
        }

        return false; // Command not found or not executable.
    }

    // Helper function to determine if command should be cached
    static bool shouldCache(const std::string& cmd) {
        // Cache pkg-config, compiler version checks, etc.
        return cmd.find("pkg-config") != std::string::npos ||
               cmd.find("--version") != std::string::npos ||
               cmd.find("which ") != std::string::npos;
    }

    // Pre-flight check to avoid unnecessary forks
    static bool canExecuteCommand(const std::vector<std::string>& args) {
        if (args.empty()) return false;
        return isCommandExecutable(args[0]);
    }

    // Optimized execute_vec with async I/O and error handling
    static CommandResult execute_vec(const std::vector<std::string>& args) {
        if (args.empty()) {
            return {127, "", "Error: empty command"};
        }

        // Pre-flight check
        if (!canExecuteCommand(args)) {
            return {127, "", "Error: command not found or not executable: " + args[0]};
        }

        int stdout_pipe[2], stderr_pipe[2];
        if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
            return {127, "", "Error: failed to create pipes"};
        }

        const pid_t pid = fork();
        if (pid == -1) {
            close(stdout_pipe[0]); close(stdout_pipe[1]);
            close(stderr_pipe[0]); close(stderr_pipe[1]);
            return {127, "", "Error: fork failed"};
        }

        if (pid == 0) {
            // Child process - optimized setup
            dup2(stdout_pipe[1], STDOUT_FILENO);
            dup2(stderr_pipe[1], STDERR_FILENO);
            close(stdout_pipe[0]); close(stdout_pipe[1]);
            close(stderr_pipe[0]); close(stderr_pipe[1]);

            // Prepare argv efficiently
            std::vector<char*> argv;
            argv.reserve(args.size() + 1);
            for (const auto& s : args) {
                argv.push_back(const_cast<char*>(s.c_str()));
            }
            argv.push_back(nullptr);

            execvp(argv[0], argv.data());
            _exit(127); // exec failed
        }

        // Parent process - async I/O
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        // Read from pipes asynchronously
        auto [stdout_result, stderr_result] = AsyncPipeReader::readPipes(stdout_pipe[0], stderr_pipe[0]);

        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        // Wait for child process
        int status = 0;
        waitpid(pid, &status, 0);

        return {WEXITSTATUS(status), std::move(stdout_result), std::move(stderr_result)};
    }

    // Cached execute function
    [[nodiscard]] static  CommandResult execute(const std::string& cmd) {
        // Check cache first for expensive operations
        if (auto cached = getExecutionCache().get(cmd)) {
            return *cached;
        }

        auto result = execute_vec(Strings::split_string(cmd));

        // Cache successful results of potentially expensive commands
        if (result.exit_code == 0 && shouldCache(cmd)) {
            getExecutionCache().put(cmd, result);
        }

        return result;
    }

    // Async execute for non-blocking operations
    static std::future<CommandResult> execute_async(const std::string& cmd) {
        return std::async(std::launch::async, [cmd] {
            return execute(cmd);
        });
    }
};

class MemoryMappedFile {
    void* data;
    size_t size;
public:
    explicit MemoryMappedFile(const fs::path& path) {
        const int fd = open(path.c_str(), O_RDONLY);
        struct stat sb;
        fstat(fd, &sb);
        size = sb.st_size;
        data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
    }

    std::string_view content() const {
        return {static_cast<char*>(data), size};
    }

    ~MemoryMappedFile() { munmap(data, size); }
};


class StringInterner {
    std::unordered_set<std::string> pool;
    mutable std::shared_mutex mutex;
public:
    std::string_view intern(std::string_view str) {
        std::shared_lock lock(mutex);
        if (const auto it = pool.find(std::string(str)); it != pool.end()) {
            return *it;
        }

        std::unique_lock ulock(mutex);
        return *pool.emplace(str).first;
    }
};

static StringInterner g_interner;