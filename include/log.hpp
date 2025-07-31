// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#pragma once

#include <fmt/core.h>
#include <fmt/color.h>
#include <mutex>
#include <chrono>
#include <ctime>
#include <sstream>

// ====== CONFIGURATION: Compile-time flags ======
// Define these in CMake or via compiler flags (-DLOG_DISABLE, etc.)

// Disable all logging (for release builds)
#ifndef LOG_DISABLE
// #define LOG_DISABLE
#endif

// Disable specific levels (useful for stripping verbose logs)
#ifndef LOG_DISABLE_INFO
// #define LOG_DISABLE_INFO
#endif
#ifndef LOG_DISABLE_WARN
// #define LOG_DISABLE_WARN
#endif
#ifndef LOG_DISABLE_ERROR
// #define LOG_DISABLE_ERROR
#endif

// Disable colors (for environments that don't support ANSI)
#ifndef LOG_DISABLE_COLORS
// #define LOG_DISABLE_COLORS
#endif

// Enable file logging
#ifndef LOG_ENABLE_FILE
// #define LOG_ENABLE_FILE
#endif

// Enable timestamp in logs
#ifndef LOG_DISABLE_TIMESTAMP
// #define LOG_DISABLE_TIMESTAMP
#endif

// Enable thread-safe output
#ifndef LOG_DISABLE_THREAD_SAFETY
    #define LOG_THREAD_SAFE
#endif

// Default output stream for info/success/command
#ifndef LOG_DEFAULT_STREAM
    #define LOG_DEFAULT_STREAM stdout
#endif

// Error stream for warnings and errors
#ifndef LOG_ERROR_STREAM
    #define LOG_ERROR_STREAM stderr
#endif

// ===============================================

// Forward declare file sink if enabled
#ifdef LOG_ENABLE_FILE
#include <fstream>
extern std::ofstream g_log_file;
void init_log_file(const std::string& filename);
void close_log_file();
#endif

// Global mutex for thread safety
#ifdef LOG_THREAD_SAFE
    extern std::mutex g_output_mutex;
    #define LOG_LOCK() std::lock_guard<std::mutex> lock(g_output_mutex)
#else
    #define LOG_LOCK()
#endif

// Helper to format timestamp: YYYY-MM-DD HH:MM:SS.mmm
inline std::string now_str() {
#ifdef LOG_DISABLE_TIMESTAMP
    return "YYYY-MM-DD HH:MM:SS.000"; // placeholder
#else
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    const auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
#endif
}

// Color definitions (conditionally disabled)
#ifdef LOG_DISABLE_COLORS
    #define COLOR_INFO
    #define COLOR_WARN
    #define COLOR_ERROR
    #define COLOR_SUCCESS
    #define COLOR_CMD
    #define COLOR_PROMPT
    #define COLOR_DEFAULT
#else
    #define COLOR_INFO fmt::fg(fmt::color::dodger_blue) | fmt::emphasis::bold
    #define COLOR_WARN fmt::fg(fmt::color::orange) | fmt::emphasis::bold
    #define COLOR_ERROR fmt::fg(fmt::color::crimson) | fmt::emphasis::bold
    #define COLOR_SUCCESS fmt::fg(fmt::color::lime_green) | fmt::emphasis::bold
    #define COLOR_CMD fmt::fg(fmt::color::cyan)
    #define COLOR_PROMPT fmt::fg(fmt::color::dodger_blue) | fmt::emphasis::bold
    #define COLOR_DEFAULT fmt::fg(fmt::color::white)
#endif

namespace out {

    // Generic log function with stream and color
    template<typename... T>
    void log_impl(const fmt::text_style style, FILE* stream, const char* level, fmt::format_string<T...> fmt, T&&... args) {
        LOG_LOCK();
        std::string time_str = now_str();

        // Format the message
        auto msg = fmt::format(fmt, std::forward<T>(args)...);

        // Output with or without color
#ifdef LOG_DISABLE_COLORS
        fmt::print(stream, "[{}] [{}] {}", time_str, level, msg);
#else
        fmt::print(stream, style, "[{}] [{}] ", time_str, level);
        fmt::print(stream, "{}", msg); // Avoid color reset interference
#endif
        fmt::print(stream, "\n");

#ifdef LOG_ENABLE_FILE
        // Also write to file (without color codes)
        g_log_file << "[" << time_str << "] [" << level << "] " << msg << "\n";
        g_log_file.flush();
#endif
    }

    // Individual log functions (conditionally compiled)

#ifndef LOG_DISABLE_INFO
    template<typename... T>
    void info(fmt::format_string<T...> fmt, T&&... args) {
        log_impl(COLOR_INFO, LOG_DEFAULT_STREAM, "[INFO]", fmt, std::forward<T>(args)...);
    }
#endif

    template<typename... T>
    void warn(fmt::format_string<T...> fmt, T&&... args) {
#ifndef LOG_DISABLE_WARN
        log_impl(COLOR_WARN, LOG_ERROR_STREAM, "[WARNING]", fmt, std::forward<T>(args)...);
#endif
    }

    template<typename... T>
    void error(fmt::format_string<T...> fmt, T&&... args) {
#ifndef LOG_DISABLE_ERROR
        log_impl(COLOR_ERROR, LOG_ERROR_STREAM, "[ERROR]", fmt, std::forward<T>(args)...);
#endif
    }

    template<typename... T>
    void success(fmt::format_string<T...> fmt, T&&... args) {
#ifndef LOG_DISABLE_INFO
        log_impl(COLOR_SUCCESS, LOG_DEFAULT_STREAM, "[OK]", fmt, std::forward<T>(args)...);
#endif
    }

    template<typename... T>
    void command(fmt::format_string<T...> fmt, T&&... args) {
#ifndef LOG_DISABLE_INFO
        log_impl(COLOR_CMD, LOG_DEFAULT_STREAM, "[CMD]", fmt, std::forward<T>(args)...);
#endif
    }

    // Optional prompt utility (e.g., for interactive tools)
    template<typename... T>
    void prompt(fmt::format_string<T...> fmt, T&&... args) {
        LOG_LOCK();
#ifdef LOG_DISABLE_COLORS
        fmt::print(stdout, "[PROMPT] ");
#else
        fmt::print(COLOR_PROMPT, "[PROMPT] ");
#endif
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, " ");
        fflush(stdout);
    }

} // namespace out