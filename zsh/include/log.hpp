// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
// log.hpp
#pragma once

#include <fmt/core.h>
#include <fmt/color.h>
#include <mutex>
#include <chrono>
#include <ctime>

// A global mutex for ensuring threads do not interleave cout/cerr writes
extern std::mutex g_output_mutex;


// Helper to format timestamp: YYYY-MM-DD HH:MM:SS.mmm
inline std::string now_str() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

namespace out {

    constexpr auto color_info = fmt::fg(fmt::color::dodger_blue) | fmt::emphasis::bold;
    constexpr auto color_warn = fmt::fg(fmt::color::orange) | fmt::emphasis::bold;
    constexpr auto color_error = fmt::fg(fmt::color::crimson) | fmt::emphasis::bold;
    constexpr auto color_success = fmt::fg(fmt::color::lime_green) | fmt::emphasis::bold;
    constexpr auto color_cmd = fmt::fg(fmt::color::cyan);
    constexpr auto color_prompt = fmt::fg(fmt::color::dodger_blue) | fmt::emphasis::bold;
    constexpr auto color_default = fmt::fg(fmt::color::white);

    template<typename... T>
    void info(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print( color_info, "[{}] [INFO] ", now_str());
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, "\n");
    }

    template<typename... T>
    void warn(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_warn,"[{}] [WARNING] ", now_str());
        fmt::print(stderr, fmt, std::forward<T>(args)...);
        fmt::print(stderr, "\n");
    }

    template<typename... T>
    void error(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_error, "[{}] [ERROR] ", now_str());
        fmt::print(stderr, fmt, std::forward<T>(args)...);
        fmt::print(stderr, "\n");
    }

    template<typename... T>
    void success(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_success, "[{}] [OK] ", now_str());
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, "\n");
    }

    template<typename... T>
    void command(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_cmd,"[{}] [CMD] ", now_str());
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, "\n");
    }

} // namespace out