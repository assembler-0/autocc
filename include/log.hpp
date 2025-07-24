// log.hpp
#pragma once

#include <fmt/core.h>
#include <fmt/color.h>
#include <mutex>

// A global mutex for ensuring threads do not interleave cout/cerr writes
extern std::mutex g_output_mutex;

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
        fmt::print( color_info, "[INFO] ");
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, "\n");
    }

    template<typename... T>
    void warn(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_warn,"[WARN] ");
        fmt::print(stderr, fmt, std::forward<T>(args)...);
        fmt::print(stderr, "\n");
    }

    template<typename... T>
    void error(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_error, "[ERROR] ");
        fmt::print(stderr, fmt, std::forward<T>(args)...);
        fmt::print(stderr, "\n");
    }

    template<typename... T>
    void success(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_success, "[OK] ");
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, "\n");
    }

    template<typename... T>
    void command(fmt::format_string<T...> fmt, T&&... args) {
        std::lock_guard lock(g_output_mutex);
        fmt::print(color_cmd,"[CMD]  ");
        fmt::print(stdout, fmt, std::forward<T>(args)...);
        fmt::print(stdout, "\n");
    }

} // namespace log