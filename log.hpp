// log.hpp
#pragma once

#include <fmt/core.h>
#include <fmt/color.h>
#include <mutex>

// A global mutex for ensuring threads do not interleave cout/cerr writes
extern std::mutex g_output_mutex;

namespace out {
    // Define our color scheme
    constexpr auto color_info = fmt::fg(fmt::color::steel_blue);
    constexpr auto color_warn = fmt::fg(fmt::color::golden_rod);
    constexpr auto color_error = fmt::fg(fmt::color::indian_red) | fmt::emphasis::bold;
    constexpr auto color_success = fmt::fg(fmt::color::medium_sea_green) | fmt::emphasis::bold;
    constexpr auto color_cmd = fmt::fg(fmt::color::slate_gray);
    constexpr auto color_prompt = fmt::fg(fmt::color::medium_turquoise);
    constexpr auto color_default = fmt::fg(fmt::color::light_slate_gray);

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