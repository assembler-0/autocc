// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <regex>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
#include <sstream>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/chrono.h>
#include <xxhash.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "toml.hpp"
#include "log.hpp"
#include "utils.hpp"
#include "json.hpp"
#include "httplib.h"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#define DATE __DATE__
#define TIME __TIME__
#define VERSION "v0.1.4"

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace ftxui;
using DependencyMap = std::unordered_map<fs::path, std::unordered_set<fs::path>>;

// log.hpp
std::ofstream g_log_file;
std::mutex g_output_mutex;

// --- Constants ---
static constexpr auto CACHE_DIR_NAME = ".autocc_cache";
static constexpr auto CONFIG_FILE_NAME = "config.cache";
static constexpr auto DEP_CACHE_FILE_NAME = "deps.cache";
static constexpr auto PCH_HEADER_NAME = "autocc_pch.hpp";
static constexpr auto DB_FILE_NAME = "autocc.base.json";
static constexpr auto AUTOINSTALL_SCRIPT_PATH = "scripts/autoinstall";
static constexpr auto DEFAULT_INSTALL_PATH = "/usr/local/bin";
static constexpr auto BASE_DB_URL = "https://raw.githubusercontent.com/assembler-0/autocc/refs/heads/main/autocc.base.json";

template <>
struct fmt::formatter<fs::path> : formatter<std::string_view> {
    auto format(const fs::path& p, format_context& ctx) const{
        return formatter<std::string_view>::format(p.string(), ctx);
    }
};

struct Target {
    std::string name;
    std::string main_file; // not compiled, just for misc. uses
    std::vector<std::string> sources;
    std::string output_name;
    std::vector<std::string> exclude_patterns;
};

struct Config {
    std::string cc = "clang";
    std::string cxx = "clang++";
    std::string as = "nasm";

    std::string cxxflags = "-march=native -std=c++23 -O2 -pipe";
    std::string cflags = "-march=native -std=c11 -O2 -pipe";
    std::string ldflags;
    std::string build_dir = ".autocc_build";
    bool use_pch = true;
    std::vector<std::string> include_dirs;
    std::vector<std::string> external_libs;
    std::vector<std::string> exclude_patterns;
    // Target system
    std::vector<Target> targets;
    std::string default_target;
};

class TargetDiscovery {
public:
    struct DiscoveredTarget {

        std::string suggested_name;
        fs::path main_file;
        std::vector<fs::path> suggested_sources;
        std::string reason; // Why we think this is a target
    };

    static std::vector<DiscoveredTarget> discover_targets(const std::vector<fs::path>& all_source_files) {
        std::vector<DiscoveredTarget> discovered;
        std::unordered_set<std::string> main_files_seen;
        std::unordered_set<std::string> dirs_with_main;

        // Helper: prefer src/ and root, deprioritize include/examples/test dirs
        auto is_preferred_dir = [](const fs::path& p) {
            const auto dir = p.parent_path().string();
            if (dir == "." || dir == "./" || dir == "src" || dir.ends_with("/src")) return true;
            if (dir.find("include") != std::string::npos) return false;
            if (dir.find("example") != std::string::npos) return false;
            if (dir.find("test") != std::string::npos) return false;
            return true;
        };

        // Collect all main candidates
        std::vector<fs::path> preferred_mains, fallback_mains;
        for (const auto& file : all_source_files) {
            if (std::string filename = file.filename().string(); filename == "main.cpp" || filename == "main.c" || filename == "main.cc") {
                if (is_preferred_dir(file)) {
                    preferred_mains.push_back(file);
                } else {
                    fallback_mains.push_back(file);
                }
            }
        }

        // Strategy 1: Look for files with the "main" function, prefer preferred_mains
        auto try_main_candidates = [&](const std::vector<fs::path>& candidates) {
            for (const auto& file : candidates) {
                std::string dir = file.parent_path().string();
                if (dirs_with_main.contains(dir)) continue;
                if (has_main_function(file)) {
                    std::string target_name = get_target_name_from_file(file);
                    if (main_files_seen.contains(target_name)) continue;
                    DiscoveredTarget target;
                    target.main_file = file;
                    target.suggested_name = target_name;
                    target.suggested_sources = suggest_sources_for_target(file, all_source_files);
                    target.reason = "contains main() function";
                    discovered.push_back(target);
                    main_files_seen.insert(target_name);
                    dirs_with_main.insert(dir);
                    // Only add the first preferred main
                    break;
                }
            }
        };

        // Try preferred mains first, then fallback
        try_main_candidates(preferred_mains);
        if (discovered.empty()) try_main_candidates(fallback_mains);

        // Strategy 2: Look for test files if no main found
        if (discovered.empty()) {
            for (const auto& file : all_source_files) {
                std::string filename = file.filename().string();
                if (std::string dir = file.parent_path().string(); dirs_with_main.contains(dir)) continue;
                if (filename.starts_with("test") && !discovered_has_test_target(discovered)) {
                    DiscoveredTarget target;
                    target.main_file = file;
                    target.suggested_name = "test";
                    target.suggested_sources = suggest_sources_for_target(file, all_source_files);
                    target.reason = "test file pattern";
                    discovered.push_back(target);
                }
            }
        }

        // Fallback: If nothing found, suggest the first .cpp file as main
        if (discovered.empty() && !all_source_files.empty()) {
            auto cpp_file = std::ranges::find_if(all_source_files,
                                                 [](const fs::path& p) {
                                                     const std::string ext = p.extension().string();
                                                     return ext == ".cpp" || ext == ".cc" || ext == ".cxx";
                                                 });

            if (cpp_file != all_source_files.end()) {
                DiscoveredTarget target;
                target.main_file = *cpp_file;
                target.suggested_name = "main";
                target.suggested_sources = all_source_files;
                target.reason = "fallback - first C++ file";
                discovered.push_back(target);
            }
        }

        // Remove duplicate targets (by main_file)
        std::unordered_set<std::string> seen_main_files;
        std::vector<DiscoveredTarget> unique_discovered;
        for (const auto& t : discovered) {
            if (std::string main_file_str = t.main_file.string(); !seen_main_files.contains(main_file_str)) {
                unique_discovered.push_back(t);
                seen_main_files.insert(main_file_str);
            }
        }

        return unique_discovered;
    }

private:
    static bool has_main_function(const fs::path& file) {
        std::ifstream stream(file);
        if (!stream.is_open()) return false;

        // Read line by line to avoid loading entire file
        std::string line;
        // More robust pattern that handles different main signatures
        const std::regex main_regex(R"(^\s*int\s+main\s*\([^)]*\)\s*(?:\{|$))");
        while (std::getline(stream, line)) {
            if (std::regex_search(line, main_regex)) {
                return true;
            }
        }
        return false;
    }

    static std::string get_target_name_from_file(const fs::path& file) {
        std::string filename = file.stem().string(); // filename without extension

        // Clean up common patterns
        if (filename == "main") return "main";
        if (filename.starts_with("test")) return "test";
        if (filename.ends_with("_main")) return filename.substr(0, filename.size() - 5);
        if (filename.ends_with("_test")) return filename.substr(0, filename.size() - 5) + "_test";

        return filename;
    }

    static std::vector<fs::path> suggest_sources_for_target(const fs::path& main_file,
                                                           const std::vector<fs::path>& all_files) {
        std::vector<fs::path> suggested;
        suggested.push_back(main_file); // Always include the main file

        // If it's a test target, include other test files
        if (const std::string main_filename = main_file.filename().string(); main_filename.starts_with("test") || main_filename.find("test") != std::string::npos) {
            for (const auto& file : all_files) {
                if (file == main_file) continue;
                if (std::string filename = file.filename().string(); filename.find("test") != std::string::npos) {
                    suggested.push_back(file);
                }
            }
        } else {
            // For main targets, include all non-test files
            for (const auto& file : all_files) {
                if (file == main_file) continue;
                std::string filename = file.filename().string();
                // Skip obvious test files and other main files
                if (filename.find("test") != std::string::npos) continue;
                if (filename == "main.cpp" || filename == "main.c" || filename == "main.cc") {
                    if (file != main_file) continue; // Skip other main files
                }
                suggested.push_back(file);
            }
        }

        return suggested;
    }

    static bool discovered_has_test_target(const std::vector<DiscoveredTarget>& discovered) {
        return std::ranges::any_of(discovered,
                                   [](const DiscoveredTarget& t) { return t.suggested_name == "test"; });
    }
};

class SourceEditor {
public:
    // The main entry point. Launches the TUI for a given target.
    // Returns the new list of selected source files.
    static std::vector<std::string> run(
        const Target& target,
        const std::vector<fs::path>& all_project_sources)
    {
        // 1. Prepare the data for the TUI
        std::vector<std::string> base_entries;
        for (const auto& p : all_project_sources) {
            std::string relative_path = fs::relative(p).string();
            // Ensure path starts with ./
            if (!relative_path.starts_with("./")) {
                relative_path += "./";
            }
            base_entries.push_back(relative_path);
        }
        std::ranges::sort(base_entries); // Keep the list sorted for usability.

        // Remove main_file from the selector if it exists (it will be added automatically)
        std::string main_file_normalized = target.main_file;
        if (!main_file_normalized.starts_with("./")) {
            main_file_normalized = "./" + main_file_normalized;
        }

        if (const auto main_file_it = std::ranges::find(base_entries, main_file_normalized); main_file_it != base_entries.end()) {
            base_entries.erase(main_file_it);
        }

        std::vector<int> states;
        states.resize(base_entries.size(), 0);

        // Pre-select files that are already in the target's source list (excluding main_file)
        std::unordered_set<std::string> initial_selection;
        for (const auto& source : target.sources) {
            std::string normalized_source = source;
            if (!normalized_source.starts_with("./")) {
                normalized_source += "./";
            }
            if (normalized_source != main_file_normalized) {
                initial_selection.insert(normalized_source);
            }
        }

        for (size_t i = 0; i < base_entries.size(); ++i) {
            if (initial_selection.contains(base_entries[i])) {
                states[i] = 1; // 1 means checked
            }
        }

        // Create display entries with checkbox indicators
        std::vector<std::string> entries;
        auto update_entries = [&] {
            entries.clear();
            for (size_t i = 0; i < base_entries.size(); ++i) {
                std::string prefix = states[i] ? "[x] " : "[ ] ";
                entries.push_back(prefix + base_entries[i]);
            }
        };
        update_entries();

        // --- 2. Define the TUI components ---
        auto screen = ScreenInteractive::Fullscreen();

        int selected = 0;
        Component menu = Menu(&entries, &selected);

        // Add event handling for selection toggle and exit
        menu = CatchEvent(menu, [&](const Event &event) {
            if (event == Event::Character(' ') || event == Event::Return) {
                states[selected] = 1 - states[selected]; // Toggle
                update_entries(); // Update display entries
                return true;
            }
            if (event == Event::Character('q') || event == Event::Escape) {
                screen.Exit();
                return true;
            }
            return false;
        });

        // Add a title and instructions
        auto title_renderer = Renderer([] {
            return text(" Source File Selector ") | bold | center;
        });

        auto instructions_renderer = Renderer([&] {
            return vbox({
                text("Target: " + target.name) | bold,
                text("Main file: " + main_file_normalized + " (auto-included)") | dim,
                separator(),
                text("Use [↑/↓] to navigate."),
                text("Use [space] or [enter] to toggle selection."),
                text("Press [q] or [escape] to confirm and exit."),
                separator(),
                text("Selected: " + std::to_string(std::ranges::count(states, 1))) | dim,
            }) | border;
        });

        // Layout the components
        const auto layout = Container::Vertical({
            title_renderer,
            instructions_renderer,
            menu
        });

        // --- 3. Run the TUI event loop ---
        const auto main_renderer = Renderer(layout, [&] {
            return vbox({
                title_renderer->Render(),
                instructions_renderer->Render(),
                menu->Render() | vscroll_indicator | frame | flex,
            }) | border;
        });

        // The TUI takes control of the terminal here.
        // It will exit when the user presses 'q' or 'escape'.
        screen.Loop(main_renderer);

        // --- 4. Process the results ---
        std::vector<std::string> final_selection;
        for (size_t i = 0; i < base_entries.size(); ++i) {
            if (states[i] == 1) { // If the checkbox is checked
                final_selection.push_back(base_entries[i]);
            }
        }

        // Always include the main file, even if the user unchecks it by mistake.
        if (std::ranges::find(final_selection, main_file_normalized) == final_selection.end()) {
             final_selection.push_back(main_file_normalized);
             out::warn("The target's main_file ('{}') was unselected, but has been re-added automatically.", main_file_normalized);
        }

        return final_selection;
    }
};

std::string hash_file(const fs::path& path) {
    constexpr size_t buffer_size = 65536;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }

    std::vector<char> buffer(buffer_size);
    XXH64_state_t* const state = XXH64_createState();
    if (!state) return "";  // Check allocation

    // Use RAII wrapper
    auto state_deleter = [](XXH64_state_t* s) { XXH64_freeState(s); };
    std::unique_ptr<XXH64_state_t, decltype(state_deleter)> state_guard(state, state_deleter);

    XXH64_reset(state, 0);

    while (file.read(buffer.data(), buffer_size)) {
        XXH64_update(state, buffer.data(), file.gcount());
    }
    if (file.gcount() > 0) {
        XXH64_update(state, buffer.data(), file.gcount());
    }

    XXH64_hash_t const hash_val = XXH64_digest(state);
    return fmt::format("{:016x}", hash_val);
}

void write_config_to_toml(const Config& config, const fs::path& toml_path) {
    auto includes_arr = toml::array{};
    for (const auto& dir : config.include_dirs) {
        includes_arr.push_back(dir);
    }

    auto libs_arr = toml::array{};
    for (const auto& lib : config.external_libs) {
        libs_arr.push_back(lib);
    }

    auto exclude_arr = toml::array{};
    for (const auto& pattern : config.exclude_patterns) {
        exclude_arr.push_back(pattern);
    }

    auto targets_arr = toml::array{};
    for (const auto&[name, main_file, sources, output_name, exclude_patterns] : config.targets) {
        auto sources_arr = toml::array{}; // RENAMED from additional_sources
        for (const auto& src : sources) {
            sources_arr.push_back(src);
        }

        auto target_exclude_arr = toml::array{};
        for (const auto& pattern : exclude_patterns) {
            target_exclude_arr.push_back(pattern);
        }

        auto target_tbl = toml::table{
            {"name", name},
            {"main_file", main_file},
            {"sources", sources_arr}, // RENAMED
            {"output_name", output_name},
            {"exclude_patterns", target_exclude_arr}
        };
        targets_arr.push_back(target_tbl);
    }

    auto tbl = toml::table{
        {"project", toml::table{
            {"build_dir", config.build_dir},
            {"default_target", config.default_target}
        }},
        {"compilers", toml::table{
            {"cxx", config.cxx},
            {"cc", config.cc},
            {"as", config.as}
        }},
        {"flags", toml::table{
            {"cxxflags", config.cxxflags},
            {"cflags", config.cflags},
            {"ldflags", config.ldflags}
        }},
        {"features", toml::table{
            {"use_pch", config.use_pch}
        }},
        {"paths", toml::table{
            {"include_dirs", includes_arr},
            {"external_libs", libs_arr},
            {"exclude_patterns", exclude_arr}
        }},
        {"targets", targets_arr}
    };

    std::ofstream file(toml_path);
    if (!file.is_open()) {
        out::error("Failed to open '{}' for writing configuration.", toml_path);
        return;
    }
    file << fmt::format("# CONFIGURATION FILE 'autocc.toml' IS WRITTEN BY AUTOCC ON {} {}, EDIT WITH CAUTION.\n", TIME, DATE);
    file << tbl;
    out::success("Configuration saved to '{}'.", toml_path);
}

void validate_config(Config& config) {
    std::unordered_set<std::string> names, outputs;
    for (const auto& t : config.targets) {
        if (t.name.empty()) out::warn("A target has an empty name.");
        if (t.main_file.empty()) out::warn("Target '{}' has an empty main_file.", t.name);
        if (t.sources.empty()) out::warn("Target '{}' has no sources.", t.name);
        if (!names.insert(t.name).second) out::error("Duplicate target name '{}'.", t.name);
        if (!outputs.insert(t.output_name).second) out::error("Duplicate output_name '{}'.", t.output_name);
    }
    if (!config.default_target.empty() &&
        std::ranges::none_of(config.targets, [&](const Target& t){ return t.name == config.default_target; }))
        out::warn("default_target '{}' does not match any target name.", config.default_target);
}

std::optional<Config> load_config_from_toml(const fs::path& toml_path) {
    if (!fs::exists(toml_path)) {
        return std::nullopt;
    }

    try {
        toml::table tbl = toml::parse_file(toml_path.string());
        Config config;

        auto get_or = [&](const toml::node* node, const std::string& default_val) {
            return node ? node->value_or(default_val) : default_val;
        };
        auto get_bool_or = [&](const toml::node* node, bool default_val) {
            return node ? node->value_or(default_val) : default_val;
        };

        config.build_dir = get_or(tbl["project"]["build_dir"].as_string(), ".autocc_build");
        config.default_target = get_or(tbl["project"]["default_target"].as_string(), "main"); // NEW

        config.cxx = get_or(tbl["compilers"]["cxx"].as_string(), "clang++");
        config.cc = get_or(tbl["compilers"]["cc"].as_string(), "clang");
        config.as = get_or(tbl["compilers"]["as"].as_string(), "nasm");
        config.cxxflags = get_or(tbl["flags"]["cxxflags"].as_string(), "-march=native -std=c++23 -O2 -pipe");
        config.cflags = get_or(tbl["flags"]["cflags"].as_string(), "-march=native -std=c11 -O2 -pipe");
        config.ldflags = get_or(tbl["flags"]["ldflags"].as_string(), "");
        config.use_pch = get_bool_or(tbl["features"]["use_pch"].as_boolean(), false);

        if (auto* includes = tbl["paths"]["include_dirs"].as_array()) {
            for (const auto& elem : *includes) {
                std::string dir = elem.value_or("");
                if (!dir.empty() && fs::path(dir).is_absolute()) {
                    out::warn("Include directory '{}' in autocc.toml is absolute. This may break portability. Consider using a relative path.", dir);
                }
                config.include_dirs.emplace_back(dir);
            }
        }

        if (auto* libs = tbl["paths"]["external_libs"].as_array()) {
            for (const auto& elem : *libs) { config.external_libs.emplace_back(elem.value_or("")); }
        }

        if (auto* excludes = tbl["paths"]["exclude_patterns"].as_array()) {
            for (const auto& elem : *excludes) { config.exclude_patterns.emplace_back(elem.value_or("")); }
        }

        // NEW: Load targets
        if (auto* targets_arr = tbl["targets"].as_array()) {
            for (const auto& target_node : *targets_arr) {
                if (auto* target_tbl = target_node.as_table()) {
                    Target target;
                    target.name = get_or((*target_tbl)["name"].as_string(), "");
                    target.main_file = get_or((*target_tbl)["main_file"].as_string(), "");
                    target.output_name = get_or((*target_tbl)["output_name"].as_string(), target.name);

                    if (auto* sources = (*target_tbl)["sources"].as_array()) { // RENAMED from additional_sources
                        for (const auto& elem : *sources) {
                            target.sources.emplace_back(elem.value_or(""));
                        }
                    }

                    if (auto* target_excludes = (*target_tbl)["exclude_patterns"].as_array()) {
                        for (const auto& elem : *target_excludes) {
                            target.exclude_patterns.emplace_back(elem.value_or(""));
                        }
                    }

                    if (!target.name.empty() && !target.main_file.empty()) {
                        config.targets.push_back(target);
                    }
                }
            }
        }

        validate_config(config);
        return config;

    } catch (const toml::parse_error& err) {
        out::error("Failed to parse '{}':\n{}", toml_path, err.description());
        return std::nullopt;
    }
}

class Fetcher {
public:
    static bool download_file(const std::string& url, const fs::path& dest_path, int max_retries = 3) {
        out::info("Attempting to download from {}...", url);

        for (int retry_count = 0; retry_count < max_retries; ++retry_count) {
            try {
                std::string host, path;
                if (!parse_url(url, host, path)) {
                    out::error("Invalid URL format: {}", url);
                    return false;
                }

                httplib::SSLClient client(host);

                // Try to find CA certs, but don't fail if we can't
                if (std::string ca_path = find_ca_cert_path(); !ca_path.empty()) {
                    client.set_ca_cert_path(ca_path);
                    out::info("Using CA certificates from: {}", ca_path);
                } else {
                    out::warn("No CA certificate bundle found. SSL verification may fail.");
                }

                client.set_follow_location(true);
                client.set_connection_timeout(std::chrono::seconds(5));
                client.set_read_timeout(std::chrono::seconds(10));

                auto res = client.Get(path);

                if (!res) {
                    out::error("Download failed (Attempt {}/{}). Reason: {}", retry_count + 1, max_retries, httplib::to_string(res.error()));
                    if (retry_count < max_retries - 1) {
                        std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before retrying
                    }
                    continue;
                }
                if (res->status == 200) {
                    std::ofstream file(dest_path, std::ios::binary);
                    if (!file.is_open()) {
                        out::error("Failed to open file for writing: {}", dest_path);
                        return false;
                    }
                    file.write(res->body.c_str(), static_cast<std::streamsize>(res->body.size()));
                    out::success("Successfully downloaded and saved to '{}'.", dest_path);
                    return true;
                }
                out::error("Download failed (Attempt {}/{}). Server responded with status code: {}", retry_count + 1, max_retries, res->status);
                if (retry_count < max_retries - 1) {
                    std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before retrying
                }
            } catch (const std::exception& e) {
                out::error("An exception occurred during download (Attempt {}/{}): {}", retry_count + 1, max_retries, e.what());
                if (retry_count < max_retries - 1) {
                    std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before retrying
                }
            }
        }
        out::error("Failed to download {} after {} attempts.", url, max_retries);
        return false;
    }
private:
    static std::string find_ca_cert_path() {
        // Common CA cert locations across different distros
        static const std::vector<std::string> ca_paths = {
            "/etc/ssl/certs/ca-certificates.crt",     // Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",       // RHEL/CentOS/Fedora
            "/etc/ssl/ca-bundle.pem",                 // OpenSUSE
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Modern RHEL/CentOS
            "/etc/ssl/cert.pem",                      // Alpine/some others
            "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
            "/etc/ssl/certs/ca-bundle.crt"            // Some other distros
        };

        for (const auto& path : ca_paths) {
            if (fs::exists(path)) {
                return path;
            }
        }

        return ""; // None found
    }
    static bool parse_url(const std::string& url, std::string& host, std::string& path) {
        const std::string protocol_end = "://";
        size_t host_start = url.find(protocol_end);
        if (host_start == std::string::npos) return false;
        host_start += protocol_end.length();
        if (const size_t path_start = url.find('/', host_start); path_start == std::string::npos) {
            host = url.substr(host_start);
            path = "/";
        } else {
            host = url.substr(host_start, path_start - host_start);
            path = url.substr(path_start);
        }
        return true;
    }
};

class LibraryDetector {
    struct DetectionRule {
        std::vector<std::string> direct_libs;
        std::vector<std::string> pkg_configs;
    };
    std::unordered_map<std::string, DetectionRule> detectionMap;
    std::unordered_map<std::string, std::string> pkg_cache;
    void load_rules_from_file(const fs::path& db_path) {
        if (!fs::exists(db_path)) {
            out::warn("Library database '{}' not found. Attempting to download...", db_path);
            if (!Fetcher::download_file(BASE_DB_URL, db_path)) {
                out::error("Failed to download library database. Library detection will be limited.");
                return;
            }
        }
        try {
            std::ifstream f(db_path);
            if (!f.is_open()) {
                out::error("Failed to open library database '{}'. Library detection will be limited.", db_path);
                return;
            }
            json data = json::parse(f);
            if (!data.contains("libraries") || !data["libraries"].is_object()) {
                out::error("Invalid database format: missing 'libraries' object");
                return;
            }

            for (auto& [header, rule_json] : data["libraries"].items()) {
                if (!rule_json.is_object()) continue; // Skip invalid entries

                DetectionRule rule;
                if (rule_json.contains("direct_libs") && rule_json["direct_libs"].is_array()) {
                    rule.direct_libs = rule_json["direct_libs"].get<std::vector<std::string>>();
                }
                if (rule_json.contains("pkg_configs") && rule_json["pkg_configs"].is_array()) {
                    rule.pkg_configs = rule_json["pkg_configs"].get<std::vector<std::string>>();
                }
                detectionMap[header] = rule;
            }
            out::info("Loaded {} library detection rules.", detectionMap.size());
        } catch (const json::parse_error& e) {
            out::error("Failed to parse library database '{}': {}. Attempting to re-download and parse.", db_path, e.what());
            try {
                fs::remove(db_path); // Remove corrupt file
            } catch (const fs::filesystem_error& fs_error) {
                out::error("Failed to remove corrupt database file '{}': {}", db_path, fs_error.what());
            }
            if (Fetcher::download_file(BASE_DB_URL, db_path)) {
                // Try parsing again after a successful download
                try {
                    std::ifstream f(db_path);
                    if (!f.is_open()) {
                        out::error("Failed to open re-downloaded library database '{}'. Library detection will be limited.", db_path);
                        return;
                    }
                    json data = json::parse(f);
                    if (!data.contains("libraries") || !data["libraries"].is_object()) {
                        out::error("Invalid database format: missing 'libraries' object");
                        return;
                    }

                    for (auto& [header, rule_json] : data["libraries"].items()) {
                        if (!rule_json.is_object()) continue; // Skip invalid entries

                        DetectionRule rule;
                        if (rule_json.contains("direct_libs") && rule_json["direct_libs"].is_array()) {
                            rule.direct_libs = rule_json["direct_libs"].get<std::vector<std::string>>();
                        }
                        if (rule_json.contains("pkg_configs") && rule_json["pkg_configs"].is_array()) {
                            rule.pkg_configs = rule_json["pkg_configs"].get<std::vector<std::string>>();
                        }
                        detectionMap[header] = rule;
                    }
                    out::info("Successfully re-downloaded and loaded {} library detection rules.", detectionMap.size());
                } catch (const json::parse_error& e2) {
                    out::error("Failed to parse re-downloaded library database '{}': {}. Library detection will be limited.", db_path, e2.what());
                }
            } else {
                out::error("Failed to re-download library database. Library detection will be limited.");
            }
        }
    }
public:
    LibraryDetector() { load_rules_from_file(DB_FILE_NAME); }
    void detect(const std::vector<std::string>& includes, Config& config) {
        std::unordered_set found_direct_libs(config.external_libs.begin(), config.external_libs.end());
        std::unordered_set<std::string> processed_pkg_configs;
        std::string additional_cflags;    // ✅ Separate compile flags
        std::string additional_ldflags;   // ✅ Only for actual linker flags

        for (const auto& include : includes) {
            for (const auto& [header_signature, rule] : detectionMap) {
                if (include.find(header_signature) != std::string::npos) {
                    // Add direct libraries
                    for (const auto& lib : rule.direct_libs) {
                        found_direct_libs.insert(lib);
                    }

                    // Process pkg-config
                    for (const auto& pkg_name : rule.pkg_configs) {
                        if (processed_pkg_configs.contains(pkg_name)) continue;

                        if (const auto pkg_result = getPkgConfigFlags(pkg_name); !pkg_result.empty()) {
                            // Parse pkg-config output and separate flags properly
                            parsePkgConfigOutput(pkg_result, found_direct_libs, additional_cflags, additional_ldflags);
                            out::info("Found dependency '{}', adding flags via pkg-config.", pkg_name);
                        } else {
                            out::warn("Found include for '{}' but 'pkg-config {}' failed. Is it installed?", pkg_name, pkg_name);
                        }
                        processed_pkg_configs.insert(pkg_name);
                    }
                }
            }
        }

        config.external_libs.assign(found_direct_libs.begin(), found_direct_libs.end());

        // Add compile flags to cxxflags (not ldflags!)
        if (!additional_cflags.empty()) {
            config.cxxflags += " " + additional_cflags;
            config.cflags += " " + additional_cflags;  // Add to both C and C++ flags
        }

        // Only add actual linker flags to ldflags
        if (!additional_ldflags.empty()) {
            config.ldflags += " " + additional_ldflags;
        }
    }

private:
    static void parsePkgConfigOutput(const std::string& pkg_output, std::unordered_set<std::string>& libs, std::string& cflags, std::string& ldflags) {
        std::istringstream iss(pkg_output);
        std::string token;

        while (iss >> token) {
            if (token.starts_with("-l")) {
                libs.insert(token);
            } else if (token.starts_with("-L") || token.starts_with("-Wl,") ||
                token.starts_with("-T") ||
                token.starts_with("--dynamic-linker") ||
                token.starts_with("-rpath")) {
                ldflags += " " + token;
            } else {
               // Everything else goes to cflags (includes -I, -D, and other compile flags)
               cflags += " " + token;
            }
        }
    }
    std::string getPkgConfigFlags(const std::string& package) {
        if (pkg_cache.contains(package)) return pkg_cache[package];
        const std::string cmd = fmt::format("pkg-config --libs --cflags {}", package);
        auto [exit_code, stdout_output, stderr_output] = execute(cmd);

        if (exit_code != 0) {
            if (stderr_output.find("not found") != std::string::npos) {
                out::warn("pkg-config for '{}' failed: Package not found. Is it installed?", package);
            } else if (!stderr_output.empty()) {
                out::warn("pkg-config for '{}' failed with error: {}", package, stderr_output);
            } else {
                out::warn("pkg-config for '{}' failed with unknown error.", package);
            }
            return "";
        }

        std::string stdout_result = stdout_output;
        if (!stdout_result.empty() && stdout_result.back() == '\n') stdout_result.pop_back();
        return pkg_cache[package] = stdout_result;
    }
};

class IncludeParser {
    std::regex include_regex{R"_(\s*#\s*include\s*(?:<([^>]+)>|"([^"]+)"))_"};
    static fs::path findHeader(const std::string& header_name, const fs::path& relative_to, const std::vector<std::string>& include_dirs) {
        fs::path potential_path = relative_to / header_name;
        if (fs::exists(potential_path)) return fs::canonical(potential_path);
        for (const auto& dir_flag : include_dirs) {
            if (dir_flag.rfind("-I", 0) == 0) {
                fs::path base_dir = dir_flag.substr(2);
                potential_path = base_dir / header_name;
                if (fs::exists(potential_path)) return fs::canonical(potential_path);
            }
        }
        return {};
    }
public:
    [[nodiscard]] DependencyMap parseSourceDependencies(const std::vector<fs::path>& sourceFiles, const std::vector<std::string>& include_dirs) const {
        DependencyMap dep_map;
        for (const auto& src_file : sourceFiles) {
            std::unordered_set<fs::path> dependencies;
            std::vector files_to_scan = {src_file};
            std::unordered_set<fs::path> scanned_files;
            while (!files_to_scan.empty()) {
                fs::path current_file = files_to_scan.back();
                files_to_scan.pop_back();
                if (scanned_files.contains(current_file)) continue;
                scanned_files.insert(current_file);
                std::ifstream file_stream(current_file);
                if (!file_stream.is_open()) {
                    out::warn("Could not open file for dependency parsing: {}", current_file);
                    continue;
                }
                std::string line;
                while (std::getline(file_stream, line)) {
                    if (std::smatch matches; std::regex_search(line, matches, include_regex)) {
                        if (matches[2].matched) { // Only track local "..." includes
                            const auto& header_name = matches[2].str();
                            if (fs::path header_path = findHeader(header_name, current_file.parent_path(), include_dirs); !header_path.empty()) {
                                dependencies.insert(header_path);
                                files_to_scan.push_back(header_path);
                            }
                        }
                    }
                }
            }
            dep_map[src_file] = dependencies;
        }
        return dep_map;
    }
    [[nodiscard]] std::vector<std::string> getAllProjectIncludes(const std::vector<fs::path>& sourceFiles,
                                                                 const std::vector<std::string>& include_dirs,
                                                                 const std::unordered_set<std::string>& ignored_dirs) const {
        std::unordered_set<std::string> unique_includes;
        std::vector<fs::path> files_to_scan = sourceFiles;
        std::unordered_set<fs::path> scanned_files;
        for (const auto& entry : fs::recursive_directory_iterator(".", fs::directory_options::skip_permission_denied)) {
            // Skip ignored directories
            bool is_in_ignored_dir = false;
            for (const auto& part : entry.path()) {
                if (ignored_dirs.contains(part.string())) {
                    is_in_ignored_dir = true;
                    break;
                }
            }
            if (is_in_ignored_dir) continue;

            if (entry.is_regular_file()) {
                if (const std::string ext = entry.path().extension().string(); ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".hh") {
                    // Scan this header file for includes
                    if (std::ifstream file_stream(entry.path()); file_stream.is_open()) {
                        std::string line;
                        while (std::getline(file_stream, line)) {
                            if (std::smatch matches; std::regex_search(line, matches, include_regex)) {
                                unique_includes.insert(matches[1].matched ? matches[1].str() : matches[2].str());
                            }
                        }
                    }
                }
            }
        }
        while (!files_to_scan.empty()) {
            fs::path current_file = files_to_scan.back();
            files_to_scan.pop_back();
            if (scanned_files.contains(current_file)) continue;
            scanned_files.insert(current_file);
            std::ifstream file_stream(current_file);
            if (!file_stream.is_open()) {
                out::warn("Could not open file for unique includes parsing: {}", current_file);
                continue;
            }
            std::string line;
            while (std::getline(file_stream, line)) {
                if (std::smatch matches; std::regex_search(line, matches, include_regex)) {
                    unique_includes.insert(matches[1].matched ? matches[1].str() : matches[2].str());
                    if (matches[2].matched) { // Recurse on local "..." includes
                        const auto& header_name = matches[2].str();
                        if (fs::path header_path = findHeader(header_name, current_file.parent_path(), include_dirs); !header_path.empty()) {
                            files_to_scan.push_back(header_path);
                        }
                    }
                }
            }
        }
        return {unique_includes.begin(), unique_includes.end()};
    }
};


class AutoCC {
public:
    Config config;
    LibraryDetector lib_detector;
    IncludeParser include_parser;
    std::vector<fs::path> source_files;
    std::vector<fs::path> target_source_files;
    bool should_auto_detect{};

    std::unordered_set<std::string> getIgnoredDirs() const {
        return {".git", config.build_dir, CACHE_DIR_NAME}; // to avoid conflict i remove ignored dirs
    }

    void scanLocalHeaders() {
        std::set<fs::path> header_dirs;
        const auto ignored_dirs_set = getIgnoredDirs();
        try {
            for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
                try {
                    // Check if we can access this entry
                    if (!entry.exists()) continue;

                    bool is_in_ignored_dir = false;
                    for (const auto& part : entry.path()) {
                        if (ignored_dirs_set.contains(part.string())) {
                            is_in_ignored_dir = true;
                            break;
                        }
                    }
                    if (is_in_ignored_dir) continue;

                    if (entry.is_regular_file()) {
                        if (const std::string ext = entry.path().extension().string(); ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".hh") {
                            header_dirs.insert(fs::canonical(entry.path().parent_path()));
                        }
                    }
                } catch (const fs::filesystem_error& e) {
                    out::warn("Skipping file due to filesystem error: {}", e.what());
                }
            }
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to scan for headers: {}", e.what());
            return;
        }

        // Use a set to avoid duplicate -I flag from TOML and scan
        std::unordered_set<std::string> final_includes;
        for (const auto& dir : config.include_dirs) final_includes.insert(dir);
        for (const auto& dir : header_dirs) {
            fs::path rel = fs::relative(dir, root);
            final_includes.insert(rel.empty() ? dir.string() : rel.string());
        }
        config.include_dirs.assign(final_includes.begin(), final_includes.end());
    }

    void detectLibraries() {
        const auto ignored_dirs = getIgnoredDirs();
        const auto all_includes = include_parser.getAllProjectIncludes(source_files, config.include_dirs, ignored_dirs);
        lib_detector.detect(all_includes, config);
    }

    std::string generatePCH(const fs::path& build_path) {
        out::info("Analyzing for Pre-Compiled Header generation...");
        std::unordered_map<std::string, int> include_counts;
        int cpp_file_count = 0;
        for (const auto& src : target_source_files) {
            if (getCompiler(src) != config.cxx) continue;
            cpp_file_count++;
            std::ifstream stream(src);
        if (!stream.is_open()) {
            out::warn("Could not open source file for PCH analysis: {}", src);
            continue;
        }
            std::string line;
            std::regex pch_candidate_regex(R"_(\s*#\s*include\s*<([^>]+)>)_" );
            while(std::getline(stream, line)) {
                if(std::smatch matches; std::regex_search(line, matches, pch_candidate_regex)) {
                    include_counts[matches[1].str()]++;
                }
            }
        }
        if (cpp_file_count < 3) {
            out::info("PCH skipped: Not enough C++ source files.");
            return "";
        }
        std::vector<std::string> pch_headers;
        for(const auto& [header, count] : include_counts) {
            if (count > cpp_file_count / 2) {
                pch_headers.push_back(header);
            }
        }
        if (pch_headers.empty()) {
             out::info("PCH skipped: No sufficiently common headers found.");
             return "";
        }
        fs::path pch_source = build_path / PCH_HEADER_NAME;
        fs::path pch_out = pch_source.string() + ".gch";
        out::info("Generating PCH from headers: {}", fmt::join(pch_headers, ", "));
        std::ofstream pch_file(pch_source);
        if (!pch_file.is_open()) {
            out::error("Failed to create PCH source file: {}", pch_source);
            return "";
        }
        for(const auto& header : pch_headers) pch_file << "#include <" << header << ">\n";
        pch_file.close();
        const std::string pch_compile_cmd = fmt::format("{} -x c++-header {} -o {} {} {}",
            config.cxx, pch_source, pch_out, config.cxxflags, 
            fmt::join(config.include_dirs | std::views::transform([](const std::string& d){ return "-I" + d; }), " "));
        out::command("{}", pch_compile_cmd);
        if (auto [exit_code, stdout_output, stderr_output] = execute(pch_compile_cmd); exit_code != 0) {
            out::warn("PCH generation failed. Continuing without it.\n   Compiler error: {}", stderr_output);
            return "";
        }
        if (!fs::exists(pch_out)) {
            out::warn("PCH compilation appeared successful but output file missing: {}", pch_out);
            // Clean up partial files
            try {
                if (fs::exists(pch_source)) fs::remove(pch_source);
            } catch (...) {}
            return "";
        }
        return fmt::format("-include {}", pch_source.string());
    }

    std::string getCompiler(const fs::path& file) const {
        const std::string ext = file.extension().string();
        if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".c++") return config.cxx;
        if (ext == ".c") return config.cc;
        if (ext == ".s" || ext == ".S" || ext == ".asm") return config.as;
        return config.cxx;
    }

    explicit AutoCC() = default;

    explicit AutoCC(Config cfg, const bool auto_detect = false)
        : config(std::move(cfg)), should_auto_detect(auto_detect) {

        // Always scan for source files first
        const auto ignored_dirs = getIgnoredDirs();
        source_files = find_source_files(root, ignored_dirs, config.exclude_patterns);

        // Only run auto-detection if explicitly requested
        if (should_auto_detect) {
            out::info("Running auto-detection for headers and libraries...");
            scanLocalHeaders();
            detectLibraries();
        }
    }

    static std::optional<AutoCC> load_from_cache() {
        Config config;

        // Try to read cache first
        if (!read_config_cache_static(config)) {
            return std::nullopt;
        }

        // Create instance WITHOUT auto-detection
        AutoCC instance(std::move(config), false);

        if (instance.source_files.empty()) {
            out::error("No source files found.");
            return std::nullopt;
        }

        return instance;
    }

    static AutoCC create_with_auto_detection(Config config) {
        return AutoCC(std::move(config), true);
    }

    void writeConfigCache() const {
        try {
            fs::create_directories(cache_dir);
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to create cache directory '{}': {}", cache_dir, e.what());
            return;
        }
        std::ofstream file(config_file);
        if (!file.is_open()) {
            out::error("Failed to open config cache file for writing: {}", config_file);
            return;
        }

        // Basic config
        file << "cxx:" << config.cxx << "\n";
        file << "cc:" << config.cc << "\n";
        file << "as:" << config.as << "\n";
        file << "cxxflags:" << config.cxxflags << "\n";
        file << "cflags:" << config.cflags << "\n";
        file << "ldflags:" << config.ldflags << "\n";
        file << "build_dir:" << config.build_dir << "\n";
        file << "use_pch:" << (config.use_pch ? "true" : "false") << "\n";
        file << "default_target:" << config.default_target << "\n"; // NEW

        // Arrays
        for (const auto& dir : config.include_dirs) file << "include:" << dir << "\n";
        for (const auto& lib : config.external_libs) file << "lib:" << lib << "\n";
        for (const auto& pattern : config.exclude_patterns) file << "exclude:" << pattern << "\n";

        // NEW: Targets (using a simple format that's straightforward to parse)
        for (const auto& [name, main_file, sources, output_name, exclude_patterns] : config.targets) {
            // Escape pipe characters in the values
            auto escape_pipes = [](const std::string& str) {
                std::string result = str;
                size_t pos = 0;
                while ((pos = result.find('|', pos)) != std::string::npos) {
                    result.replace(pos, 1, "\\|");
                    pos += 2;
                }
                return result;
            };

            file << "target:" << escape_pipes(name) << "|"
                 << escape_pipes(main_file) << "|"
                 << escape_pipes(output_name) << "\n";

            // Sources for this target
            for (const auto& src : sources) {
                file << "target_src:" << name << ":" << src << "\n";
            }

            // Target-specific excludes
            for (const auto& pattern : exclude_patterns) {
                file << "target_exclude:" << name << ":" << pattern << "\n";
            }
        }
    }



    int build(const std::string& target_name = "") {
        if (config.targets.empty()) {
            out::error("No targets configured. Run 'autocc autoconfig' to set up targets.");
            return 1;
        }
        std::string actual_target = target_name.empty() ? config.default_target : target_name;

        if (actual_target.empty()) {
            actual_target = config.targets[0].name;
            out::info("No default target specified, using '{}'", actual_target);
        }
        // Find the target
        const auto target_it = std::ranges::find_if(config.targets,
                                              [&](const Target& t) { return t.name == actual_target; });

        if (target_it == config.targets.end()) {
            out::error("Target '{}' not found. Available targets: {}",
                      actual_target,
                      fmt::join(config.targets | std::views::transform([](const Target& t) { return t.name; }), ", "));
            return 1;
        }

        return build_target(*target_it);
    }

    static bool read_config_cache_static(Config& config) {
        const fs::path cache_dir = CACHE_DIR_NAME;
        const fs::path config_file = cache_dir / CONFIG_FILE_NAME;

        if (!fs::exists(config_file)) return false;

        std::ifstream file(config_file);
        if (!file.is_open()) {
            out::error("Failed to open config cache file for reading: {}", config_file);
            return false;
        }

        std::string line;
        config.include_dirs.clear();
        config.external_libs.clear();
        config.exclude_patterns.clear();
        config.targets.clear(); // NEW: Clear targets

        // Helper maps to build targets as we parse
        std::unordered_map<std::string, Target> target_map;

        while (std::getline(file, line)) {
            const auto pos = line.find(':');
            if (pos == std::string::npos) {
                out::warn("Invalid config cache line format, skipping: {}", line);
                continue;
            }

            const std::string_view key = std::string_view(line).substr(0, pos);
            std::string_view value = pos + 1 < line.size() ? std::string_view(line).substr(pos + 1) : "";

            // Basic config
            if (key == "cxx") config.cxx = value;
            else if (key == "cc") config.cc = value;
            else if (key == "as") config.as = value;
            else if (key == "cxxflags") config.cxxflags = value;
            else if (key == "cflags") config.cflags = value;
            else if (key == "ldflags") config.ldflags = value;
            else if (key == "build_dir") config.build_dir = value;
            else if (key == "use_pch") config.use_pch = value == "true";
            else if (key == "default_target") config.default_target = value; // NEW

            // Arrays
            else if (key == "include") config.include_dirs.emplace_back(value);
            else if (key == "lib") config.external_libs.emplace_back(value);
            else if (key == "exclude") config.exclude_patterns.emplace_back(value);

            else if (key == "target") {
                auto unescape_pipes = [](const std::string& str) {
                    std::string result = str;
                    size_t position = 0;
                    while ((position = result.find("\\|", position)) != std::string::npos) {
                        result.replace(position, 2, "|");
                        position += 1;
                    }
                    return result;
                };

                // Format: name|main_file|output_name
                std::string value_str(value);
                size_t first_pipe = value_str.find('|');

                if (size_t second_pipe = value_str.find('|', first_pipe + 1);
                    first_pipe != std::string::npos && second_pipe != std::string::npos) {
                    Target target;
                    target.name = unescape_pipes(value_str.substr(0, first_pipe));
                    target.main_file = unescape_pipes(value_str.substr(first_pipe + 1, second_pipe - first_pipe - 1));
                    target.output_name = unescape_pipes(value_str.substr(second_pipe + 1));
                    target_map[target.name] = target;
                    } else {
                        out::warn("Invalid target format in cache, skipping: {}", line);
                    }
            }

            else if (key == "target_src") {
                // Format: target_name:source_path
                std::string value_str(value);
                if (size_t colon_pos = value_str.find(':'); colon_pos != std::string::npos) {
                    std::string target_name = value_str.substr(0, colon_pos);
                    std::string source_path = value_str.substr(colon_pos + 1);
                    if (target_map.contains(target_name)) {
                        target_map[target_name].sources.push_back(source_path);
                    }
                }
            }

            else if (key == "target_exclude") {
                // Format: target_name:exclude_pattern
                std::string value_str(value);
                if (size_t colon_pos = value_str.find(':'); colon_pos != std::string::npos) {
                    std::string target_name = value_str.substr(0, colon_pos);
                    std::string exclude_pattern = value_str.substr(colon_pos + 1);
                    if (target_map.contains(target_name)) {
                        target_map[target_name].exclude_patterns.push_back(exclude_pattern);
                    }
                }
            }
            else {
                out::warn("Unknown config cache key, skipping: {}", key);
            }
        }

        // Convert target_map to vector
        for (auto &target: target_map | std::views::values) {
            config.targets.push_back(std::move(target));
        }

        return true;
    }
private:

    int build_target(const Target& target) {
        target_source_files.clear(); // clear previous target files (extra safety)
        out::info("Building target: {} -> {}", target.name, target.output_name);

        for (const auto& src_path : target.sources) {

            bool excluded = false;
            for (const auto& pat : config.exclude_patterns) {
                if (matches_pattern(src_path, pat)) { excluded = true; break; }
            }
            for (const auto& pat : target.exclude_patterns) {
                if (matches_pattern(src_path, pat)) { excluded = true; break; }
            }
            if (excluded) {
                out::info("Source '{}' excluded by pattern.", src_path);
                continue;
            }

            fs::path file_path(src_path);
            if (!file_path.is_absolute()) {
                file_path = fs::path(root) / file_path;
            }
            try {
                if (fs::exists(file_path)) {
                    try {
                        target_source_files.push_back(fs::canonical(file_path));
                    }
                    catch (const fs::filesystem_error& e) {
                        out::error("Cannot resolve path '{}': {}", file_path.string(), e.what());
                        return 1;
                    }
                } else {
                    out::error("Source file '{}' specified in target '{}' not found at '{}'",
                            src_path, target.name, file_path.string());
                    return 1;
                }
            } catch (const fs::filesystem_error& e) {
                out::error("Error accessing source file '{}': {}", file_path.string(), e.what());
                return 1;
            }
        }

        if (target_source_files.empty()) {
            out::error("No valid source files found for target '{}'", target.name);
            return 1;
        }

        out::info("Target '{}' building {} source files:", target.name, target_source_files.size());
        for (const auto& file : target_source_files) {
            out::info("  - {}", file.filename().string());
        }

        // Build with target-specific files - use target.output_name directly
        return build_with_files(target_source_files, target.output_name);
    }


    int build_with_files(const std::vector<fs::path>& files_to_build, const std::string& output_name) {
        if (files_to_build.empty()) {
            out::error("No source files found to build.");
            return 1;
        }

        if (files_to_build.size() > 1000) {
            out::warn("Suspiciously high number of source files ({}). Are you sure your configuration is correct?", files_to_build.size());
        }

        const fs::path build_path = config.build_dir;
        try {
            fs::create_directories(build_path);
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to create build directory '{}': {}", build_path, e.what());
            return 1;
        }

        out::info("Parsing source file dependencies for build...");
        dependency_map = include_parser.parseSourceDependencies(files_to_build, config.include_dirs);

        json build_cache;
        std::string pch_flags;
        if (config.use_pch) {
            pch_flags = generatePCH(build_path);
        }

        if (fs::exists(dep_cache_file)) {
            std::ifstream f(dep_cache_file);
            build_cache = json::parse(f, nullptr, false);
            if (build_cache.is_discarded()) {
                out::warn("Dependency cache is corrupt. Forcing a full rebuild.");
                build_cache = json::object();
            }
        }

        json new_build_cache = json::object();
        std::vector<fs::path> files_to_compile;
        std::vector<fs::path> object_files;

        out::info("Checking dependencies with content hashing...");

        for (const auto& src_file : files_to_build) {
            fs::path obj_file = build_path / src_file.filename().replace_extension(".o");
            object_files.push_back(obj_file);

            bool needs_recompile = false;
            std::string reason;

            if (!fs::exists(obj_file)) {
                needs_recompile = true;
                reason = "object file missing";
            }

            std::string current_source_hash = hash_file(src_file);
            if (current_source_hash.empty()) {
                out::error("Could not hash source file: {}. Aborting.", src_file);
                return 1;
            }

            std::string current_flags;
            if (const std::string compiler = getCompiler(src_file); compiler == config.cxx) {
                current_flags = config.cxxflags;
            } else if (compiler == config.cc) {
                current_flags = config.cflags;
            }

            json current_dep_hashes = json::object();
            if (dependency_map.contains(src_file)) {
                for (const auto& header : dependency_map.at(src_file)) {
                    current_dep_hashes[header.string()] = hash_file(header);
                }
            }

            if (!needs_recompile) {
                if (!build_cache.contains(obj_file.string())) {
                    needs_recompile = true;
                    reason = "not in cache";
                } else {
                    if (const auto& cached_info = build_cache[obj_file.string()]; cached_info.value("source_hash", "") != current_source_hash) reason = "source file changed";
                    else if (cached_info.value("flags", "") != current_flags) reason = "compiler flags changed";
                    else if (cached_info.value("dep_hashes", json::object()) != current_dep_hashes) reason = "a header dependency changed";
                    if (!reason.empty()) needs_recompile = true;
                }
            }
            if (needs_recompile) {
                files_to_compile.push_back(src_file);
                out::info("Will recompile {}: {}.", src_file, reason);
            }
            new_build_cache[obj_file.string()] = {
                {"source", src_file.string()},
                {"source_hash", current_source_hash},
                {"dep_hashes", current_dep_hashes},
                {"flags", current_flags}
            };
        }

        if (object_files.empty()) {
            out::error("No object files to link. Aborting.");
            return 1;
        }

        if (files_to_compile.empty() && !files_to_build.empty()) {
            out::success("All {} files are up to date.", files_to_build.size());
        } else {
            out::info("Compiling {}/{} source files...", files_to_compile.size(), files_to_build.size());
            std::atomic compilation_failed = false;
            std::atomic<size_t> file_index = 0;
            const unsigned int num_threads = std::max(1u, std::thread::hardware_concurrency());
            std::vector<std::thread> workers;
            for (unsigned int i = 0; i < num_threads; ++i) {
                workers.emplace_back([&] {
                    while (true) {
                        if (compilation_failed.load()) return;
                        const size_t index = file_index.fetch_add(1);
                        if (index >= files_to_compile.size()) return;
                        if (compilation_failed.load()) return;
                        const auto& src = files_to_compile[index];
                        std::string compiler = getCompiler(src);
                        fs::path obj = build_path / src.filename().replace_extension(".o");
                        std::string cmd;
                        if (compiler == config.as) {
                            cmd = fmt::format("{} {} -felf64 -o {}", compiler, src, obj);
                        } else {
                            std::string_view flags = compiler == config.cxx ? config.cxxflags : config.cflags;
                            std::string current_pch_flags = compiler == config.cxx ? pch_flags : "";
                            cmd = fmt::format("{} -c {} -o {} {} {} {}", compiler, src, obj, flags, current_pch_flags, 
                                  fmt::join(config.include_dirs | std::views::transform([](const std::string& d){ return "-I" + d; }), " "));
                        }
                        out::command("{}", cmd);
                        if (auto [exit_code, stdout_output, stderr_output] = execute(cmd); exit_code != 0) {
                            out::error("Failed to compile: {}", src);
                            std::lock_guard lock(g_output_mutex);
                            fmt::print(stderr, "{}\n", stderr_output);
                            compilation_failed = true;
                        }
                    }
                });
            }
            for (auto& w : workers) w.join();
            if (compilation_failed) {
                out::error("Compilation failed. Aborting.");
                return 1;
            }
        }

        // Add this line to define target_path before using it
        const fs::path target_path = fs::path(config.build_dir) / output_name;

        out::info("Linking target...");
        const std::string link_cmd = fmt::format("{} -o {} {} {} {} {}",
            config.cxx, target_path, fmt::join(object_files, " "),
            config.cxxflags, config.ldflags, fmt::join(config.external_libs, " "));
        out::command("{}", link_cmd);

        // Add a timeout or check for hanging linker if needed (not implemented here, but can be added)
        if (auto [exit_code, stdout_output, stderr_output] = execute(link_cmd); exit_code != 0) {
            out::error("Failed to link target: {}", output_name);
            std::lock_guard lock(g_output_mutex);
            fmt::print(stderr, "{}\n", stderr_output);
            return 1;
        }
        std::ofstream out_cache(dep_cache_file);
        out_cache << new_build_cache.dump(2);
        out::success("Target '{}' built successfully in '{}'.", output_name, config.build_dir);
        return 0;
    }

    const fs::path root = ".";
    const fs::path cache_dir = root / CACHE_DIR_NAME;
    const fs::path config_file = cache_dir / CONFIG_FILE_NAME;
    const fs::path dep_cache_file = cache_dir / DEP_CACHE_FILE_NAME;
    DependencyMap dependency_map;



};

// info and help

void show_version() {
    fmt::print("AutoCC {} compiled on {} at {}\n",
        fmt::styled(VERSION, COLOR_SUCCESS),
        fmt::styled(DATE, COLOR_INFO),
        fmt::styled(TIME, COLOR_INFO)
    );
}

void show_help() {
    using fmt::styled;
    show_version();
    fmt::print(
        "\n"
        "Usage: autocc [command]\n\n"
        "Commands:\n"
        "  {}               Builds the project incrementally using cached settings.\n"
        "  {}        Creates 'autocc.toml' via an interactive prompt.\n"
        "  {}        Converts 'autocc.toml' to the internal build cache.\n"
        "  {}          Open a TUI to visually select source files for targets.\n"
        "  {}                Removes the build directory.\n"
        "  {}                 Removes all autocc generated files (cache, build dir, db).\n"
        "  {}                Download/update the library detection database.\n"
        "  {}              Show current version and build date.\n"
        "  {}                 Shows this help message.\n"
        "  {}              Install default target.\n"
        "Flags:\n"
        "  {}            For 'autocc autoconfig', use default settings.\n",
        styled("<none>", COLOR_PROMPT),
        styled("ac/autoconfig", COLOR_PROMPT),
        styled("setup/sync/sc", COLOR_PROMPT),
        styled("edit/select", COLOR_PROMPT), // <-- MODIFIED LINE
        styled("clean", COLOR_PROMPT),
        styled("wipe", COLOR_PROMPT),
        styled("fetch", COLOR_PROMPT),
        styled("version", COLOR_PROMPT),
        styled("help", COLOR_PROMPT),
        styled("install", COLOR_PROMPT),
        styled("--default", COLOR_PROMPT)
    );
}

void user_init(Config& config) {
    auto get_input = [](const std::string_view prompt, const std::string_view default_val) -> std::string {
        fmt::print(stdout, "{} ({})? ",
            fmt::styled(prompt, COLOR_PROMPT),
            fmt::styled(default_val, COLOR_DEFAULT));
        std::string input;
        std::getline(std::cin, input);
        return input.empty() ? std::string(default_val) : input;
    };

    config.cc = get_input("C Compiler", config.cc);
    config.cxx = get_input("C++ Compiler", config.cxx);
    config.as = get_input("Assembler", config.as);

    // Don't ask for an executable name anymore - it comes from targets

    config.cxxflags = get_input("CXX Flags", config.cxxflags);
    config.cflags = get_input("CC Flags", config.cflags);
    config.ldflags = get_input("Linker Flags", config.ldflags);
    config.build_dir = get_input("Build Directory", config.build_dir);
    std::string pch_choice = get_input("Use Pre-Compiled Headers (yes/no)", config.use_pch ? "yes" : "no");
    config.use_pch = pch_choice == "yes" || pch_choice == "y";

    if (std::string exclude_input = get_input("Global exclude patterns (space-separated, e.g. 'test_*.cpp *_test.cpp')", ""); !exclude_input.empty()) {
        std::stringstream ss(exclude_input);
        std::string item;
        while (ss >> item) {
            config.exclude_patterns.push_back(item);
        }
    }

    // NEW: Smart target discovery and configuration
    out::info("Discovering potential build targets...");

    // Get all source files for discovery
    const auto ignored_dirs = std::unordered_set<std::string>{".git", config.build_dir, CACHE_DIR_NAME};
    auto all_sources = find_source_files(".", ignored_dirs, config.exclude_patterns);

    auto discovered = TargetDiscovery::discover_targets(all_sources);

    if (discovered.empty()) {
        out::warn("No targets discovered. You'll need to configure them manually in autocc.toml");
        return;
    }

    out::info("Discovered {} potential target(s):", discovered.size());
    for (size_t i = 0; i < discovered.size(); ++i) {
        const auto&[suggested_name, main_file, suggested_sources, reason] = discovered[i];
        out::info("  {}: {} ({}) - {} source files",
                 i + 1, suggested_name, main_file.filename().string(),
                 suggested_sources.size());
        out::info("     Reason: {}", reason);
    }

    fmt::print("\n");

    // Let user configure each discovered target
    for (const auto& discovered_target : discovered) {
        std::string accept = get_input(
            fmt::format("Configure target '{}' with main file '{}'? (y/n)",
                       discovered_target.suggested_name, discovered_target.main_file.filename().string()),
            "y");

        if (accept == "y" || accept == "yes" || accept == "Y") {
            Target target;
            target.name = get_input("Target name", discovered_target.suggested_name);
            target.main_file = discovered_target.main_file.string();
            target.output_name = get_input("Output executable name", target.name);

            // Show suggested sources
            out::info("Suggested source files for target '{}':", target.name);
            for (size_t i = 0; i < discovered_target.suggested_sources.size(); ++i) {
                out::info("  {}: {}", i + 1, discovered_target.suggested_sources[i].filename().string());
            }

            if (std::string use_suggested = get_input("Use these suggested sources? (y/n)", "y"); use_suggested == "y" || use_suggested == "yes" || use_suggested == "Y") {
                for (const auto& src : discovered_target.suggested_sources) {
                    target.sources.push_back(src.string());
                }
            } else {
                // Manual source specification, should not get here btw
                out::info("Enter source files manually (space-separated, relative paths):");
                std::string sources_input;
                std::getline(std::cin, sources_input);
                if (!sources_input.empty()) {
                    std::stringstream ss(sources_input);
                    std::string src;
                    while (ss >> src) {
                        target.sources.push_back(src);
                    }
                }
            }

            // Target-specific excludes
            std::string target_excludes = get_input(
                fmt::format("Target-specific exclude patterns for '{}' (optional)", target.name), "");
            if (!target_excludes.empty()) {
                std::stringstream ss(target_excludes);
                std::string pattern;
                while (ss >> pattern) {
                    target.exclude_patterns.push_back(pattern);
                }
            }

            config.targets.push_back(target);
        }
    }

    if (!config.targets.empty()) {
        config.default_target = get_input("Default target", config.targets[0].name);
    }
}

void default_init(Config& config) {

    out::info("Discovering potential build targets to create a default configuration...");

    // Get all source files for discovery
    const auto ignored_dirs = std::unordered_set<std::string>{".git", config.build_dir, CACHE_DIR_NAME};
    const auto all_sources = find_source_files(".", ignored_dirs, config.exclude_patterns);

    auto discovered = TargetDiscovery::discover_targets(all_sources);

    if (discovered.empty()) {
        out::warn("No targets discovered. A default autocc.toml will be created without targets.");
        return;
    }

    out::info("Discovered {} potential target(s). Auto-configuring with defaults.", discovered.size());
    for (size_t i = 0; i < discovered.size(); ++i) {
        const auto&[suggested_name, main_file, suggested_sources, reason] = discovered[i];
        out::info("  {}: Found {} ({}) - {} source files. Reason: {}",
                 i + 1, suggested_name, main_file.filename().string(),
                 suggested_sources.size(), reason);
    }
     fmt::print("\n");

    // Let's automatically configure each discovered target.
    for (const auto& discovered_target : discovered) {
        // The prompt to configure a target defaults to "y". We will act on that.
        out::info("Automatically configuring target '{}'", discovered_target.suggested_name);

        Target target;

        // The prompt for "Target name" defaults to the suggested name.
        target.name = discovered_target.suggested_name;

        target.main_file = discovered_target.main_file.string();

        // The prompt for "Output executable name" defaults to the target name.
        target.output_name = target.name;

        // The prompt "Use these suggested sources?" defaults to "y".
        out::info("  -> Using all {} suggested source files.", discovered_target.suggested_sources.size());
        for (const auto& src : discovered_target.suggested_sources) {
            target.sources.push_back(src.string());
        }

        // The prompt for "Target-specific exclude patterns" defaults to "".
        // So, no target-specific patterns are added by default.

        config.targets.push_back(target);
    }

    // If we created any targets, set the default build target.
    if (!config.targets.empty()) {
        // The prompt for "Default target" defaults to the first target's name.
        config.default_target = config.targets[0].name;
        out::info("Setting default target to '{}'", config.default_target);
    }
}

class CLIHandler {
public:
    struct CommandResult {
        int exit_code;
        bool handled;
    };

    CLIHandler();
    CommandResult handle_command(int argc, char* argv[]);

private:
    struct Command {
        std::string description;
        std::function<int(const std::vector<std::string>&)> handler;
        std::vector<std::string> aliases;
    };

    std::unordered_map<std::string, Command> commands_;

    // Path constants
    const fs::path config_toml_path_ = "autocc.toml";
    const fs::path cache_dir_ = CACHE_DIR_NAME;
    const fs::path base_db_path_ = DB_FILE_NAME;

    // Command handlers
    int handle_default_build() const;
    int handle_target_build(const std::string& target_name) const;
    int handle_fetch(const std::vector<std::string>& args) const;

    static int handle_help(const std::vector<std::string>& args);

    static int handle_version(const std::vector<std::string>& args);
    int handle_autoconfig(const std::vector<std::string>& args) const;
    int handle_edit(const std::vector<std::string>& args) const;
    int handle_setup(const std::vector<std::string>& args) const;

    static int handle_clean(const std::vector<std::string>& args);
    int handle_wipe(const std::vector<std::string>& args) const;

    static int handle_default_install(const std::vector<std::string> &args) ;
    // int handle_default_install(const std::vector<std::string>& args) const; TODO: implement target installation

    // Helper methods
    bool is_project_setup() const;
    bool sync_config_if_needed() const;

    static std::optional<AutoCC> load_autocc_from_cache();
    void register_commands();
};

// cli_handler.cpp
CLIHandler::CLIHandler() {
    register_commands();
}

void CLIHandler::register_commands() {
    commands_["fetch"] = {"Download the base database",
        [this](const auto& args) { return handle_fetch(args); }, {}};

    commands_["help"] = {"Show help information",
        [this](const auto& args) { return handle_help(args); }, {}};

    commands_["version"] = {"Show version information",
        [this](const auto& args) { return handle_version(args); }, {}};

    commands_["autoconfig"] = {"Auto-configure the project",
        [this](const auto& args) { return handle_autoconfig(args); }, {"ac"}};

    commands_["edit"] = {"Edit target source files interactively",
        [this](const auto& args) { return handle_edit(args); }, {"select"}};

    commands_["setup"] = {"Set up the project from configuration",
        [this](const auto& args) { return handle_setup(args); }, {"sync", "sc"}};

    commands_["clean"] = {"Clean build directory",
        [this](const auto& args) { return handle_clean(args); }, {}};

    commands_["wipe"] = {"Remove all autocc files (build dir and cache)",
        [this](const auto& args) { return handle_wipe(args); }, {}};

    commands_["install"] = {"Install default targets",
        [this](const auto& args) { return handle_default_install(args); }, {}};

    // Register aliases
    for (const auto &info: commands_ | std::views::values) {
        for (const auto& alias : info.aliases) {
            commands_[alias] = info;
        }
    }
}

CLIHandler::CommandResult CLIHandler::handle_command(const int argc, char* argv[]) {
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    // No arguments - default build
    if (argc < 2) {
        return {handle_default_build(), true};
    }

    const std::string command = args[1];

    // Check if it's a registered command
    if (const auto it = commands_.find(command); it != commands_.end()) {
        return {it->second.handler(args), true};
    }

    // Otherwise, treat as target name
    return {handle_target_build(command), true};
}

bool CLIHandler::is_project_setup() const {
    return fs::exists(cache_dir_ / CONFIG_FILE_NAME);
}

bool CLIHandler::sync_config_if_needed() const {
    if (!fs::exists(config_toml_path_)) return true;
    if (!is_project_setup()) return false;

    // Check if config is newer than cache
    if (fs::last_write_time(config_toml_path_) <= fs::last_write_time(cache_dir_ / CONFIG_FILE_NAME)) {
        return true; // No sync needed
    }

    const auto config_opt = load_config_from_toml(config_toml_path_);
    if (!config_opt) {
        out::error("Could not load '{}'. Please fix the configuration file.", config_toml_path_);
        return false;
    }

    // Remove old cache
    if (fs::exists(cache_dir_)) {
        try {
            fs::remove_all(cache_dir_);
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to remove cache directory '{}': {}", cache_dir_, e.what());
            return false;
        }
    }

    const AutoCC autocc(*config_opt, false);
    autocc.writeConfigCache();

    // Create empty dependency cache
    std::ofstream out_cache(cache_dir_ / DEP_CACHE_FILE_NAME);
    out_cache << "{}";
    out_cache.close();

    out::success("Configuration synced automatically.");
    return true;
}

std::optional<AutoCC> CLIHandler::load_autocc_from_cache() {
    auto autocc_opt = AutoCC::load_from_cache();
    if (!autocc_opt) {
        out::error("Failed to load project from cache. Try running 'autocc setup' again.");
    }
    return autocc_opt;
}

int CLIHandler::handle_default_build() const {
    if (!is_project_setup()) {
        out::error("Project not set up. Run 'autocc setup' first.");
        out::info("If you have no 'autocc.toml', run 'autocc autoconfig' to create one.");
        return 1;
    }

    if (!sync_config_if_needed()) {
        return 1;
    }

    auto autocc_opt = load_autocc_from_cache();
    if (!autocc_opt) {
        return 1;
    }

    return autocc_opt->build();
}

int CLIHandler::handle_target_build(const std::string& target_name) const {
    if (!is_project_setup()) {
        out::error("Project not set up. Run 'autocc setup' first.");
        return 1;
    }

    auto autocc_opt = load_autocc_from_cache();
    if (!autocc_opt) {
        return 1;
    }

    return autocc_opt->build(target_name);
}

int CLIHandler::handle_fetch(const std::vector<std::string>& args) const {
    Fetcher::download_file(BASE_DB_URL, base_db_path_);
    return 0;
}

int CLIHandler::handle_help(const std::vector<std::string>& args) {
    show_help();
    return 0;
}

int CLIHandler::handle_version(const std::vector<std::string>& args) {
    show_version();
    return 0;
}

int CLIHandler::handle_autoconfig(const std::vector<std::string>& args) const {
    if (!exists(base_db_path_)) {
        Fetcher::download_file(BASE_DB_URL, base_db_path_);
    }

    Config config;

    if (args[2] == "--default") {
        default_init(config);
    } else {
        user_init(config);
    }

    const AutoCC scanner = AutoCC::create_with_auto_detection(std::move(config));
    write_config_to_toml(scanner.config, config_toml_path_);
    return 0;
}

int CLIHandler::handle_edit(const std::vector<std::string>& args) const {
    out::info("Loading configuration for editing...");

    const auto config_opt = load_config_from_toml(config_toml_path_);
    if (!config_opt) {
        out::error("Could not load '{}'. Run 'autocc autoconfig' first.", config_toml_path_);
        return 1;
    }

    Config config = *config_opt;
    if (config.targets.empty()) {
        out::error("No targets found in '{}'. Nothing to edit.", config_toml_path_);
        return 1;
    }

    // Find all source files
    const auto ignored_dirs = std::unordered_set<std::string>{".git", config.build_dir, CACHE_DIR_NAME};
    const auto all_sources = find_source_files(".", ignored_dirs, config.exclude_patterns);

    if (all_sources.empty()) {
        out::error("No source files found in the project. Cannot open editor.");
        return 1;
    }

    // Edit each target
    for (auto& target : config.targets) {
        out::info("Opening TUI editor for target: {}", target.name);

        if (auto new_sources = SourceEditor::run(target, all_sources);
            new_sources.size() != target.sources.size() ||
            !std::is_permutation(target.sources.begin(), target.sources.end(), new_sources.begin())) {

            out::info("Updating sources for target '{}'. Old count: {}, New count: {}.",
                      target.name, target.sources.size(), new_sources.size());
            target.sources = new_sources;
            std::ranges::sort(target.sources);
        } else {
            out::info("No changes made for target '{}'.", target.name);
        }
    }

    out::info("\nAll targets processed.");
    out::warn("This will overwrite your 'autocc.toml' with the new selections.");

    fmt::print(stdout, "{} (y/n)? ", fmt::styled("Do you want to save your changes?", COLOR_PROMPT));
    std::string confirmation;
    std::getline(std::cin, confirmation);

    if (confirmation == "y" || confirmation == "yes") {
        write_config_to_toml(config, config_toml_path_);
        out::info("To apply changes, run 'autocc setup' to sync the new config to the cache.");
    } else {
        out::info("Operation cancelled. 'autocc.toml' was not modified.");
    }
    return 0;
}

int CLIHandler::handle_setup(const std::vector<std::string>& args) const {
    if (!exists(base_db_path_)) {
        out::warn("{} not found!", DB_FILE_NAME);
    }

    const auto config_opt = load_config_from_toml(config_toml_path_);
    if (!config_opt) {
        out::error("Could not load '{}'. Run 'autocc autoconfig' to create it.", config_toml_path_);
        return 1;
    }

    const AutoCC autocc(*config_opt, false);
    autocc.writeConfigCache();

    // Create empty dependency cache
    std::ofstream out_cache(cache_dir_ / DEP_CACHE_FILE_NAME);
    out_cache << "{}";
    out_cache.close();

    out::success("Setup complete. You can now run 'autocc' to build.");
    return 0;
}

int CLIHandler::handle_clean(const std::vector<std::string>& args) {
    const auto autocc_opt = AutoCC::load_from_cache();
    if (!autocc_opt) {
        out::warn("Cache not found, cannot determine build directory. Nothing to clean.");
        return 0;
    }

    const auto& build_dir = autocc_opt->config.build_dir;
    out::info("Cleaning build directory '{}'...", build_dir);

    if (fs::exists(build_dir)) {
        try {
            fs::remove_all(build_dir);
            out::success("Clean complete. Targets and objects removed.");
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to remove build directory '{}': {}", build_dir, e.what());
            return 1;
        }
    }
    return 0;
}

int CLIHandler::handle_wipe(const std::vector<std::string>& args) const {
    Config temp_cfg;
    if (const auto optional = AutoCC::load_from_cache()) {
        temp_cfg = optional->config;
    } else if (const auto toml_optional = load_config_from_toml(config_toml_path_)) {
        temp_cfg = *toml_optional;
    }

    out::warn("Wiping all autocc files (build dir and cache)...");

    for (std::vector<fs::path> const paths_to_remove = {temp_cfg.build_dir, cache_dir_, base_db_path_};
        const auto& path : paths_to_remove) {
        if (!fs::exists(path)) continue;

        try {
            if (fs::is_directory(path)) {
                fs::remove_all(path);
            } else {
                fs::remove(path);
            }
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to remove '{}': {}", path, e.what());
        }
    }

    out::success("Wipe complete. 'autocc.toml' was not removed.");
    return 0;
}

int CLIHandler::handle_default_install(const std::vector<std::string>& args) {
    static_cast<void>(args);
    Config autocc{};
    if (!AutoCC::read_config_cache_static(autocc)) {
        out::error("Failed to read cache.");
        return 1;
    }
    const std::string autoinstall = AUTOINSTALL_SCRIPT_PATH;
    const std::string path = DEFAULT_INSTALL_PATH;
    const std::string full_path = fmt::format("./{}/{}", autocc.build_dir, autocc.default_target);
    std::string cmd;
    if (!fs::exists(autocc.build_dir)) {
        out::error("Project not setup. Cannot install");
        return 1;
    }
    if (fs::exists(autoinstall)) {
        out::info("Using autoinstall script at {}", autoinstall);
        cmd = fmt::format("./{} {} --auto", autoinstall, full_path);
    } else if (isCommandExecutable("/usr/local/bin/autoinstall") || isCommandExecutable("autoinstall")) {
        out::info("Using autoinstall script in system PATH");
        cmd = fmt::format("autoinstall {} --auto", full_path);
    } else {
        cmd = fmt::format("cp {} {}", full_path, path);
    }
    const ::CommandResult res = execute(cmd);
    if (res.exit_code != 0) {
        out::error("Failed to install target {}", autocc.default_target);
        return 1;
    }
    out::success("Installed target {}", autocc.default_target);
    return res.exit_code;
}

int main(const int argc, char* argv[]) {
    CLIHandler cli;
    auto [exit_code, handled] = cli.handle_command(argc, argv);

    if (!handled) {
        out::error("Unknown command. Use 'autocc help' for usage.");
        return 1;
    }

    return exit_code;
}