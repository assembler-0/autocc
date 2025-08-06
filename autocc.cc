// AUTOCC - a simple, fast and intelligent target-based build system written in modern C++
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
#include <future>
#include <shared_mutex>

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "toml.hpp"
#include "log.hpp"
#include "utils.hpp"
#include "json.hpp"
#include "httplib.h"

#ifdef USE_TUI
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;
#endif

#define DATE __DATE__
#define TIME __TIME__
#define VERSION "0.1.6-2"

using json = nlohmann::json;
namespace fs = std::filesystem;
using DependencyMap = std::unordered_map<fs::path, std::unordered_set<fs::path>>;

// --- Constants ---
static constexpr auto CACHE_DIR_NAME = ".autocc_cache";
static constexpr auto CONFIG_CACHE_FILE_NAME = "config.cache"; // THIS SUPPOSED TO 
static constexpr auto CONFIG_FILE_NAME = "autocc.toml";
static constexpr auto DEP_CACHE_FILE_NAME = "deps.cache";
static constexpr auto PCH_HEADER_NAME = "autocc_pch.hpp";
static constexpr auto DB_FILE_NAME = "autocc.base.json";
static constexpr auto AUTOINSTALL_SCRIPT_PATH = "scripts/autoinstall";
static constexpr auto BASE_DB_URL = "https://raw.githubusercontent.com/assembler-0/autocc/refs/heads/main/autocc.base.json";
static constexpr auto PROJECT_ROOT = ".";
static constexpr auto AUTOCC_LOG_FILE_NAME = "autocc.log";
static const std::unordered_set<std::string_view> CPP_EXTENSIONS{".cpp", ".cc", ".cxx", ".c++"};
static const std::unordered_set<std::string_view> ASM_EXTENSIONS{".asm", ".s", ".S"};
static const std::unordered_set<std::string_view> C_EXTENSIONS{".c"};
static const std::unordered_set<std::string_view> HEADER_EXTENSIONS{".h", ".hpp", ".hxx", ".hh"};

// log.hpp
#ifdef LOG_ENABLE_FILE
std::ofstream g_log_file(AUTOCC_LOG_FILE_NAME);
#endif
std::mutex g_output_mutex;

template <>
struct fmt::formatter<fs::path> : formatter<std::string_view> {
    auto format(const fs::path& p, format_context& ctx) const{
        return formatter<std::string_view>::format(p.string(), ctx);
    }
};

struct Target {
    std::string type = "Executable";
    std::string name;
    std::string main_file;
    std::vector<std::string> sources;
    std::string output_name;
    std::vector<std::string> exclude_patterns;
    std::optional<std::string> cflags = "-std=c11";
    std::optional<std::string> cxxflags = "-std=c++20";
    std::optional<std::string> ldflags;
    std::vector<std::string> external_libs; // Per-target external libraries
};

struct Config {
    std::string cc = "clang";
    std::string cxx = "clang++";
    std::string as = "nasm";
    std::string launcher;
    std::string ar = "ar";
    std::string shared = "clang++";
    std::string build_dir = ".autocc_build";
    bool use_pch = true;
    std::vector<std::string> include_dirs;
    std::vector<std::string> exclude_patterns;
    std::vector<Target> targets;
    std::string default_target;
};

class Validation {
public:

    static std::vector<std::string> getAllValidationPattern() {
        static const std::vector<std::string> patterns = {
            "# AUTOCC 0.1.5",
            "# AUTOCC 0.1.6"
        };
        return patterns;
    }

    static std::string getCurrentValidationPattern() {
        return fmt::format("# AUTOCC {}", VERSION);
    }

    static bool isTypeValid(const std::string& str) {
        static const std::vector<std::string> valid = {"Executable", "DLibrary", "SLibrary"};
        return std::ranges::find(valid, str) != valid.end();
    }

    static bool validateVersion() {
        if (Strings::searchPatternInFile(CONFIG_FILE_NAME, getAllValidationPattern())) {
            return true;
        }
        return false;
    }

};

class TargetDiscovery {
public:
    struct DiscoveredTarget {
        std::string suggested_name;
        fs::path main_file;
        std::vector<fs::path> suggested_sources;
        std::string reason; // Why we think this is a target
    };

    static const std::unordered_set<std::string_view>& get_all_source_extensions() {
        static const std::unordered_set<std::string_view> exts = [] {
            std::unordered_set<std::string_view> s;
            s.reserve(CPP_EXTENSIONS.size() + C_EXTENSIONS.size() + ASM_EXTENSIONS.size());
            s.insert(CPP_EXTENSIONS.begin(), CPP_EXTENSIONS.end());
            s.insert(C_EXTENSIONS.begin(), C_EXTENSIONS.end());
            s.insert(ASM_EXTENSIONS.begin(), ASM_EXTENSIONS.end());
            return s;
        }();
        return exts;
    }

    static std::vector<fs::path> find_source_files(const fs::path& dir,
                                              const std::unordered_set<std::string>& ignored_dirs,
                                              const std::vector<std::string>& exclude_patterns = {}) {
        std::vector<fs::path> files;
        std::error_code ec;

        if (!fs::exists(dir, ec)) return files;

        try {
            files.reserve(1000);

            const auto& source_extensions = get_all_source_extensions();

            fs::recursive_directory_iterator iter(dir, fs::directory_options::skip_permission_denied, ec);
            if (ec) return files;

            for (const auto& entry : iter) {
                if (!entry.is_regular_file(ec)) {
                    if (ec) continue;
                }

                const auto& path = entry.path();
                if (const std::string ext = path.extension().string(); !source_extensions.contains(ext)) {
                    continue;
                }

                if (isInIgnoredDirectory(path, ignored_dirs)) {
                    continue;
                }

                if (!exclude_patterns.empty()) {
                    const std::string filename_str = path.filename().string(); // Materialize once
                    bool should_exclude = false;

                    for (const auto& pattern : exclude_patterns) {
                        if (Strings::matches_pattern(filename_str, pattern)) { // Pass const ref safely
                            should_exclude = true;
                            out::warn("Excluding file '{}' (matches pattern '{}')", filename_str, pattern);
                            break;
                        }
                    }

                    if (!should_exclude) {
                        files.emplace_back(path);
                    }
                } else {
                    files.emplace_back(path);
                }
            }
        } catch(const fs::filesystem_error& e) {
            out::warn("Filesystem error while scanning: {}", e.what());
        }
        return files;
    }


    static std::vector<DiscoveredTarget> discover_targets(const std::vector<fs::path>& all_source_files) {
        if (all_source_files.empty()) {
            return {};
        }

        // --- Phase 1: Categorize all files in a single pass ---
        std::vector<fs::path> preferred_mains_candidates;
        std::vector<fs::path> fallback_mains_candidates;
        std::vector<fs::path> test_files;
        std::vector<fs::path> library_files;
        // Micro optimizations
        preferred_mains_candidates.reserve(all_source_files.size() / 4);
        fallback_mains_candidates.reserve(all_source_files.size() / 4);
        test_files.reserve(all_source_files.size() / 4);
        library_files.reserve(all_source_files.size());

        fs::path first_cpp_file;

        auto is_preferred_dir = [](const fs::path& p) {
            const auto dir = p.parent_path().string();
            if (dir == "." || dir == "./" || dir == "src" || dir.ends_with("/src")) return true;
            if (dir.find("include") != std::string::npos) return false;
            if (dir.find("example") != std::string::npos) return false;
            if (dir.find("test") != std::string::npos) return false;
            return true;
        };

        for (const auto& file : all_source_files) {
            if (const std::string filename = file.filename().string(); filename == "main.cpp" || filename == "main.c" || filename == "main.cc") {
                if (is_preferred_dir(file)) {
                    preferred_mains_candidates.push_back(file);
                } else {
                    fallback_mains_candidates.push_back(file);
                }
            } else if (filename.find("test") != std::string::npos) {
                test_files.push_back(file);
            } else {
                library_files.push_back(file);
            }

            if (first_cpp_file.empty()) {
                if (const std::string ext = file.extension().string(); CPP_EXTENSIONS.contains(ext)) {
                    first_cpp_file = file;
                }
            }
        }

        std::vector<DiscoveredTarget> discovered;

        // Helper lambda to find a main file from a list of candidates in parallel
        auto find_main_in_list =
            [&](const std::vector<fs::path>& candidates) -> std::optional<DiscoveredTarget> {

            if (candidates.empty()) return std::nullopt;

            std::vector<std::future<bool>> futures;
            futures.reserve(candidates.size());
            for (const auto& candidate : candidates) {
                futures.push_back(std::async(std::launch::async, &TargetDiscovery::has_main_function, candidate));
            }

            for (size_t i = 0; i < candidates.size(); ++i) {
                if (futures[i].get()) { // Blocks until this future is ready
                    const auto& main_file = candidates[i];
                    DiscoveredTarget target;
                    target.main_file = main_file;
                    target.suggested_name = get_target_name_from_file(main_file);
                    target.reason = "contains main() function";
                    target.suggested_sources.push_back(main_file);
                    target.suggested_sources.insert(target.suggested_sources.end(), library_files.begin(), library_files.end());
                    return target;
                }
            }
            return std::nullopt;
        };

        // --- Phase 2: Look for a main() function in preferred directories (in parallel) ---
        if (auto target = find_main_in_list(preferred_mains_candidates)) {
            discovered.push_back(*target);
        }

        // --- Phase 3: If nothing found, check fallback directories (in parallel) ---
        if (discovered.empty()) {
            if (auto target = find_main_in_list(fallback_mains_candidates)) {
                discovered.push_back(*target);
            }
        }

        // --- Phase 4: If no main executable found, look for a test target ---
        if (discovered.empty() && !test_files.empty()) {
            DiscoveredTarget target;
            // The first test file found becomes the 'main' for the test suite
            target.main_file = test_files[0];
            target.suggested_name = "test";
            // Per original logic, test targets only link against other test files
            target.suggested_sources = test_files;
            target.reason = "test file pattern";
            discovered.push_back(target);
        }

        // --- Phase 5: Fallback - if nothing found, suggest the first C++ file ---
        if (discovered.empty() && !first_cpp_file.empty()) {
            DiscoveredTarget target;
            target.main_file = first_cpp_file;
            target.suggested_name = "main";
            // Fallback includes all sources as it's a best-guess effort
            target.suggested_sources = all_source_files;
            target.reason = "fallback - first C++ file";
            discovered.push_back(target);
        }

        // The simplified logic ensures only one target is discovered, so no de-duplication is needed.
        return discovered;
    }

private:
    // This I/O-bound function is now called in parallel.
    static bool has_main_function(const fs::path& file) {
        std::ifstream stream(file);
        if (!stream.is_open()) return false;

        const std::string content((std::istreambuf_iterator(stream)),
                           std::istreambuf_iterator<char>());

        // Simple regex to find "int main(" with flexible spacing.
        const std::regex main_pattern(R"(\bint\s+main\s*\()");
        return std::regex_search(content, main_pattern);
    }

    // This helper function is unchanged.
    static std::string get_target_name_from_file(const fs::path& file) {
        std::string filename = file.stem().string(); // filename without extension

        // Clean up common patterns
        if (filename == "main") return "main";
        if (filename.starts_with("test")) return "test";
        if (filename.ends_with("_main")) return filename.substr(0, filename.size() - 5);
        if (filename.ends_with("_test")) return filename.substr(0, filename.size() - 5) + "_test";

        return filename;
    }

};

#ifdef USE_TUI
class SourceEditor {
public:

    static std::string ensure_relative_prefix(const std::string_view path) {
        if (path.starts_with("./") || path.starts_with("../") || path.starts_with("/")) {
            return std::string(path);
        }
        return "./" + std::string(path);
    }
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
            // Ensure a path starts with ./ for consistency
            if (!relative_path.starts_with("./") && !relative_path.starts_with("../")) {
                relative_path = ensure_relative_prefix(relative_path);
            }
            base_entries.push_back(relative_path);
        }
        std::ranges::sort(base_entries); // Keep the list sorted for usability.

        std::string main_file_normalized = target.main_file;
        if (!main_file_normalized.starts_with("./") && !main_file_normalized.starts_with("../")) {
             main_file_normalized = "./" + main_file_normalized;
        }

        // Remove main_file from the selector (it's auto-included)
        if (const auto main_file_it = std::ranges::find(base_entries, main_file_normalized); main_file_it != base_entries.end()) {
            base_entries.erase(main_file_it);
        }

        std::vector states(base_entries.size(), 0);

        // Pre-select files that are already in the target's source list
        std::unordered_set<std::string> initial_selection;
        for (const auto& source : target.sources) {
            std::string normalized_source = source;
            if (!normalized_source.starts_with("./") && !normalized_source.starts_with("../")) {
                normalized_source = ensure_relative_prefix(normalized_source);
            }
            if (normalized_source != main_file_normalized) {
                initial_selection.insert(normalized_source);
            }
        }

        for (size_t i = 0; i < base_entries.size(); ++i) {
            if (initial_selection.contains(base_entries[i])) {
                states[i] = 1; // 1 mean checked
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
                if (selected < states.size()) {
                    states[selected] = 1 - states[selected]; // Toggle
                    update_entries(); // Update display entries
                }
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

        // Lay out the components
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

        screen.Loop(main_renderer);

        // --- 4. Process the results ---
        std::vector<std::string> final_selection;
        final_selection.push_back(target.main_file); // Always include the main file.

        for (size_t i = 0; i < base_entries.size(); ++i) {
            if (states[i] == 1) { // If the checkbox is checked
                final_selection.push_back(base_entries[i]);
            }
        }

        return final_selection;
    }
};
#endif

class Configuration {
public:
    static void write_config_to_toml(const Config& config, const fs::path& toml_path) {
    auto includes_arr = toml::array{};
    for (const auto& dir : config.include_dirs) {
        includes_arr.push_back(dir);
    }

    auto exclude_arr = toml::array{};
    for (const auto& pattern : config.exclude_patterns) {
        exclude_arr.push_back(pattern);
    }

    auto targets_arr = toml::array{};
    for (const auto&[type, name, main_file, sources, output_name, exclude_patterns, cflags, cxxflags, ldflags, external_libs] : config.targets) {
        auto sources_arr = toml::array{};
        for (const auto& src : sources) sources_arr.push_back(src);

        auto target_exclude_arr = toml::array{};
        for (const auto& pattern : exclude_patterns) target_exclude_arr.push_back(pattern);

        auto libs_arr = toml::array{};
        for (const auto& lib : external_libs) libs_arr.push_back(lib);

        auto target_tbl = toml::table{
            {"type", type},
            {"name", name},
            {"main_file", main_file},
            {"sources", sources_arr},
            {"output_name", output_name},
            {"exclude_patterns", target_exclude_arr},
            {"external_libs", libs_arr}
        };
        if (cflags) target_tbl.insert_or_assign("cflags", *cflags);
        if (cxxflags) target_tbl.insert_or_assign("cxxflags", *cxxflags);
        if (ldflags) target_tbl.insert_or_assign("ldflags", *ldflags);

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
            {"as", config.as},
            {"launcher", config.launcher},
            {"ar", config.ar},
            {"sl", config.shared}
        }},

        {"features", toml::table{
            {"use_pch", config.use_pch}
        }},
        {"paths", toml::table{
            {"include_dirs", includes_arr},
            {"exclude_patterns", exclude_arr}
        }},
        {"targets", targets_arr}
    };

    std::ofstream file(toml_path);
    if (!file.is_open()) {
        out::error("Failed to open '{}' for writing configuration.", toml_path);
        return;
    }

    file << fmt::format("# AUTOCC {}\n", VERSION);
    file << fmt::format("# CONFIGURATION FILE 'autocc.toml' IS WRITTEN BY AUTOCC {}, MAKE SURE YOU HAVE AN APPROPRIATE AUTOCC BUILD.\n", VERSION);
    file << fmt::format("# COPYRIGHT (C) assembler-0 2025\n", VERSION);
    file << tbl;
    out::success("Configuration saved to '{}'.", toml_path);
}

    static void validate_config(Config& config) {
        std::unordered_set<std::string> names, outputs;
        for (const auto& t : config.targets) {
            if (t.name.empty()) out::warn("A target has an empty name.");
            if (t.main_file.empty()) out::warn("Target '{}' has an empty main_file.", t.name);
            if (t.sources.empty()) out::warn("Target '{}' has no sources.", t.name);
            if (!names.insert(t.name).second) out::error("Duplicate target name '{}'.", t.name);
            if (!outputs.insert(t.output_name).second) out::warn("Duplicate output_name '{}'.", t.output_name);
        }
        if (!config.default_target.empty() &&
            std::ranges::none_of(config.targets, [&](const Target& t){ return t.name == config.default_target; }))
            out::warn("default_target '{}' does not match any target name.", config.default_target);
    }

    static std::optional<Config> read_config_from_toml(const fs::path& toml_path) {
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
            config.default_target = get_or(tbl["project"]["default_target"].as_string(), "");

            config.cxx = get_or(tbl["compilers"]["cxx"].as_string(), config.cxx);
            config.cc = get_or(tbl["compilers"]["cc"].as_string(), config.cc);
            config.as = get_or(tbl["compilers"]["as"].as_string(), config.as);
            config.launcher = get_or(tbl["compilers"]["launcher"].as_string(), config.launcher);
            config.ar = get_or(tbl["compilers"]["ar"].as_string(), config.ar);
            config.shared = get_or(tbl["compilers"]["sl"].as_string(), config.shared);
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

            if (auto* excludes = tbl["paths"]["exclude_patterns"].as_array()) {
                for (const auto& elem : *excludes) { config.exclude_patterns.emplace_back(elem.value_or("")); }
            }

            if (auto* targets_arr = tbl["targets"].as_array()) {
                for (const auto& target_node : *targets_arr) {
                    if (auto* target_tbl = target_node.as_table()) {
                        Target target;
                        target.type = get_or((*target_tbl)["type"].as_string(), target.type);
                        target.name = get_or((*target_tbl)["name"].as_string(), target.name);
                        target.main_file = get_or((*target_tbl)["main_file"].as_string(), target.main_file);
                        target.output_name = get_or((*target_tbl)["output_name"].as_string(), target.output_name);

                        if (auto* node = (*target_tbl)["cflags"].as_string()) target.cflags = node->get();
                        if (auto* node = (*target_tbl)["cxxflags"].as_string()) target.cxxflags = node->get();
                        if (auto* node = (*target_tbl)["ldflags"].as_string()) target.ldflags = node->get();

                        if (auto* sources = (*target_tbl)["sources"].as_array()) {
                            for (const auto& elem : *sources) target.sources.emplace_back(elem.value_or(""));
                        }
                        if (auto* target_excludes = (*target_tbl)["exclude_patterns"].as_array()) {
                            for (const auto& elem : *target_excludes) target.exclude_patterns.emplace_back(elem.value_or(""));
                        }
                        if (auto* libs = (*target_tbl)["external_libs"].as_array()) {
                            for (const auto& elem : *libs) target.external_libs.emplace_back(elem.value_or(""));
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
};

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

    // Optimized data structures
    std::unordered_map<std::string, DetectionRule> detectionMap;
    std::unordered_map<std::string, std::string> pkg_cache;
    mutable std::shared_mutex cache_mutex;

    // Pre-computed optimization structures
    std::vector<std::pair<std::string, const DetectionRule*>> sorted_rules;
    bool rules_sorted = false;

    void load_rules_from_file(const fs::path& db_path) {
        if (!fs::exists(db_path)) {
            out::warn("Library database '{}' not found. Attempting to download...", db_path);
            if (!download_and_parse(db_path)) {
                out::error("Failed to download library database. Library detection will be limited.");
                return;
            }
        } else {
            if (!parse_database(db_path)) {
                // Try re-downloading if parsing fails
                out::warn("Failed to parse existing database. Attempting to re-download...");
                try {
                    fs::remove(db_path);
                } catch (const fs::filesystem_error&) {}

                if (!download_and_parse(db_path)) {
                    out::error("Failed to re-download library database. Library detection will be limited.");
                }
            }
        }

        // Pre-sort rules by header length (longest first) for better matching
        optimize_rules();
    }

    bool download_and_parse(const fs::path& db_path) {
        if (!Fetcher::download_file(BASE_DB_URL, db_path)) {
            return false;
        }
        return parse_database(db_path);
    }

    bool parse_database(const fs::path& db_path) {
        try {
            std::ifstream f(db_path);
            if (!f.is_open()) {
                out::error("Failed to open library database '{}'.", db_path);
                return false;
            }

            json data = json::parse(f);
            if (!data.contains("libraries") || !data["libraries"].is_object()) {
                out::error("Invalid database format: missing 'libraries' object");
                return false;
            }

            detectionMap.clear();
            detectionMap.reserve(data["libraries"].size());

            for (auto& [header, rule_json] : data["libraries"].items()) {
                if (!rule_json.is_object()) continue;

                DetectionRule rule;
                if (rule_json.contains("direct_libs") && rule_json["direct_libs"].is_array()) {
                    auto libs = rule_json["direct_libs"].get<std::vector<std::string>>();
                    rule.direct_libs.reserve(libs.size());
                    rule.direct_libs = std::move(libs);
                }
                if (rule_json.contains("pkg_configs") && rule_json["pkg_configs"].is_array()) {
                    auto pkgs = rule_json["pkg_configs"].get<std::vector<std::string>>();
                    rule.pkg_configs.reserve(pkgs.size());
                    rule.pkg_configs = std::move(pkgs);
                }
                detectionMap[header] = std::move(rule);
            }

            out::info("Loaded {} library detection rules.", detectionMap.size());
            return true;

        } catch (const json::parse_error& e) {
            out::error("Failed to parse library database '{}': {}", db_path, e.what());
            return false;
        }
    }

    void optimize_rules() {
        sorted_rules.clear();
        sorted_rules.reserve(detectionMap.size());

        for (const auto& [header, rule] : detectionMap) {
            sorted_rules.emplace_back(header, &rule);
        }

        // Sort by header length (longest first) for better matching efficiency
        std::ranges::sort(sorted_rules,
                          [](const auto& a, const auto& b) {
                              return a.first.length() > b.first.length();
                          });

        rules_sorted = true;
    }

public:
    LibraryDetector() {
        load_rules_from_file(DB_FILE_NAME);
    }


    void detect(const std::vector<std::string>& includes, Target& target) {
        if (!rules_sorted) optimize_rules();

        // Use sets for O(1) duplicate detection
        std::unordered_set collected_libs_set(target.external_libs.begin(), target.external_libs.end());
        std::unordered_set<std::string> processed_pkg_configs;
        std::unordered_set<std::string> matched_headers; // Avoid it if it is re-processing same headers

        // Pre-allocate result containers
        std::vector<std::string> pkg_configs_to_process;
        pkg_configs_to_process.reserve(includes.size());

        // First pass: collect all matches without executing pkg-config
        for (const auto& include : includes) {
            if (matched_headers.contains(include)) continue;

            for (const auto& [header_signature, rule_ptr] : sorted_rules) {
                if (include.find(header_signature) != std::string::npos) {
                    if (isLikelyFalsePositive(include, header_signature)) { // remove if encounter bugs -- 05/08/2025 6:46
                        continue;
                    }
                    matched_headers.insert(include);

                    // Add direct libraries
                    for (const auto& lib : rule_ptr->direct_libs) {
                        collected_libs_set.insert(lib);
                    }

                    // Collect unique pkg-configs for batch processing
                    for (const auto& pkg_name : rule_ptr->pkg_configs) {
                        if (!processed_pkg_configs.contains(pkg_name)) {
                            pkg_configs_to_process.push_back(pkg_name);
                            processed_pkg_configs.insert(pkg_name);
                        }
                    }
                    break; // Stop at the first match for this include
                }
            }
        }

        // Second pass: batch process pkg-config calls
        if (!pkg_configs_to_process.empty()) {
            processPkgConfigs(pkg_configs_to_process, collected_libs_set, target);
        }

        // Convert set back to vector efficiently
        target.external_libs.clear();
        target.external_libs.reserve(collected_libs_set.size());
        target.external_libs.assign(collected_libs_set.begin(), collected_libs_set.end());
    }

private:

    static bool isLikelyFalsePositive(const std::string& include, const std::string& header) {
        if (include.length() <= header.length()) return false;

        const size_t pos = include.find(header);
        if (pos == std::string::npos) return false;

        // Allow path separators before/after
        const bool valid_before = pos == 0 || include[pos - 1] == '/' || include[pos - 1] == '\\';
        const bool valid_after = pos + header.length() == include.length() ||
                           !std::isalnum(include[pos + header.length()]);

        return !(valid_before && valid_after);
    }


    void processPkgConfigs(const std::vector<std::string>& pkg_configs,
                          std::unordered_set<std::string>& collected_libs_set,
                          Target& target) {

        const size_t num_threads = std::min(pkg_configs.size(),
                                           static_cast<size_t>(std::thread::hardware_concurrency()));

        if (num_threads <= 1 || pkg_configs.size() < 3) {
            // Single-threaded for small workloads
            for (const auto& pkg_name : pkg_configs) {
                processSinglePkgConfig(pkg_name, collected_libs_set, target);
            }
            return;
        }

        std::vector<std::thread> threads;
        std::atomic<size_t> next_pkg_index{0};

        // Thread-local storage for results
        struct ThreadResults {
            std::unordered_set<std::string> libs;
            std::string cflags;
            std::string ldflags;
        };

        std::vector<ThreadResults> thread_results(num_threads);

        for (size_t t = 0; t < num_threads; ++t) {
            threads.emplace_back([&, t] {
                size_t pkg_index;
                auto&[libs, cflags, ldflags] = thread_results[t];

                while ((pkg_index = next_pkg_index.fetch_add(1)) < pkg_configs.size()) {
                    const auto& pkg_name = pkg_configs[pkg_index];

                    if (const auto pkg_result = getPkgConfigFlags(pkg_name); !pkg_result.empty()) {
                        parsePkgConfigOutput(pkg_result, libs, cflags, ldflags);
                    #ifdef VERBOSE
                        out::info("Found dependency '{}', adding flags via pkg-config.", pkg_name);
                    #endif
                    } else {
                    #ifdef VERBOSE
                        out::warn("Found include for '{}' but 'pkg-config {}' failed. Is it installed?", pkg_name, pkg_name);
                    #endif
                    }
                }
            });
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }

        // Merge results from all threads
        std::string combined_cflags, combined_ldflags;
        for (const auto&[libs, cflags, ldflags] : thread_results) {
            collected_libs_set.insert(libs.begin(), libs.end());
            if (!cflags.empty()) {
                combined_cflags += cflags + " ";
            }
            if (!ldflags.empty()) {
                combined_ldflags += ldflags + " ";
            }
        }

        // Apply combined flags to the target
        if (!combined_cflags.empty()) {
            combined_cflags.pop_back(); // Remove trailing space
            if (target.cxxflags) *target.cxxflags += " " + combined_cflags;
            else target.cxxflags = combined_cflags;
            if (target.cflags) *target.cflags += " " + combined_cflags;
            else target.cflags = combined_cflags;
        }

        if (!combined_ldflags.empty()) {
            combined_ldflags.pop_back(); // Remove trailing space
            if (target.ldflags) *target.ldflags += " " + combined_ldflags;
            else target.ldflags = combined_ldflags;
        }
    }

    void processSinglePkgConfig(const std::string& pkg_name,
                               std::unordered_set<std::string>& collected_libs_set,
                               Target& target) {
        if (const auto pkg_result = getPkgConfigFlags(pkg_name); !pkg_result.empty()) {
            std::unordered_set<std::string> local_libs;
            std::string additional_cflags, additional_ldflags;

            parsePkgConfigOutput(pkg_result, local_libs, additional_cflags, additional_ldflags);
            collected_libs_set.insert(local_libs.begin(), local_libs.end());

            // Apply flags immediately for a single-threaded case
            if (!additional_cflags.empty()) {
                if (target.cxxflags) *target.cxxflags += " " + additional_cflags;
                else target.cxxflags = additional_cflags;
                if (target.cflags) *target.cflags += " " + additional_cflags;
                else target.cflags = additional_cflags;
            }

            if (!additional_ldflags.empty()) {
                if (target.ldflags) *target.ldflags += " " + additional_ldflags;
                else target.ldflags = additional_ldflags;
            }
        #ifdef VERBOSE
            out::info("Found dependency '{}', adding flags via pkg-config.", pkg_name);
        #endif
        } else {
        #ifdef VERBOSE
            out::warn("Found include for '{}' but 'pkg-config {}' failed. Is it installed?", pkg_name, pkg_name);
        #endif
        }
    }

    // Optimized version using sets instead of vectors for O(1) duplicate detection
    static void parsePkgConfigOutput(const std::string& pkg_output,
                                   std::unordered_set<std::string>& collected_libs,
                                   std::string& cflags,
                                   std::string& ldflags) {
        std::istringstream iss(pkg_output);
        std::string token;

        // Pre-allocate string space to reduce reallocations
        cflags.reserve(pkg_output.length() / 2);
        ldflags.reserve(pkg_output.length() / 2);

        while (iss >> token) {
            if (token.starts_with("-l")) {
                collected_libs.insert(token);
            } else if (token.starts_with("-L") || token.starts_with("-Wl,") ||
                      token.starts_with("-T") || token.starts_with("--dynamic-linker") ||
                      token.starts_with("-rpath")) {
                if (!ldflags.empty()) ldflags += " ";
                ldflags += token;
            } else {
                if (!cflags.empty()) cflags += " ";
                cflags += token;
            }
        }
    }

    std::string getPkgConfigFlags(const std::string& package) {
        // Thread-safe cache access
        {
            std::shared_lock lock(cache_mutex);
            if (const auto it = pkg_cache.find(package); it != pkg_cache.end()) {
                return it->second;
            }
        }

        const std::string cmd = fmt::format("pkg-config --libs --cflags {}", package);
        auto [exit_code, stdout_output, stderr_output] = Execution::execute(cmd);

        std::string result;
        if (exit_code == 0) {
            result = std::move(stdout_output);
            if (!result.empty() && result.back() == '\n') {
                result.pop_back();
            }
        } else {
            if (stderr_output.find("not found") != std::string::npos) {
                out::warn("pkg-config for '{}' failed: Package not found. Is it installed?", package);
            } else if (!stderr_output.empty()) {
                out::warn("pkg-config for '{}' failed with error: {}", package, stderr_output);
            } else {
                out::warn("pkg-config for '{}' failed with unknown error.", package);
            }
        }

        // Thread-safe cache update
        {
            std::unique_lock lock(cache_mutex);
            pkg_cache[package] = result;
        }

        return result;
    }
};

class IncludeParser {

    static inline const std::regex include_regex{R"_(\s*#\s*include\s*(?:<([^>]+)>|"([^"]+)"))_"};

    // Cache for file contents and header paths
    mutable std::unordered_map<fs::path, std::vector<std::string>> file_cache;
    mutable std::unordered_map<std::string, fs::path> header_path_cache;
    mutable std::shared_mutex cache_mutex;

    // Read a file once and cache the lines
    static std::vector<std::string> getFileLines(const fs::path& file_path) {
        std::ifstream file_stream(file_path);
        if (!file_stream.is_open()) return {};

        std::vector<std::string> lines;
        std::string line;

        // Early detection of generated files
        for (int i = 0; i < 10 && std::getline(file_stream, line); ++i) {
            if (line.find("auto-generated") != std::string::npos ||
                line.find("DO NOT EDIT") != std::string::npos) {
                return {}; // Skip entirely
                }
            lines.push_back(line);
        }

        // Continue reading if not generated
        while (std::getline(file_stream, line)) {
            lines.push_back(line);
        }
        return lines;
    }

    static fs::path findHeader(const std::string& header_name, const fs::path& relative_to, const std::vector<std::string>& include_dirs) {
        fs::path potential_path = relative_to / header_name;
        if (fs::exists(potential_path)) return fs::canonical(potential_path);
        for (const auto& dir_flag : include_dirs) {
            // Handle both bare paths and -I flag for convenience
            fs::path base_dir = dir_flag.starts_with("-I") ? dir_flag.substr(2) : dir_flag;
            potential_path = base_dir / header_name;
            if (fs::exists(potential_path)) return fs::canonical(potential_path);
        }
        return {};
    }

    fs::path findHeaderCached(const std::string& header_name, const fs::path& relative_to, const std::vector<std::string>& include_dirs) const {
        const std::string cache_key = header_name + "|" + relative_to.string();

        {
            std::shared_lock lock(cache_mutex);
            if (const auto it = header_path_cache.find(cache_key); it != header_path_cache.end()) {
                return it->second;
            }
        }

        fs::path result = findHeader(header_name, relative_to, include_dirs);

        {
            std::unique_lock lock(cache_mutex);
            header_path_cache[cache_key] = result;
        }
        return result;
    }

    // Extract includes from cached file lines
    static std::vector<std::pair<std::string, bool>> extractIncludes(const std::vector<std::string>& lines) {
        std::vector<std::pair<std::string, bool>> includes;
        includes.reserve(lines.size() / 10); // Estimate

        for (const auto& line : lines) {
            if (std::smatch matches; std::regex_search(line, matches, include_regex)) {
                if (matches[1].matched) {
                    includes.emplace_back(matches[1].str(), false); // system include
                } else if (matches[2].matched) {
                    includes.emplace_back(matches[2].str(), true);  // locally include
                }
            }
        }
        return includes;
    }

    std::unordered_set<fs::path> parseSingleFileDependencies(const fs::path& src_file, const std::vector<std::string>& include_dirs) const {
        std::unordered_set<fs::path> dependencies;
        std::vector files_to_scan = {src_file};
        std::unordered_set<fs::path> scanned_files;

        while (!files_to_scan.empty()) {
            fs::path current_file = files_to_scan.back();
            files_to_scan.pop_back();

            if (scanned_files.contains(current_file)) continue;
            scanned_files.insert(current_file);

            auto lines = getFileLines(current_file);
            if (lines.empty()) {
                out::warn("Could not open file for dependency parsing: {}", current_file);
                continue;
            }

            for (auto includes = extractIncludes(lines); const auto& [header_name, is_local] : includes) {
                if (is_local) {
                    if (fs::path header_path = findHeaderCached(header_name, current_file.parent_path(), include_dirs); !header_path.empty()) {
                        dependencies.insert(header_path);
                        files_to_scan.push_back(header_path);
                    }
                }
            }
        }

        return dependencies;
    }

    static std::vector<std::string> extractIncludesFromString(const std::string& content) {
        std::vector<std::string> includes;
        std::istringstream stream(content);
        std::string line;

        while (std::getline(stream, line)) {
            if (std::smatch matches; std::regex_search(line, matches, include_regex)) {
                if (matches[1].matched) {
                    includes.push_back(matches[1].str());
                } else if (matches[2].matched) {
                    includes.push_back(matches[2].str());
                }
            }
        }
        return includes;
    }

public:
    [[nodiscard]] DependencyMap parseSourceDependencies(const std::vector<fs::path>& sourceFiles, const std::vector<std::string>& include_dirs) const {
        DependencyMap dep_map;
        const size_t num_threads = std::min(sourceFiles.size(), static_cast<size_t>(std::thread::hardware_concurrency()));

        if (num_threads <= 1 || sourceFiles.size() < 4) {
            // Single-threaded for small workloads or single-core systems
            for (const auto& src_file : sourceFiles) {
                dep_map[src_file] = parseSingleFileDependencies(src_file, include_dirs);
            }
            return dep_map;
        }

        // Multithreaded processing
        std::mutex dep_map_mutex;
        std::vector<std::thread> threads;
        std::atomic<size_t> next_file_index{0};

        for (size_t t = 0; t < num_threads; ++t) {
            threads.emplace_back([&] {
                size_t file_index;
                while ((file_index = next_file_index.fetch_add(1)) < sourceFiles.size()) {
                    const auto& src_file = sourceFiles[file_index];
                    auto dependencies = parseSingleFileDependencies(src_file, include_dirs);

                    std::lock_guard lock(dep_map_mutex);
                    dep_map[src_file] = std::move(dependencies);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        return dep_map;
    }

    std::vector<std::string> getAllProjectIncludes(const std::vector<fs::path> &sourceFiles,
                                             const std::unordered_set<std::string> &ignored_dirs) const {

    #ifdef AGGRESSIVE
        out::warn("THIS BUILD OF AUTOCC HAVE 'AGGRESSIVE' OPTION ENABLED.");
        // PHASE 1: Bulk collect all files to scan
        std::vector<fs::path> files_to_scan;
        files_to_scan.reserve(sourceFiles.size() + 10000);

        // Add source files
        files_to_scan.insert(files_to_scan.end(), sourceFiles.begin(), sourceFiles.end());

        // Add header files with aggressive filtering
        for (const auto& entry : fs::recursive_directory_iterator(".", fs::directory_options::skip_permission_denied)) {
            if (isInIgnoredDirectory(entry.path(), ignored_dirs)) continue;

            if (entry.is_regular_file()) {
                const auto ext = entry.path().extension().string();
                if (HEADER_EXTENSIONS.contains(ext)) {
                    if (std::error_code ec; entry.file_size(ec) > 10'000) {
                        // Your brilliant content peek optimization
                        std::ifstream peek(entry.path());
                        std::string first_chunk(1000, '\0');
                        peek.read(first_chunk.data(), 1000);
                        if (first_chunk.find("#include <") == std::string::npos) {
                            continue;
                        }
                    }
                    files_to_scan.push_back(entry.path());
                }
            }
        }

        // PHASE 2: Bulk load ALL files into RAM using memory mapping
        std::unordered_map<fs::path, std::string> file_cache;
        file_cache.reserve(files_to_scan.size());

        const size_t num_threads = std::thread::hardware_concurrency() * 2; // Oversubscribe!
        std::mutex cache_mutex;

        // Parallel bulk loading
        std::vector<std::thread> loaders;
        std::atomic<size_t> file_index{0};

        for (size_t t = 0; t < num_threads; ++t) {
            loaders.emplace_back([&] {
                size_t idx;
                while ((idx = file_index.fetch_add(1)) < files_to_scan.size()) {
                    const auto& file_path = files_to_scan[idx];
                    try {
                        MemoryMappedFile mmf(file_path);
                        std::string content(mmf.content());

                        std::lock_guard lock(cache_mutex);
                        file_cache[file_path] = std::move(content);
                    } catch (...) {
                        // Fallback to regular file reading
                        auto lines = getFileLines(file_path);
                        std::string content;
                        for (const auto& line : lines) {
                            content += line + '\n';
                        }
                        std::lock_guard lock(cache_mutex);
                        file_cache[file_path] = std::move(content);
                    }
                }
            });
        }

        for (auto& loader : loaders) {
            loader.join();
        }

        // PHASE 3: Process from RAM (lightning fast)
        std::unordered_set<std::string> unique_includes;
        unique_includes.reserve(100000); // Go big!

        std::vector<std::future<std::unordered_set<std::string>>> futures;
        const size_t chunk_size = file_cache.size() / num_threads + 1;

        auto cache_iter = file_cache.begin();
        for (size_t t = 0; t < num_threads && cache_iter != file_cache.end(); ++t) {
            auto chunk_start = cache_iter;
            auto chunk_end = chunk_start;
            std::advance(chunk_end, std::min(chunk_size, static_cast<size_t>(std::distance(chunk_start, file_cache.end()))));
            cache_iter = chunk_end;

            futures.push_back(std::async(std::launch::async, [chunk_start, chunk_end, this] {
                std::unordered_set<std::string> local_includes;
                for (auto it = chunk_start; it != chunk_end; ++it) {
                    const auto& content = it->second;
                    // Extract includes directly from string content
                    for (auto includes = extractIncludesFromString(content); const auto& include : includes) {
                        local_includes.insert(include);
                    }
                }
                return local_includes;
            }));
        }

        // Merge results
        for (auto& future : futures) {
            auto local_set = future.get();
            unique_includes.insert(local_set.begin(), local_set.end());
        }

        return {unique_includes.begin(), unique_includes.end()};

    #else
        std::unordered_set<std::string> unique_includes;

        // 1. FILTER FILES FIRST - Skip huge files
        std::vector<fs::path> files_to_scan;
        files_to_scan.reserve(sourceFiles.size() + 5000);

        // Add source files
        for (const auto& src : sourceFiles) {
            files_to_scan.push_back(src);
        }

        // Add ONLY small header files
        for (const auto& entry : fs::recursive_directory_iterator(".", fs::directory_options::skip_permission_denied)) {
            if (isInIgnoredDirectory(entry.path(), ignored_dirs)) continue;

            if (entry.is_regular_file()) {
                const auto ext = entry.path().extension().string();
                if (HEADER_EXTENSIONS.contains(ext)) {
                    // SKIP HUGE FILES
                    if (std::error_code ec; entry.file_size(ec) > 50'000) continue; // Skip files > 70KB
                    if (const std::string filename = entry.path().filename().string();
                        filename.ends_with("_generated.h") ||
                        filename.ends_with(".pb.h") ||        // Protobuf
                        filename.starts_with("moc_") ||       // Qt MOC
                        filename.contains("_autogen")) {
                        continue;
                    }
                    if (std::error_code ec; entry.file_size(ec) > 10'000) {
                        // Quick peek for system includes
                        std::ifstream peek(entry.path());
                        std::string first_chunk(1000, '\0');
                        peek.read(first_chunk.data(), 1000);

                        if (first_chunk.find("#include <") == std::string::npos) {
                            continue; // No system includes, skip
                        }
                    }
                    files_to_scan.push_back(entry.path());
                }
            }
        }

        // 2. BETTER PARALLELIZATION
        const size_t num_threads = std::thread::hardware_concurrency();
        const size_t chunk_size = files_to_scan.size() / num_threads + 1;

        std::vector<std::future<std::unordered_set<std::string>>> futures;

        for (size_t i = 0; i < num_threads; ++i) {
            size_t start = i * chunk_size;
            size_t end = std::min(start + chunk_size, files_to_scan.size());

            if (start >= end) break;

            futures.push_back(std::async(std::launch::async, [this, start, end, &files_to_scan] {
                std::unordered_set<std::string> local_includes;
                for (size_t j = start; j < end; ++j) {
                    auto lines = getFileLines(files_to_scan[j]);
                    for (auto includes = extractIncludes(lines); const auto &include: includes | std::views::keys) {
                        local_includes.insert(include);
                    }
                }
                return local_includes;
            }));
        }

        // Merge results
        for (auto& future : futures) {
            auto local_set = future.get();
            unique_includes.insert(local_set.begin(), local_set.end());
        }

        return {unique_includes.begin(), unique_includes.end()};
    #endif
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
        return {".git", config.build_dir, CACHE_DIR_NAME};
    }

    void scanLocalHeaders() {
        const auto ignored_dirs_set = getIgnoredDirs();

        // Use thread-safe containers for parallel processing
        std::vector<fs::path> all_entries;
        std::unordered_set<fs::path> header_dirs_set; // Use set for O(1) deduplication

        // First pass: collect all filesystem entries in a single traversal
        try {
            all_entries.reserve(10000); // Pre-allocate for typical project sizes

            for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
                try {
                    if (!entry.exists()) continue;
                    all_entries.push_back(entry.path());
                } catch (const fs::filesystem_error& e) {
                    out::warn("Skipping file due to filesystem error: {}", e.what());
                }
            }
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to scan for headers: {}", e.what());
            return;
        }

        // Early exit if no files found
        if (all_entries.empty()) {
            return;
        }

        // Pre-compute ignored directory components for faster checking
        std::unordered_set<std::string> ignored_components;
        for (const auto& dir : ignored_dirs_set) {
            ignored_components.insert(dir);
            // Also add with trailing slash variants that might appear in paths
            ignored_components.insert(dir + "/");
            ignored_components.insert(dir + "\\");
        }

        // Parallel processing of entries
        const size_t num_threads = std::min(all_entries.size() / 100 + 1, // At least 100 files per thread
                                           static_cast<size_t>(std::thread::hardware_concurrency()));

        processEntries(all_entries, ignored_components, header_dirs_set, num_threads);

        // Efficiently merge with existing include directories
        std::unordered_set<std::string> final_includes;
        final_includes.reserve(config.include_dirs.size() + header_dirs_set.size());

        // Add existing config include dirs
        for (const auto& dir : config.include_dirs) {
            final_includes.insert(dir);
        }

        // Add discovered header directories
        for (const auto& dir : header_dirs_set) {
            try {
                fs::path rel = fs::relative(dir, root);
                final_includes.insert(rel.empty() ? dir.string() : rel.string());
            } catch (const fs::filesystem_error&) {
                // Fallback to absolute path if relative fails
                final_includes.insert(dir.string());
            }
        }

        // Assign results efficiently
        config.include_dirs.clear();
        config.include_dirs.reserve(final_includes.size());
        config.include_dirs.assign(final_includes.begin(), final_includes.end());
    }

    void detectLibraries() {
        const auto ignored_dirs = getIgnoredDirs();
        const auto all_includes = include_parser.getAllProjectIncludes(source_files, ignored_dirs);

        #ifdef AGGRESSIVE
        // PARALLEL TARGET PROCESSING
        const size_t num_threads = std::min(config.targets.size(),
                                           static_cast<size_t>(std::thread::hardware_concurrency()));

        if (num_threads <= 1 || config.targets.size() < 2) {
            // Fallback to sequential
            for (auto& target : config.targets) {
                lib_detector.detect(all_includes, target);
            }
            return;
        }

        // Parallel detection for all targets
        std::vector<std::thread> workers;
        std::atomic<size_t> target_index{0};

        for (size_t t = 0; t < num_threads; ++t) {
            workers.emplace_back([&] {
                size_t idx;
                while ((idx = target_index.fetch_add(1)) < config.targets.size()) {
                    lib_detector.detect(all_includes, config.targets[idx]);
                }
            });
        }

        for (auto& worker : workers) {
            worker.join();
        }
        #else
        // Original sequential version
        for (auto& target : config.targets) {
            lib_detector.detect(all_includes, target);
        }
        #endif
    }


    std::string generatePCH(const fs::path &build_path, const std::string &target_cxxflags) {
    out::info("Analyzing for Pre-Compiled Header generation...");

    #ifdef AGGRESSIVE
        // PHASE 1: Parallel include analysis using memory-mapped files
        std::unordered_map<std::string, std::atomic<int>> include_counts;
        std::atomic cpp_file_count{0};

        const size_t num_threads = std::min(target_source_files.size(),
                                           static_cast<size_t>(std::thread::hardware_concurrency()));

        if (num_threads > 1 && target_source_files.size() > 4) {
            // Parallel processing
            std::vector<std::thread> workers;
            std::atomic<size_t> file_index{0};
            std::mutex counts_mutex;

            for (size_t t = 0; t < num_threads; ++t) {
                workers.emplace_back([&] {
                    std::unordered_map<std::string, int> local_counts;
                    int local_cpp_count = 0;
                    size_t idx;

                    while ((idx = file_index.fetch_add(1)) < target_source_files.size()) {
                        const auto& src = target_source_files[idx];
                        if (getCompiler(src) != config.cxx) continue;

                        local_cpp_count++;

                        // Use memory-mapped file for speed
                        MemoryMappedFile mmf(src);
                        if (!mmf.is_valid()) continue;

                        auto content = mmf.content();

                        // Fast regex-free parsing
                        size_t pos = 0;
                        while ((pos = content.find("#include <", pos)) != std::string_view::npos) {
                            pos += 10; // Skip "#include <"
                            const size_t end = content.find('>', pos);
                            if (end != std::string_view::npos) {
                                std::string header(content.substr(pos, end - pos));
                                local_counts[header]++;
                            }
                            pos = end;
                        }
                    }

                    // Merge local results
                    std::lock_guard lock(counts_mutex);
                    cpp_file_count += local_cpp_count;
                    for (const auto& [header, count] : local_counts) {
                        include_counts[header] += count;
                    }
                });
            }

            for (auto& worker : workers) {
                worker.join();
            }
        } else {
            // Sequential fallback
            for (const auto& src : target_source_files) {
                if (getCompiler(src) != config.cxx) continue;
                ++cpp_file_count;

                MemoryMappedFile mmf(src);
                if (!mmf.is_valid()) continue;

                auto content = mmf.content();
                size_t pos = 0;
                while ((pos = content.find("#include <", pos)) != std::string_view::npos) {
                    pos += 10;
                    size_t end = content.find('>', pos);
                    if (end != std::string_view::npos) {
                        std::string header(content.substr(pos, end - pos));
                        ++include_counts[header];
                    }
                    pos = end;
                }
            }
        }

    #else
        // Original regex-based version (slower)
        std::unordered_map<std::string, int> include_counts;
        int cpp_file_count = 0;

        for (const auto& src : target_source_files) {
            if (getCompiler(src) != config.cxx) continue;
            cpp_file_count++;

            std::ifstream stream(src);
            if (!stream.is_open()) continue;

            std::string line;
            std::regex pch_candidate_regex(R"_(\s*#\s*include\s*<([^>]+)>)_");
            while (std::getline(stream, line)) {
                if (std::smatch matches; std::regex_search(line, matches, pch_candidate_regex)) {
                    include_counts[matches[1].str()]++;
                }
            }
        }
    #endif

        if (cpp_file_count < 3) {
            out::info("PCH skipped: Not enough C++ source files.");
            return "";
        }

        // PHASE 2: Smart header selection
        std::vector<std::string> pch_headers;
        pch_headers.reserve(include_counts.size());

        const int threshold = std::max(2, cpp_file_count / 3); // More aggressive threshold

        // Sort by frequency for better PCH effectiveness
        std::vector<std::pair<std::string, int>> sorted_headers;
        sorted_headers.reserve(include_counts.size());

        for (const auto& [header, count] : include_counts) {
            if (count >= threshold) {
                sorted_headers.emplace_back(header, count);
            }
        }

        std::ranges::sort(sorted_headers, [](const auto& a, const auto& b) {
            return a.second > b.second; // Sort by frequency (descending)
        });

        // Take top headers (limit to avoid bloat)
        const size_t max_headers = std::min(sorted_headers.size(), size_t{50});
        for (size_t i = 0; i < max_headers; ++i) {
            pch_headers.push_back(sorted_headers[i].first);
        }

        if (pch_headers.empty()) {
            out::info("PCH skipped: No sufficiently common headers found.");
            return "";
        }

        // PHASE 3: Generate and compile PCH
        fs::path pch_source = build_path / PCH_HEADER_NAME;
        fs::path pch_out = pch_source.string() + ".gch";


        // Fast file writing
        std::ofstream pch_file(pch_source);
        if (!pch_file.is_open()) {
            out::error("Failed to create PCH source file: {}", pch_source);
            return "";
        }

        // Write headers in frequency order for better compilation
        for (const auto& header : pch_headers) {
            pch_file << "#include <" << header << ">\n";
        }
        pch_file.close();

        // Compile with all the right flags
        const std::string pch_compile_cmd = fmt::format("{} -x c++-header -fPIC {} -o {} {} {}",
            config.cxx, pch_source, pch_out, target_cxxflags,
            fmt::join(config.include_dirs | std::views::transform([](const std::string& d){ return "-I" + d; }), " "));

        #ifdef VERBOSE
        out::command("{}", pch_compile_cmd);
        #endif

        if (auto [exit_code, stdout_output, stderr_output] = Execution::execute(pch_compile_cmd); exit_code != 0) {
            out::warn("PCH generation failed. Continuing without it.\n   Compiler error: {}", stderr_output);
            return "";
        }

        if (!fs::exists(pch_out)) {
            out::warn("PCH compilation appeared successful but output file missing: {}", pch_out);
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

        const auto ignored_dirs = getIgnoredDirs();
        out::info("Getting ignored directories...");

        // Timer for find_source_files()
        const auto find_files_start = std::chrono::high_resolution_clock::now();
        out::info("Finding source files...");
        source_files = TargetDiscovery::find_source_files(root, ignored_dirs, config.exclude_patterns);
        const auto find_files_end = std::chrono::high_resolution_clock::now();
        out::success("Sources found. -- {} us",
                  std::chrono::duration_cast<std::chrono::microseconds>(find_files_end - find_files_start).count());

        if (should_auto_detect) {
            out::info("Running auto-detection for headers and libraries...");

            const auto scan_headers_start = std::chrono::high_resolution_clock::now();
            out::info("Scanning headers...");
            scanLocalHeaders();
            const auto scan_headers_end = std::chrono::high_resolution_clock::now();
            out::success("Header scan complete -- {} us",
                      std::chrono::duration_cast<std::chrono::microseconds>(scan_headers_end - scan_headers_start).count());

            const auto detect_libs_start = std::chrono::high_resolution_clock::now();
            out::info("Resolving dependencies...");
            detectLibraries();
            const auto detect_libs_end = std::chrono::high_resolution_clock::now();
            out::success("Dependencies resolved -- {} us",
                      std::chrono::duration_cast<std::chrono::microseconds>(detect_libs_end - detect_libs_start).count());
        }
    }

    static std::unique_ptr<AutoCC> load_from_cache() {
        Config config;
        read_config_cache_static(config);
        auto instance = std::make_unique<AutoCC>(std::move(config), false);
        if (instance->source_files.empty()) {
            out::warn("No source files found. This may be correct for a header-only library.");
        }
        return instance;
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

        file << "cxx:" << config.cxx << "\n";
        file << "cc:" << config.cc << "\n";
        file << "as:" << config.as << "\n";
        file << "launcher:" << config.launcher << "\n"; // eg. ccache
        file << "ar:" << config.ar << "\n";
        file << "sl:" << config.shared << "\n";
        file << "build_dir:" << config.build_dir << "\n";
        file << "use_pch:" << (config.use_pch ? "true" : "false") << "\n";
        file << "default_target:" << config.default_target << "\n";

        for (const auto& dir : config.include_dirs) file << "include:" << dir << "\n";
        for (const auto& pattern : config.exclude_patterns) file << "exclude:" << pattern << "\n";

        for (const auto&[type, name, main_file, sources, output_name, exclude_patterns, cflags, cxxflags, ldflags, external_libs] : config.targets) {
            auto escape_pipes = [](const std::string& str) {
                std::string result = str;
                size_t pos = 0;
                while ((pos = result.find('|', pos)) != std::string::npos) {
                    result.replace(pos, 1, "\\|");
                    pos += 2;
                }
                return result;
            };

            file << "target:" << escape_pipes(type) << "|"
                << escape_pipes(name) << "|"
                << escape_pipes(main_file) << "|"
                << escape_pipes(output_name) << "|"
                << escape_pipes(cflags.value_or("")) << "|"
                << escape_pipes(cxxflags.value_or("")) << "|"
                << escape_pipes(ldflags.value_or("")) << "\n";

            for (const auto& src : sources) {
                file << "target_src:" << name << ":" << src << "\n";
            }
            for (const auto& lib : external_libs) {
                file << "target_lib:" << name << ":" << lib << "\n";
            }
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
            if (!config.targets.empty()) {
                actual_target = config.targets[0].name;
                out::info("No default target specified, using first target '{}'", actual_target);
            } else {
                out::error("No targets available to build.");
                return 1;
            }
        }
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
        const fs::path config_file = cache_dir / CONFIG_CACHE_FILE_NAME;

        if (!fs::exists(config_file)) return false;

        std::ifstream file(config_file);
        if (!file.is_open()) {
            out::error("Failed to open config cache file for reading: {}", config_file);
            return false;
        }

        std::string line;
        config = {}; // Reset config
        std::unordered_map<std::string, Target> target_map;

        while (std::getline(file, line)) {
            const auto pos = line.find(':');
            if (pos == std::string::npos) {
                out::warn("Invalid config cache line format, skipping: {}", line);
                continue;
            }

            const std::string_view key = std::string_view(line).substr(0, pos);
            std::string_view value = pos + 1 < line.size() ? std::string_view(line).substr(pos + 1) : "";

            if (key == "cxx") config.cxx = value;
            else if (key == "cc") config.cc = value;
            else if (key == "as") config.as = value;
            else if (key == "launcher") config.launcher = value;
            else if (key == "ar") config.ar = value;
            else if (key == "sl") config.shared = value;
            else if (key == "build_dir") config.build_dir = value;
            else if (key == "use_pch") config.use_pch = value == "true";
            else if (key == "default_target") config.default_target = value;
            else if (key == "include") config.include_dirs.emplace_back(value);
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

                std::string value_str(value);
                std::vector<std::string> parts;
                size_t start = 0, end;
                while ((end = value_str.find('|', start)) != std::string::npos) {
                    if (start > 0 && value_str[start - 1] == '\\') { // Handle escaped pipe
                        start = end + 1;
                        continue;
                    }
                    parts.push_back(unescape_pipes(value_str.substr(start, end - start)));
                    start = end + 1;
                }
                parts.push_back(unescape_pipes(value_str.substr(start)));

                if (parts.size() >= 7) {
                    Target target;
                    target.type = parts[0];
                    target.name = parts[1];
                    target.main_file = parts[2];
                    target.output_name = parts[3];
                    if (!parts[4].empty()) target.cflags = parts[4];
                    if (!parts[5].empty()) target.cxxflags = parts[5];
                    if (!parts[6].empty()) target.ldflags = parts[6];
                    target_map[target.name] = target;
                } else {
                    out::warn("Invalid target format in cache, skipping: {}", line);
                }
            }

            else if (key == "target_src") {
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
                std::string value_str(value);
                if (size_t colon_pos = value_str.find(':'); colon_pos != std::string::npos) {
                    std::string target_name = value_str.substr(0, colon_pos);
                    std::string exclude_pattern = value_str.substr(colon_pos + 1);
                    if (target_map.contains(target_name)) {
                        target_map[target_name].exclude_patterns.push_back(exclude_pattern);
                    }
                }
            }

            else if (key == "target_lib") {
                std::string value_str(value);
                if (size_t colon_pos = value_str.find(':'); colon_pos != std::string::npos) {
                    std::string target_name = value_str.substr(0, colon_pos);
                    std::string lib = value_str.substr(colon_pos + 1);
                    if (target_map.contains(target_name)) {
                        target_map[target_name].external_libs.push_back(lib);
                    }
                }
            }
            else {
                out::warn("Unknown config cache key, skipping: {}", key);
            }
        }

        for (auto &target: target_map | std::views::values) {
            config.targets.push_back(std::move(target));
        }

        return true;
    }

private:

    static std::string hash_file(const fs::path& path) {
    #ifdef AGGRESSIVE
        // Use memory-mapped file for maximum speed
        const MemoryMappedFile mmf(path);
        if (mmf.is_valid() && !mmf.empty()) {
            const auto content = mmf.content();
            XXH64_hash_t hash_val = XXH64(content.data(), content.size(), 0);
            return fmt::format("{:016x}", hash_val);
        }

        // Fallback for invalid/empty files
        if (mmf.is_valid() && mmf.empty()) {
            return "ef46db3751d8e999"; // XXH64 of empty data
        }

    #endif

        // Original fallback implementation
        const int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1) return "";

        struct stat sb{};
        if (fstat(fd, &sb) == -1) {
            close(fd);
            return "";
        }

        if (sb.st_size == 0) {
            close(fd);
            return "ef46db3751d8e999";
        }

        void* mapped = mmap(nullptr, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapped == MAP_FAILED) {
            close(fd);
            return "";
        }

        // Hint for sequential access
        madvise(mapped, sb.st_size, MADV_SEQUENTIAL);

        XXH64_hash_t hash_val = XXH64(mapped, sb.st_size, 0);

        munmap(mapped, sb.st_size);
        close(fd);

        return fmt::format("{:016x}", hash_val);
    }

    static void processEntries(const std::vector<fs::path>& entries,
                                const std::unordered_set<std::string>& ignored_components,
                                std::unordered_set<fs::path>& header_dirs_set,
                                const size_t num_threads) { // for scanLocalHeaders()

        std::vector<std::thread> threads;
        std::mutex result_mutex;
        std::atomic<size_t> next_entry_index{0};

        // Pre-compile header extensions for faster comparison
        static const std::unordered_set<std::string_view> header_extensions = HEADER_EXTENSIONS;

        for (size_t t = 0; t < num_threads; ++t) {
            threads.emplace_back([&] {
                std::unordered_set<fs::path> local_header_dirs;
                local_header_dirs.reserve(entries.size() / num_threads + 100);

                size_t entry_index;
                while ((entry_index = next_entry_index.fetch_add(1)) < entries.size()) {
                    const auto& entry_path = entries[entry_index];

                    try {
                        // Fast ignored directory check using path components
                        if (isInIgnoredDirectory(entry_path, ignored_components)) {
                            continue;
                        }

                        // Check if it's a regular file with header extension
                        if (fs::is_regular_file(entry_path)) {
                            if (const std::string ext = entry_path.extension().string(); header_extensions.contains(ext)) {
                                if (auto parent = entry_path.parent_path(); !parent.empty()) {
                                    try {
                                        local_header_dirs.insert(fs::canonical(parent));
                                    } catch (const fs::filesystem_error&) {
                                        // If canonical fails, use the original path
                                        local_header_dirs.insert(parent);
                                    }
                                }
                            }
                        }
                    } catch (const fs::filesystem_error& e) {
                        out::warn("Skipping file due to filesystem error: {}", e.what());
                    }
                }

                // Merge local results into global set
                if (!local_header_dirs.empty()) {
                    std::lock_guard lock(result_mutex);
                    header_dirs_set.insert(local_header_dirs.begin(), local_header_dirs.end());
                }
            });
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
    }

    int build_target(const Target& target) {
        target_source_files.clear();
        out::info("Building target: {} -> {}", target.name, target.output_name);

        for (const auto& src_path_str : target.sources) {
            fs::path src_path(src_path_str);
            bool excluded = false;
            for (const auto& pat : config.exclude_patterns) {
                if (Strings::matches_pattern(src_path_str, pat)) { excluded = true; break; }
            }
            if (excluded) continue;
            for (const auto& pat : target.exclude_patterns) {
                if (Strings::matches_pattern(src_path_str, pat)) { excluded = true; break; }
            }
            if (excluded) continue;

            fs::path file_path = src_path.is_absolute() ? src_path : fs::path(root) / src_path;

            try {
                if (fs::exists(file_path)) {
                    target_source_files.push_back(fs::canonical(file_path));
                } else {
                    out::error("Source file '{}' specified in target '{}' not found at '{}'",
                            src_path_str, target.name, file_path.string());
                    return 1;
                }
            } catch (const fs::filesystem_error& e) {
                out::error("Error accessing source file '{}': {}", file_path.string(), e.what());
                return 1;
            }
        }

        if (target_source_files.empty()) {
            out::error("No valid source files found for target '{}' after applying exclusions.", target.name);
            return 1;
        }

        #ifdef VERBOSE
        out::info("Target '{}' needs {} source files:", target.name, target_source_files.size());
        for (const auto& file : target_source_files) {
            out::info("  - {}", fs::relative(file).string());
        }
        #endif

        return build_with_files(target_source_files, target.output_name,
                                target.cflags.value_or(""),
                                target.cxxflags.value_or(""),
                                target.ldflags.value_or(""),
                                target.external_libs,
                                config.launcher, target.type);
    }


    int build_with_files(const std::vector<fs::path>& files_to_build, const std::string& output_name,
                const std::string& target_cflags, const std::string& target_cxxflags,
                const std::string& target_ldflags, const std::vector<std::string>& target_libs,
                const std::string& launcher, const std::string& type) {

        if (!Validation::isTypeValid(type)) {
            out::error("Unknown type: {}", type);
            return 1;
        }

        if (files_to_build.empty()) {
            out::error("No source files found to build.");
            return 1;
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
            pch_flags = generatePCH(build_path, target_cxxflags);
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
            if (std::string compiler = getCompiler(src_file); compiler == config.cxx) current_flags = target_cxxflags;
            else if (compiler == config.cc) current_flags = target_cflags;

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
                #ifdef VERBOSE
                out::info("Will recompile {}: {}.", fs::relative(src_file).string(), reason);
                #endif
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

        if (files_to_compile.empty()) {
            out::success("All {} files are up to date.", files_to_build.size());
        } else {
            out::info("Compiling source files...", files_to_compile.size(), files_to_build.size());
            std::atomic compilation_failed = false;
            std::atomic<size_t> file_index = 0;
            const unsigned int num_threads = std::max(1u, std::thread::hardware_concurrency());
            std::vector<std::thread> workers;
            for (unsigned int i = 0; i < num_threads; ++i) {
                workers.emplace_back([&] {
                    while (true) {
                        const size_t index = file_index.fetch_add(1);
                        if (index >= files_to_compile.size() || compilation_failed.load()) return;

                        const auto& src = files_to_compile[index];
                        std::string compiler = getCompiler(src);
                        fs::path obj = build_path / src.filename().replace_extension(".o");
                        std::string cmd;
                        if (compiler == config.as) {
                            cmd = fmt::format("{} {} {} -felf64 -o {}", launcher, compiler, src, obj);
                        } else {
                            std::string_view flags = compiler == config.cxx ? target_cxxflags : target_cflags;
                            std::string current_pch_flags = compiler == config.cxx && !pch_flags.empty() ? pch_flags : "";
                            if (type == "DLibrary" || type == "SLibrary")
                            cmd = fmt::format("{} {} -c -fPIC {} -o {} {} {} {}", launcher, compiler, src, obj, flags, current_pch_flags,
                                  fmt::join(config.include_dirs | std::views::transform([](const std::string& d){ return "-I" + d; }), " "));
                            else
                            cmd = fmt::format("{} {} -c -fPIC {} -o {} {} {} {}", launcher, compiler, src, obj, flags, current_pch_flags,
                              fmt::join(config.include_dirs | std::views::transform([](const std::string& d){ return "-I" + d; }), " "));
                        }
                        #ifdef VERBOSE
                        out::command("{}", cmd);
                        #endif
                        if (auto [exit_code, stdout_output, stderr_output] = Execution::execute(cmd); exit_code != 0) {
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

        const fs::path target_path = fs::path(config.build_dir) / output_name;

        if (type == "Executable") {
            out::info("Linking executable target...");

            const std::string link_cmd = fmt::format("{} {} -o {} {} {} {} {}",
                launcher,
                config.cxx, target_path,
                fmt::join(object_files, " "),
                target_cxxflags, // Added for link-time flags
                target_ldflags,
                fmt::join(target_libs, " "));
            #ifdef VERBOSE
            out::command("{}", link_cmd);
            #endif
            if (auto [exit_code, stdout_output, stderr_output] = Execution::execute(link_cmd); exit_code != 0) {
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

        if (type == "DLibrary") {
            out::info("Linking dynamic target...");
            if (target_path.extension() != ".so") out::warn("Target name {} with type {} Does not have appropriate extension. Consider changing it.", target_path, type);
            const std::string link_cmd = fmt::format("{} {} -shared -o {} {} {} {}",
                launcher,
                config.shared,
                target_path,
                fmt::join(object_files, " "),
                target_ldflags,
                fmt::join(target_libs, " ")
                );
            #ifdef VERBOSE
            out::command("{}", link_cmd);
            #endif
            if (auto [exit_code, stdout_output, stderr_output] = Execution::execute(link_cmd); exit_code != 0) {
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

        if (type == "SLibrary") {
            out::info("Linking static target...");
            if (target_path.extension() != ".a") out::warn("Target name {} with type {} Does not have appropiate extension. Consider changing it.", target_path, type);
            const std::string link_cmd = fmt::format("{} {} rcs {} {} {}",
                launcher,
                config.ar,
                target_path,
                fmt::join(object_files, " "),
                target_ldflags
                );
            #ifdef VERBOSE
            out::command("{}", link_cmd);
            #endif
            if (auto [exit_code, stdout_output, stderr_output] = Execution::execute(link_cmd); exit_code != 0) {
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

        return 1; // should not reach here
    }

    const fs::path root = PROJECT_ROOT;
    const fs::path cache_dir = root / CACHE_DIR_NAME;
    const fs::path config_file = cache_dir / CONFIG_CACHE_FILE_NAME;
    const fs::path dep_cache_file = cache_dir / DEP_CACHE_FILE_NAME;
    DependencyMap dependency_map;

};
// info and help
class Information {
public:
    static void show_version() {
        fmt::print("AutoCC {} compiled on {} at {}\n",
            fmt::styled(VERSION, COLOR_SUCCESS),
            fmt::styled(DATE, COLOR_INFO),
            fmt::styled(TIME, COLOR_INFO)
        );
    }

    static void show_help() {
        using fmt::styled;
        show_version();

        fmt::print(
            "\n"
            "Usage: autocc [command/target_name] (target_name)\n\n"
            "Commands:\n"
            "  {}   Builds the default target, or a specified target.\n"
            "  {}        Creates 'autocc.toml' via setup wizard.\n"
            "  {}        Converts 'autocc.toml' to the internal build cache.\n"
#ifdef USE_TUI
            "  {}          Open a TUI to visually select source files for targets.\n"
#endif
            "  {}                Removes the build directory.\n"
            "  {}                 Removes all autocc generated files (cache, build dir, db).\n"
            "  {}                Download/update the library detection database.\n"
            "  {}              Show current version and build date.\n"
            "  {}                 Shows this help message.\n"
            "  {}     Install specified target to system binary dir.\n"
            "Flags:\n"
            "  {}            For 'autocc autoconfig', use default settings.\n",
            styled("<none> or <target>", COLOR_PROMPT),
            styled("ac/autoconfig", COLOR_PROMPT),
            styled("setup/sync/sc", COLOR_PROMPT),
            styled("edit/select", COLOR_PROMPT),
            styled("clean", COLOR_PROMPT),
            styled("wipe", COLOR_PROMPT),
            styled("fetch", COLOR_PROMPT),
            styled("version", COLOR_PROMPT),
            styled("help", COLOR_PROMPT),
            styled("install <target>", COLOR_PROMPT),
            styled("--default", COLOR_PROMPT)
        );
    }
};

class Setup {
public:

#ifdef USE_TUI

    static void user_init(Config& config) {
        using namespace ftxui;
        int current_step = 0;
        constexpr int total_steps = 5;

        // Helper to format the step title like "[1/5] Title"
        auto format_step_title = [&](const std::string& title) {
            return fmt::format("[{}/{}] {}", current_step, total_steps, title);
        };

        // Helper to create a progress bar that adapts to terminal width
        auto create_progress_bar = [&](const int width) {
            const float progress = static_cast<float>(current_step) / total_steps;
            const int bar_width = std::min(30, width / 3); // Adaptive width, max 30
            const int filled = static_cast<int>(progress) * bar_width;
            std::string bar = "[";
            for (int i = 0; i < bar_width; i++) {
                bar += i < filled ? "█" : "░";
            }
            bar += "]";
            return text(bar) | dim;
        };
        // Helper to display a fullscreen message box
        auto display_message = [&](const std::string& title, const Element &message_element) {
            current_step++;
            auto screen = ScreenInteractive::Fullscreen();
            const auto component = Renderer([&] {
                // Get terminal dimensions
                const int term_width = Terminal::Size().dimx;
                // Create a decorative header that spans full width
                auto header = vbox({
                    text("╭" + std::string(term_width - 2, '-') + "╮") | dim,
                    hbox({
                        text("│ ") | dim,
                        text("AutoCC Configuration Wizard") | bold,
                        filler(),
                        create_progress_bar(term_width),
                        text(" │") | dim
                    }),
                    text("╰" + std::string(term_width - 2, '-') + "╯") | dim,
                });

                // Create the main content area with proper padding
                const auto padded_content = vbox({
                    filler(),  // Top filler to center content
                    message_element | center,
                    filler(),  // Bottom filler to center content
                    separatorEmpty(),
                    hbox({
                        filler(),
                        text("[ Press ") | dim,
                        text("ENTER") | bold | underlined,
                        text(" to continue ]") | dim,
                        filler()
                    }),
                    separatorEmpty()
                });

                // Create the step indicator
                const auto step_indicator = hbox({
                    text(" ◆ ") | bold,
                    text(format_step_title(title)) | bold,
                    text(" ◆ ") | bold
                }) | center;

                // Combine everything with proper margins
                auto main_content = vbox({
                    header,
                    separatorEmpty(),
                    window(
                        step_indicator,
                        padded_content | flex
                    ) | borderDouble | flex,
                    separatorEmpty(),
                    text("© AutoCC Build System") | dim | center
                });

                return main_content;
            });

            const auto final_component = CatchEvent(component, [&](const Event& event) {
                if (event == Event::Return) {
                    screen.Exit();
                    return true;
                }
                return false;
            });
            screen.Loop(final_component);
        };

        // Helper for getting user input with fullscreen layout
        auto get_input = [&](const std::string& prompt, const std::string& default_val) -> std::string {
            std::string value;
            auto screen = ScreenInteractive::Fullscreen();
            auto input_component = Input(&value, default_val);
            const auto component = Container::Vertical({ input_component });

            const auto renderer = Renderer(component, [&] {
                // Get terminal dimensions
                const int term_width = Terminal::Size().dimx;
                const int content_width = std::min(80, term_width - 10); // Max 80 chars wide for readability

                // Create decorative elements
                auto divider = text(std::string(content_width, '=')) | dim | center;

                // Format the prompt with better typography
                auto prompt_section = vbox({
                    hbox({
                        text(" ▶ ") | bold,
                        text(prompt) | bold
                    }) | center,
                    separatorEmpty(),
                    hbox({
                        text("Default: ") | dim,
                        default_val.empty() ? text("<none>") | dim | italic : text(default_val) | underlined | dim
                    }) | center
                });

                // Create the input field with visual indicators
                auto input_field = hbox({
                    text("╭─ ") | dim,
                    text("Input") | bold,
                    text(" ─╮") | dim
                }) | center;

                const auto input_box_width = std::min(60, content_width - 10);
                auto input_area = vbox({
                    input_field,
                    hbox({
                        filler(),
                        text("│ ") | dim,
                        input_component->Render() | size(WIDTH, EQUAL, input_box_width) | borderLight,
                        text(" │") | dim,
                        filler()
                    }),
                    hbox({
                        filler(),
                        text("╰" + std::string(input_box_width + 4, '-') + "╯") | dim,
                        filler()
                    })
                });

                // Help text
                auto help_text = hbox({
                    text("💡 ") | dim,
                    text("Tip: Press Enter to use default value") | dim | italic
                }) | center;

                // Combine all elements with proper vertical centering
                const auto content = vbox({
                    filler(),  // Top spacer
                    divider,
                    separatorEmpty(),
                    prompt_section,
                    separatorEmpty(),
                    input_area,
                    separatorEmpty(),
                    help_text,
                    separatorEmpty(),
                    divider,
                    filler()   // Bottom spacer
                });

                // Create the window with a title
                return window(
                    hbox({
                        text(" ⚙ ") | bold,
                        text("Configuration Input") | bold,
                        text(" ⚙ ") | bold
                    }) | center,
                    content
                ) | borderDouble;
            });

            const auto final_component = CatchEvent(renderer, [&](const Event& event) {
                if (event == Event::Return) {
                    screen.Exit();
                    return true;
                }
                return false;
            });
            screen.Loop(final_component);
            return value.empty() ? default_val : value;
        };

        // --- The logic below remains unchanged but with enhanced display ---
        display_message("Welcome", vbox({
            text("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━") | dim | center,
            separatorEmpty(),
            text("Welcome to the AutoCC Configuration Wizard") | bold | center,
            separatorEmpty(),
            text("This utility will guide you through creating a configuration file") | center,
            text("for your C/C++ build system. The wizard will help you:") | center,
            separatorEmpty(),
            vbox({
                text("  • Configure compilers and build tools ") | center,
                text("  • Set up build directories and options") | center,
                text("  • Discover and configure build targets") | center,
                text("  • Define source files and dependencies") | center
            }) | dim,
            separatorEmpty(),
            text("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━") | dim | center,
            separatorEmpty(),
            text("💡 Press Enter on any prompt to accept the default value shown") | italic | center
        }));

        config.cc = get_input("C Compiler", config.cc);
        config.cxx = get_input("C++ Compiler", config.cxx);
        config.as = get_input("Assembler", config.as);
        config.launcher = get_input("Launcher", config.launcher);
        config.ar = get_input("Archiver", config.ar);
        config.shared = get_input("Shared library linker", config.shared);
        config.build_dir = get_input("Build Directory", config.build_dir);
        std::string pch_choice = get_input("Use Pre-Compiled Headers (yes/no)", config.use_pch ? "yes" : "no");
        config.use_pch = pch_choice == "yes" || pch_choice == "y";

        if (std::string exclude_input = get_input("Global exclude patterns (space-separated)", ""); !exclude_input.empty()) {
            std::stringstream ss(exclude_input);
            std::string item;
            while (ss >> item) {
                config.exclude_patterns.push_back(item);
            }
        }

        display_message("Discovery", vbox({
            text("🔍 Searching for potential build targets...") | bold | center,
            separatorEmpty(),
            text("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━") | dim | center,
            separatorEmpty(),
            text("The wizard is now scanning your project directory to") | center,
            text("automatically discover executable targets based on:") | center,
            separatorEmpty(),
            vbox({
                text("  • Files containing main() functions") | center,
                text("  • Common source file patterns") | center,
                text("  • Directory structure conventions") | center
            }) | dim,
            separatorEmpty(),
            text("This may take a moment depending on project size...") | italic | dim | center
        }));

        const auto ignored_dirs = std::unordered_set<std::string>{".git", config.build_dir, CACHE_DIR_NAME};
        auto all_sources = TargetDiscovery::find_source_files(".", ignored_dirs, config.exclude_patterns);
        auto discovered = TargetDiscovery::discover_targets(all_sources);

        if (discovered.empty()) {
            display_message("Warning", vbox({
                text("⚠️  No Targets Discovered") | bold | center,
                separatorEmpty(),
                text("─────────────────────────────────────────────────────") | dim | center,
                separatorEmpty(),
                text("The wizard could not automatically discover any build targets.") | center,
                text("This could mean:") | center,
                separatorEmpty(),
                vbox({
                    text("  • No source files with main() were found") | center,
                    text("  • Source files are in excluded directories") | center,
                    text("  • Non-standard project structure") | center
                }) | dim,
                separatorEmpty(),
                text("You'll need to configure targets manually in autocc.toml") | bold | center,
                separatorEmpty(),
                text("─────────────────────────────────────────────────────") | dim | center
            }));
            return;
        }

        {
            Elements target_elements;
            target_elements.push_back(text("📦 Found the following potential targets:") | bold | center);
            target_elements.push_back(separatorEmpty());
            target_elements.push_back(text("═══════════════════════════════════════════════════════════════") | dim | center);

            for (const auto&[suggested_name, main_file, suggested_sources, reason] : discovered) {
                target_elements.push_back(separatorEmpty());
                target_elements.push_back(
                    vbox({
                        hbox({
                            text("  ▸ ") | bold,
                            text(suggested_name) | bold | underlined,
                            text(" (") | dim,
                            text(std::to_string(suggested_sources.size())) | bold,
                            text(" sources)") | dim
                        }) | center,
                        hbox({
                            text("    Main: ") | dim,
                            text(main_file.filename().string())
                        }) | center,
                        hbox({
                            text("    Reason: ") | dim,
                            text(reason) | italic
                        }) | center
                    })
                );
                target_elements.push_back(text("  ─────────────────────────────────────────────────────────") | dim | center);
            }

            target_elements.push_back(text("═══════════════════════════════════════════════════════════════") | dim | center);
            current_step--;
            display_message("Discovered Targets", vbox(target_elements));
            current_step++;
        }

        for (const auto& discovered_target : discovered) {
            std::string prompt = fmt::format("Configure target '{}'?", discovered_target.suggested_name);
            if (std::string accept = get_input(prompt, "y"); accept == "y" || accept == "yes" || accept == "Y") {
                Target target;
                target.type = get_input("Target Type (Case-sensitive) (Executable, DLibrary, SLibrary)", target.type);
                while (!Validation::isTypeValid(target.type)) target.type = get_input("Target Type (Case-sensitive) (Executable, DLibrary, SLibrary)", target.type);
                target.name = get_input("Target Name", discovered_target.suggested_name);
                target.main_file = discovered_target.main_file.string();
                target.output_name = get_input("Output target Name", target.name);
                target.cxxflags = get_input("CXX Flags for this target", target.cxxflags.value());
                target.cflags = get_input("C Flags for this target", target.cflags.value());
                target.ldflags = get_input("Linker Flags for this target", "");

                if (std::string libs_input = get_input("External libs for this target (e.g. -lpthread)", ""); !libs_input.empty()) {
                    std::stringstream ss(libs_input);
                    std::string lib;
                    while (ss >> lib) target.external_libs.push_back(lib);
                }

                {
                    Elements source_elements;
                    source_elements.push_back(text("📄 Suggested source files:") | bold | center);
                    source_elements.push_back(separatorEmpty());
                    source_elements.push_back(text("─────────────────────────────────────────────────") | dim | center);
                    for (const auto& src : discovered_target.suggested_sources) {
                        source_elements.push_back(hbox({
                            text("    • "),
                            text(src.string()) | dim
                        }) | center);
                    }
                    source_elements.push_back(text("─────────────────────────────────────────────────") | dim | center);
                    display_message(fmt::format("Sources for '{}'", target.name), vbox(source_elements));
                }

                if (std::string use_suggested = get_input("Use these suggested sources? (y/n)", "y");
                    use_suggested == "y" || use_suggested == "yes" || use_suggested == "Y") {
                    for (const auto& src : discovered_target.suggested_sources) {
                        target.sources.push_back(src.string());
                    }
                } else {
                    if (std::string sources_input = get_input("Enter source files manually (space-separated)", ""); !sources_input.empty()) {
                        std::stringstream ss(sources_input);
                        std::string src;
                        while (ss >> src) target.sources.push_back(src);
                    }
                }

                std::string target_excludes_prompt = fmt::format("Target-specific exclude patterns for '{}'", target.name);
                if (std::string target_excludes = get_input(target_excludes_prompt, ""); !target_excludes.empty()) {
                    std::stringstream ss(target_excludes);
                    std::string pattern;
                    while (ss >> pattern) target.exclude_patterns.push_back(pattern);
                }
                config.targets.push_back(target);
            }
        }

        if (!config.targets.empty()) {
            config.default_target = get_input("Default Build Target", config.targets[0].name);
        }

        display_message("Complete", vbox({
            text("✨ Configuration Complete! ✨") | bold | center,
            separatorEmpty(),
            text("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━") | dim | center,
            separatorEmpty(),
            text("Your project has been successfully configured!") | center,
            separatorEmpty(),
            text("Summary:") | bold | center,
            vbox({
                hbox({text("  • Compiler: "), text(config.cxx) | dim}) | center,
                hbox({text("  • Build Dir: "), text(config.build_dir) | dim}) | center,
                hbox({text("  • Targets: "), text(std::to_string(config.targets.size())) | dim}) | center,
                hbox({text("  • PCH: "), text(config.use_pch ? "Enabled" : "Disabled") | dim}) | center
            }),
            separatorEmpty(),
            text("Your settings will be saved to: ") | center,
            text("autocc.toml") | bold | underlined | center,
            separatorEmpty(),
            text("You can now build your project with: autocc") | italic | center,
            separatorEmpty(),
            text("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━") | dim | center
        }));
    }

#else

    static void user_init(Config& config) {
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
        config.launcher = get_input("Launcher", config.launcher);
        config.ar = get_input("Archiver", config.ar);
        config.shared = get_input("Shared library linker", config.shared);
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

        out::info("Discovering potential build targets...");
        const auto ignored_dirs = std::unordered_set<std::string> {".git", config.build_dir, CACHE_DIR_NAME};
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

        for (const auto& discovered_target : discovered) {
            std::string accept = get_input(
                fmt::format("Configure target '{}' with main file '{}'? (y/n)",
                           discovered_target.suggested_name, discovered_target.main_file.filename().string()),
                "y");

            if (accept == "y" || accept == "yes" || accept == "Y") {
                Target target;
                target.type = get_input("Target type", target.type);
                target.name = get_input("Target name", discovered_target.suggested_name);
                target.main_file = discovered_target.main_file.string();
                target.output_name = get_input("Output executable name", target.name);
                target.cxxflags = get_input("CXX Flags for this target", "");
                target.cflags = get_input("CC Flags for this target", "");
                target.ldflags = get_input("Linker Flags for this target", "");
                if (std::string libs_input = get_input("External libs for this target (space-separated, e.g. -lpthread -lSDL2)", ""); !libs_input.empty()) {
                    std::stringstream ss(libs_input);
                    std::string lib;
                    while (ss >> lib) target.external_libs.push_back(lib);
                }

                out::info("Suggested source files for target '{}':", target.name);
                for (const auto& src : discovered_target.suggested_sources) {
                    out::info("  - {}", src.string());
                }

                if (std::string use_suggested = get_input("Use these suggested sources? (y/n)", "y"); use_suggested == "y" || use_suggested == "yes" || use_suggested == "Y") {
                    for (const auto& src : discovered_target.suggested_sources) {
                        target.sources.push_back(src.string());
                    }
                } else {
                    out::info("Enter source files manually (space-separated, relative paths):");
                    std::string sources_input;
                    std::getline(std::cin, sources_input);
                    if (!sources_input.empty()) {
                        std::stringstream ss(sources_input);
                        std::string src;
                        while (ss >> src) target.sources.push_back(src);
                    }
                }

                std::string target_excludes = get_input(
                    fmt::format("Target-specific exclude patterns for '{}' (optional)", target.name), "");
                if (!target_excludes.empty()) {
                    std::stringstream ss(target_excludes);
                    std::string pattern;
                    while (ss >> pattern) target.exclude_patterns.push_back(pattern);
                }

                config.targets.push_back(target);
            }
        }

        if (!config.targets.empty()) {
            config.default_target = get_input("Default target", config.targets[0].name);
        }
    }

#endif

    static void default_init(Config& config) {
        out::info("Discovering potential build targets to create a default configuration...");
        const auto ignored_dirs = std::unordered_set<std::string>{".git", config.build_dir, CACHE_DIR_NAME};
        const auto all_sources = TargetDiscovery::find_source_files(".", ignored_dirs, config.exclude_patterns);
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

        for (const auto& discovered_target : discovered) {
            out::info("Automatically configuring target '{}'", discovered_target.suggested_name);
            Target target;
            target.name = discovered_target.suggested_name;
            target.main_file = discovered_target.main_file.string();
            target.output_name = target.name;
            target.cflags = "-std=c11";
            target.cxxflags = "-std=c++20";

            out::info("  -> Using all {} suggested source files.", discovered_target.suggested_sources.size());
            for (const auto& src : discovered_target.suggested_sources) {
                target.sources.push_back(src.string());
            }

            config.targets.push_back(target);
        }

        if (!config.targets.empty()) {
            config.default_target = config.targets[0].name;
            out::info("Setting default target to '{}'", config.default_target);
        }
    }
};

class CLIHandler {
public:
    struct CommandResult {
        int exit_code = 0;
        bool handled = false;
    };

    CLIHandler();
    CommandResult handle_command(int argc, char* argv[]) const;

private:
    struct Command {
        std::string description;
        std::function<int(const std::vector<std::string>&)> handler;
        std::vector<std::string> aliases;
    };

    std::unordered_map<std::string, Command> commands_;

    const fs::path config_toml_path_ = CONFIG_FILE_NAME;
    const fs::path cache_dir_ = CACHE_DIR_NAME;
    const fs::path base_db_path_ = DB_FILE_NAME;
    const fs::path log_path_ = AUTOCC_LOG_FILE_NAME;

    int handle_build(const std::vector<std::string>& args) const;
    int handle_fetch(const std::vector<std::string>& args) const;
    int handle_autoconfig(const std::vector<std::string>& args) const;
    int handle_setup(const std::vector<std::string>& args) const;
    int handle_wipe(const std::vector<std::string>& args) const;

    #ifdef USE_TUI
    int handle_edit(const std::vector<std::string>& args) const;
    #endif

    static int handle_help(const std::vector<std::string>& args);
    static int handle_version(const std::vector<std::string>& args);
    static int handle_clean(const std::vector<std::string>& args);
    static int handle_install(const std::vector<std::string>& args);
    static void install_headers(const std::string& include_dir, const std::string& target_name);
    static int install_executable(const fs::path& target_path, const std::string& target_name);
    static int install_static_library(const fs::path& target_path, const std::string& target_name);
    static int install_dynamic_library(const fs::path& target_path, const std::string& target_name);
    bool is_project_setup() const;
    bool sync_config_if_needed() const;
    int do_setup() const;
    void register_commands();
};

CLIHandler::CLIHandler() {
    register_commands();
}

void CLIHandler::register_commands() {
    commands_["fetch"] = {"Download the base database",
        [this](const auto& args) { return handle_fetch(args); }, {}};
    commands_["help"] = {"Show help information",
        &CLIHandler::handle_help, {}};
    commands_["version"] = {"Show version information",
        &CLIHandler::handle_version, {}};
    commands_["autoconfig"] = {"Create a new 'autocc.toml' config file",
        [this](const auto& args) { return handle_autoconfig(args); }, {"ac"}};
    commands_["setup"] = {"Sync 'autocc.toml' to the internal build cache",
        [this](const auto& args) { return handle_setup(args); }, {"sync", "sc"}};
    commands_["clean"] = {"Remove the build directory",
        &CLIHandler::handle_clean, {}};
    commands_["wipe"] = {"Remove all autocc files (build dir, cache, db)",
        [this](const auto& args) { return handle_wipe(args); }, {}};
    commands_["install"] = {"Install the default target to the system",
        [this](const auto& args) { return handle_install(args); }, {}};
    #ifdef USE_TUI
    commands_["edit"] = {"Edit target source files interactively",
        [this](const auto& args) { return handle_edit(args); }, {"select"}};
    #endif

    // Register aliases
    for (const auto &command_info: commands_ | std::views::values) {
        for (const auto& alias : command_info.aliases) {
            commands_[alias] = command_info;
        }
    }
}

CLIHandler::CommandResult CLIHandler::handle_command(const int argc, char* argv[]) const {
    const std::vector<std::string> args(argv, argv + argc);

    // Handle explicit commands first (fast path)
    if (argc >= 2 && commands_.contains(args[1])) {
        const std::string& command = args[1];
        return {commands_.at(command).handler(args), true};
    }

    // Handle build commands (need project setup)
    if (!is_project_setup()) {
        out::warn("Project not found/setup, consider running 'autocc autoconfig' then 'autocc setup'.");
        return {handle_help(args), true};
    }

    // Default to build command (no args or unknown target name)
    return {handle_build(args), true};
}

bool CLIHandler::is_project_setup() const {
    return fs::exists(cache_dir_ / CONFIG_CACHE_FILE_NAME);
}

int CLIHandler::do_setup() const {
    if (!Validation::validateVersion()) {
        out::error("Version mismatch. please make sure you have a compatible autocc build and '{}' in your '{}'.", Validation::getCurrentValidationPattern(), CONFIG_FILE_NAME);
        return 1;
    }

    if (!fs::exists(config_toml_path_)) {
        out::error("'{}' not found. Run 'autocc autoconfig' to create it.", config_toml_path_);
        return 1;
    }

    const auto config_opt = Configuration::read_config_from_toml(config_toml_path_);
    if (!config_opt) {
        return 1; // Error already printed by read_config_from_toml
    }

    out::info("Syncing '{}' to internal cache...", config_toml_path_);
    // Create an instance without running auto-detection; setup just syncs the config.
    const AutoCC autocc(*config_opt, false);
    autocc.writeConfigCache();

    // Create an empty dependency cache to ensure a clean state after setup.
    std::ofstream out_cache(cache_dir_ / DEP_CACHE_FILE_NAME);
    out_cache << "{}";
    out_cache.close();

    out::success("Setup complete. You can now run 'autocc' to build.");
    return 0;
}

bool CLIHandler::sync_config_if_needed() const {

    if (!fs::exists(config_toml_path_)) {
        return true; // No toml, nothing to sync from.
    }
    if (!is_project_setup()) {
        out::error("Project not set up, but '{}' exists. Please run setup.", config_toml_path_);
        return false;
    }

    try {
        if (fs::last_write_time(config_toml_path_) <= fs::last_write_time(cache_dir_ / CONFIG_CACHE_FILE_NAME)) {
            return true; // Cache is up to date.
        }
    } catch(const fs::filesystem_error& e) {
        out::warn("Could not check file modification times: {}. Assuming sync is needed.", e.what());
    }

    out::info("'{}' is newer than the cache. Syncing configuration automatically...", config_toml_path_);
    return do_setup() == 0;
}

int CLIHandler::handle_build(const std::vector<std::string>& args) const {

    if (!sync_config_if_needed()) {
        return 1;
    }

    const auto autocc_opt = AutoCC::load_from_cache();
    if (!autocc_opt) {
        out::error("Failed to load project from cache. Try running 'autocc setup' again.");
        return 1;
    }

    const std::string target_name = args.size() > 1 ? args[1] : "";
    return autocc_opt->build(target_name);
}

int CLIHandler::handle_fetch(const std::vector<std::string>&) const {
    Fetcher::download_file(BASE_DB_URL, base_db_path_);
    return 0;
}

int CLIHandler::handle_help(const std::vector<std::string>&) {
    Information::show_help();
    return 0;
}

int CLIHandler::handle_version(const std::vector<std::string>&) {
    Information::show_version();
    return 0;
}

int CLIHandler::handle_autoconfig(const std::vector<std::string>& args) const {
    if (!exists(base_db_path_)) {
        Fetcher::download_file(BASE_DB_URL, base_db_path_);
    }

    Config config;
    if (args.size() > 2 && args[2] == "--default") {
        Setup::default_init(config);
    } else {
        Setup::user_init(config);
    }

    // Auto-detection runs here to populate includes and libraries before writing the TOML
    const auto scanner = AutoCC(std::move(config), true);
    Configuration::write_config_to_toml(scanner.config, config_toml_path_);
    out::info("Run 'autocc setup' to prepare for building.");
    return 0;
}
#ifdef USE_TUI
int CLIHandler::handle_edit(const std::vector<std::string>&) const {
    out::info("Loading configuration for editing...");
    if (!Validation::validateVersion()) {
        out::error("Version mismatch. please make sure you have a compatible autocc build and '{}' in your '{}'.", Validation::getCurrentValidationPattern(), CONFIG_FILE_NAME);
        return 1;
    }

    const auto config_opt = Configuration::read_config_from_toml(config_toml_path_);
    if (!config_opt) {
        out::error("Could not load '{}'. Run 'autocc autoconfig' first.", config_toml_path_);
        return 1;
    }

    Config config = *config_opt;
    if (config.targets.empty()) {
        out::error("No targets found in '{}'. Nothing to edit.", config_toml_path_);
        return 1;
    }

    const auto ignored_dirs = std::unordered_set<std::string>{".git", config.build_dir, CACHE_DIR_NAME};
    const auto all_sources = TargetDiscovery::find_source_files(".", ignored_dirs, config.exclude_patterns);

    if (all_sources.empty()) {
        out::error("No source files found in the project. Cannot open editor.");
        return 1;
    }

    bool changed = false;
    for (auto& target : config.targets) {
        out::info("Opening TUI editor for target: {}", target.name);

        std::vector<std::string> new_sources = SourceEditor::run(target, all_sources);
        std::ranges::sort(target.sources);
        std::ranges::sort(new_sources);

        if (target.sources != new_sources) {
            out::info("Updating sources for target '{}'. Old count: {}, New count: {}.",
                      target.name, target.sources.size(), new_sources.size());
            target.sources = std::move(new_sources);
            changed = true;
        } else {
            out::info("No changes made for target '{}'.", target.name);
        }
    }

    out::info("\nAll targets processed.");
    if (!changed) {
        out::info("No changes were made to any target.");
        return 0;
    }

    out::warn("This will overwrite your 'autocc.toml' with the new selections.");
    fmt::print(stdout, "{} (y/n)? ", fmt::styled("Do you want to save your changes?", COLOR_PROMPT));
    std::string confirmation;
    std::getline(std::cin, confirmation);

    if (confirmation == "y" || confirmation == "yes") {
        Configuration::write_config_to_toml(config, config_toml_path_);
        out::info("To apply changes, run 'autocc setup' to sync the new config to the cache.");
    } else {
        out::info("Operation cancelled. 'autocc.toml' was not modified.");
    }
    return 0;
}
#endif

int CLIHandler::handle_setup(const std::vector<std::string>&) const {
    return do_setup();
}

int CLIHandler::handle_clean(const std::vector<std::string>&) {
    Config autocc_opt;
    if (!AutoCC::read_config_cache_static(autocc_opt)) {
        out::error("Cache not found, cannot determine build directory. Nothing to clean.");
        return 1;
    }

    const auto& build_dir = autocc_opt.build_dir;
    if (build_dir.empty() || build_dir == "." || build_dir == "/") {
        out::error("Invalid build directory configured: '{}'. Clean aborted for safety.", build_dir);
        return 1;
    }

    out::info("Cleaning build directory '{}'...", build_dir);
    if (fs::exists(build_dir)) {
        try {
            fs::remove_all(build_dir);
            out::success("Clean complete.");
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to remove build directory '{}': {}", build_dir, e.what());
            return 1;
        }
    }
    return 0;
}

int CLIHandler::handle_wipe(const std::vector<std::string>&) const {
    Config temp_cfg;
    if (!AutoCC::read_config_cache_static(temp_cfg)) {
        out::error("Cache not found, cannot determine build directory. Nothing to clean.");
        return 1;
    }

    out::warn("Wiping all autocc files (build dir and cache)...");

    for (const std::vector<fs::path> paths_to_remove = {temp_cfg.build_dir, cache_dir_, base_db_path_, log_path_}; const auto& path : paths_to_remove) {
        if (!fs::exists(path) || path.empty()) continue;

        try {
            fs::remove_all(path);
            out::info("Removed '{}'.", path);
        } catch (const fs::filesystem_error& e) {
            out::error("Failed to remove '{}': {}", path, e.what());
        }
    }

    out::success("Wipe complete. 'autocc.toml' was not removed.");
    return 0;
}

int CLIHandler::handle_install(const std::vector<std::string>& args) {
    Config config;
    if (!Validation::validateVersion()) {
        out::warn("Your config file might not be up-to-date with current autocc version.");
    }
    if (!AutoCC::read_config_cache_static(config)) {
        out::error("Project cache not found. Please run 'autocc setup' first.");
        return 1;
    }

    // Determine target
    std::string target_name = args.size() > 2 ? args[2] : config.default_target;
    if (target_name.empty()) {
        out::error("No default target is set. Cannot run install.");
        return 1;
    }

    // Find target
    const auto target_it = std::ranges::find_if(config.targets,
        [&](const Target& t) { return t.name == target_name; });

    if (target_it == config.targets.end()) {
        out::error("Target '{}' not found. Available targets: {}",
                  target_name,
                  fmt::join(config.targets | std::views::transform([](const Target& t) { return t.name; }), ", "));
        return 1;
    }

    const auto& target = *target_it;
    const fs::path target_path = fs::path(config.build_dir) / target.output_name;

    if (!fs::exists(target_path)) {
        out::error("Target '{}' not found at '{}'. Please build it first with 'autocc {}'.",
                  target_name, target_path, target_name);
        return 1;
    }

    // Handle different target types
    if (target.type == "Executable")
        return install_executable(target_path, target_name);
    if (target.type == "DLibrary")
        return install_dynamic_library(target_path, target_name);
    if (target.type == "SLibrary")
        return install_static_library(target_path, target_name);
    out::error("Unknown target type: {}", target.type);
    return 1;
}

int CLIHandler::install_executable(const fs::path& target_path, const std::string& target_name) {
    const std::string install_dir = "/usr/local/bin";

    std::string cmd;
    if (fs::exists(AUTOINSTALL_SCRIPT_PATH)) {
        cmd = fmt::format("./{} {}", AUTOINSTALL_SCRIPT_PATH, target_path.string());
    } else if (Execution::isCommandExecutable("install")) {
        cmd = fmt::format("install -m 755 {} {}/{}", target_path, install_dir, target_name);
    } else {
        cmd = fmt::format("cp -f {} {}/{} && chmod +x {}/{}",
                        target_path, install_dir, target_name, install_dir, target_name);
    }

    if (const auto res = Execution::execute(cmd); res.exit_code != 0) {
        out::error("Failed to install executable '{}'. Exit code: {}", target_name, res.exit_code);
        if (!res.stderr_output.empty()) out::error("Error: {}", res.stderr_output);
        return 1;
    }

    out::success("Installed executable '{}' to {}/{}", target_name, install_dir, target_name);
    return 0;
}

int CLIHandler::install_dynamic_library(const fs::path& target_path, const std::string& target_name) {
    const std::string lib_dir = "/usr/local/lib";
    const std::string include_dir = "/usr/local/include";

    // Install the .so file
    std::string install_lib_cmd;
    if (Execution::isCommandExecutable("install")) {
        install_lib_cmd = fmt::format("install -m 644 {} {}/", target_path, lib_dir);
    } else {
        install_lib_cmd = fmt::format("cp -f {} {}/", target_path, lib_dir);
    }

    if (const auto res = Execution::execute(install_lib_cmd); res.exit_code != 0) {
        out::error("Failed to install dynamic library '{}'. Exit code: {}", target_name, res.exit_code);
        return 1;
    }

    // Install headers if they exist
    install_headers(include_dir, target_name);

    if (Execution::isCommandExecutable("ldconfig")) {
        if (const auto res = Execution::execute("ldconfig"); res.exit_code != 0) {
            out::error("Failed to run 'ldconfig'");
            return 1;
        }
        out::info("Updated library cache with ldconfig");
    }

    out::success("Installed dynamic library '{}' to {}", target_name, lib_dir);
    return 0;
}

int CLIHandler::install_static_library(const fs::path& target_path, const std::string& target_name) {
    const std::string lib_dir = "/usr/local/lib";
    const std::string include_dir = "/usr/local/include";

    // Install the .a file
    std::string install_lib_cmd;
    if (Execution::isCommandExecutable("install")) {
        install_lib_cmd = fmt::format("install -m 644 {} {}/", target_path, lib_dir);
    } else {
        install_lib_cmd = fmt::format("cp -f {} {}/", target_path, lib_dir);
    }

    if (const auto res = Execution::execute(install_lib_cmd); res.exit_code != 0) {
        out::error("Failed to install static library '{}'. Exit code: {}", target_name, res.exit_code);
        return 1;
    }

    // Install headers
    install_headers(include_dir, target_name);

    out::success("Installed static library '{}' to {}", target_name, lib_dir);
    return 0;
}

void CLIHandler::install_headers(const std::string& include_dir, const std::string& target_name) {
    // Look for common header directories
    for (const std::vector<std::string> header_dirs = {"include", "inc", "headers"}; const auto& dir : header_dirs) {
        if (fs::exists(dir) && fs::is_directory(dir)) {
            std::string target_include_dir = fmt::format("{}/{}", include_dir, target_name);

            // Create target include directory
            std::string mkdir_cmd = fmt::format("mkdir -p {}", target_include_dir);
            if (const auto res = Execution::execute(mkdir_cmd); res.exit_code != 0) {
                out::error("Failed to create directory '{}'. Exit code: {}", target_include_dir, res.exit_code);
                return;
            }
            // Copy headers
            std::string copy_cmd;
            if (Execution::isCommandExecutable("rsync")) {
                copy_cmd = fmt::format("rsync -av {}/ {}/", dir, target_include_dir);
            } else {
                copy_cmd = fmt::format("cp -r {}/* {}/", dir, target_include_dir);
            }

            if (const auto res = Execution::execute(copy_cmd); res.exit_code == 0) {
                out::info("Installed headers from '{}' to '{}'", dir, target_include_dir);
                return; // Only install from first found directory
            }
        }
    }

    out::warn("No header directory found. Consider creating an 'include/' directory for your headers.");
}


int main(const int argc, char* argv[]) {
    const CLIHandler cli;
    auto [exit_code, handled] = cli.handle_command(argc, argv);

    if (!handled) {
        out::error("Unknown command {}. Use 'autocc help' for usage.", argv[1]);
        return 1;
    }

    return exit_code;
}