#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <regex>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
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

using json = nlohmann::json;

#define DATE __DATE__
#define TIME __TIME__
#define VERSION "v0.1.1" // Incremented version for changes

namespace fs = std::filesystem;
using DependencyMap = std::unordered_map<fs::path, std::unordered_set<fs::path>>;

std::mutex g_output_mutex; // Definition for the extern in out.hpp

// --- Constants ---
static constexpr auto CACHE_DIR_NAME = ".autocc_cache";
static constexpr auto CONFIG_FILE_NAME = "config.cache";
static constexpr auto DEP_CACHE_FILE_NAME = "deps.cache";
static constexpr auto PCH_HEADER_NAME = "autocc_pch.hpp";
static constexpr auto DB_FILE_NAME = "autocc.base.json";
static constexpr auto BASE_DB_URL = "https://raw.githubusercontent.com/assembler-0/autocc/refs/heads/main/autocc.base.json";

template <>
struct fmt::formatter<fs::path> : formatter<std::string_view> {
    auto format(const fs::path& p, format_context& ctx) const{
        return formatter<std::string_view>::format(p.string(), ctx);
    }
};

struct Config {
    std::string cc = "clang";
    std::string cxx = "clang++";
    std::string as = "nasm";
    std::string name = "a.out";
    std::string cxxflags = "-march=native -std=c++23 -O2 -pipe";
    std::string cflags = "-march=native -std=c11 -O2 -pipe";
    std::string ldflags;
    std::string build_dir = ".autocc_build";
    bool use_pch = true;
    std::vector<std::string> include_dirs;
    std::vector<std::string> external_libs;
    bool manual_mode = false;
};

std::string hash_file(const fs::path& path) {
    constexpr size_t buffer_size = 65536; // 64KB buffer
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }

    std::vector<char> buffer(buffer_size);
    XXH64_state_t* const state = XXH64_createState();
    XXH64_reset(state, 0); // Use seed 0

    while (file.read(buffer.data(), buffer_size)) {
        XXH64_update(state, buffer.data(), file.gcount());
    }
    // Handle the last chunk
    if (file.gcount() > 0) {
        XXH64_update(state, buffer.data(), file.gcount());
    }

    XXH64_hash_t const hash_val = XXH64_digest(state);
    XXH64_freeState(state);

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

    auto tbl = toml::table{
            {"project", toml::table{
                {"name", config.name},
                {"build_dir", config.build_dir}
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
                {"external_libs", libs_arr}
            }}
    };

    std::ofstream file(toml_path);
    file << tbl;
    out::success("Configuration saved to '{}'.", toml_path);
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

        config.name      = get_or(tbl["project"]["name"].as_string(), "a.out");
        config.build_dir = get_or(tbl["project"]["build_dir"].as_string(), ".autocc_build");
        config.cxx       = get_or(tbl["compilers"]["cxx"].as_string(), "clang++");
        config.cc        = get_or(tbl["compilers"]["cc"].as_string(), "clang");
        config.as        = get_or(tbl["compilers"]["as"].as_string(), "nasm");
        config.cxxflags  = get_or(tbl["flags"]["cxxflags"].as_string(), "-march=native -std=c++23 -O2 -pipe");
        config.cflags    = get_or(tbl["flags"]["cflags"].as_string(), "-march=native -std=c11 -O2 -pipe");
        config.ldflags   = get_or(tbl["flags"]["ldflags"].as_string(), "");
        config.use_pch   = get_bool_or(tbl["features"]["use_pch"].as_boolean(), true);

        if (auto* includes = tbl["paths"]["include_dirs"].as_array()) {
            for (const auto& elem : *includes) { config.include_dirs.emplace_back(elem.value_or("")); }
        }
        if (auto* libs = tbl["paths"]["external_libs"].as_array()) {
            for (const auto& elem : *libs) { config.external_libs.emplace_back(elem.value_or("")); }
        }

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
                client.set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");
                client.set_follow_location(true);
                client.set_connection_timeout(std::chrono::seconds(5)); // 5-second connection timeout
                client.set_read_timeout(std::chrono::seconds(10));    // 10-second read timeout

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
                    file.write(res->body.c_str(), res->body.size());
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
    static bool parse_url(const std::string& url, std::string& host, std::string& path) {
        const std::string protocol_end = "://";
        size_t host_start = url.find(protocol_end);
        if (host_start == std::string::npos) return false;
        host_start += protocol_end.length();
        size_t path_start = url.find('/', host_start);
        if (path_start == std::string::npos) {
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
            out::warn(fmt::runtime("Library database '{}' not found. Attempting to download..."));
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
            for (json data = json::parse(f); auto& [header, rule_json] : data["libraries"].items()) {
                DetectionRule rule;
                if (rule_json.contains("direct_libs")) rule.direct_libs = rule_json["direct_libs"].get<std::vector<std::string>>();
                if (rule_json.contains("pkg_configs")) rule.pkg_configs = rule_json["pkg_configs"].get<std::vector<std::string>>();
                detectionMap[header] = rule;
            }
            out::info("Loaded {} library detection rules.", detectionMap.size());
        } catch (const json::parse_error& e) {
            out::error("Failed to parse library database '{}': {}. Attempting to re-download and parse.", db_path, e.what());
            fs::remove(db_path); // Remove corrupt file
            if (Fetcher::download_file(BASE_DB_URL, db_path)) {
                // Try parsing again after successful download
                try {
                    std::ifstream f(db_path);
                    if (!f.is_open()) {
                        out::error("Failed to open re-downloaded library database '{}'. Library detection will be limited.", db_path);
                        return;
                    }
                    for (json data = json::parse(f); auto& [header, rule_json] : data["libraries"].items()) {
                        DetectionRule rule;
                        if (rule_json.contains("direct_libs")) rule.direct_libs = rule_json["direct_libs"].get<std::vector<std::string>>();
                        if (rule_json.contains("pkg_configs")) rule.pkg_configs = rule_json["pkg_configs"].get<std::vector<std::string>>();
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
        std::unordered_set<std::string> found_direct_libs(config.external_libs.begin(), config.external_libs.end());
        std::unordered_set<std::string> processed_pkg_configs;
        std::string additional_ldflags;
        for (const auto& include : includes) {
            for (const auto& [header_signature, rule] : detectionMap) {
                if (include.find(header_signature) != std::string::npos) {
                    for (const auto& lib : rule.direct_libs) found_direct_libs.insert(lib);
                    for (const auto& pkg_name : rule.pkg_configs) {
                        if (processed_pkg_configs.contains(pkg_name)) continue;
                        if (const auto pkg_result = getPkgConfigFlags(pkg_name); !pkg_result.empty()) {
                            additional_ldflags += " " + pkg_result;
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
        if (!additional_ldflags.empty()) config.ldflags += additional_ldflags;
    }
private:
    std::string getPkgConfigFlags(const std::string& package) {
        if (pkg_cache.contains(package)) return pkg_cache[package];
        const std::string cmd = fmt::format("pkg-config --libs --cflags {}", package);
        CommandResult result = execute(cmd);

        if (result.exit_code != 0) {
            if (result.stderr_output.find("not found") != std::string::npos) {
                out::warn("pkg-config for '{}' failed: Package not found. Is it installed?", package);
            } else if (!result.stderr_output.empty()) {
                out::warn("pkg-config for '{}' failed with error: {}", package, result.stderr_output);
            } else {
                out::warn("pkg-config for '{}' failed with unknown error.", package);
            }
            return "";
        }

        std::string stdout_result = result.stdout_output;
        if (!stdout_result.empty() && stdout_result.back() == '\n') stdout_result.pop_back();
        return pkg_cache[package] = stdout_result;
    }
};
// --- START OF MODIFIED SECTION ---

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
            std::vector<fs::path> files_to_scan = {src_file};
            std::unordered_set<fs::path> scanned_files;
            while (!files_to_scan.empty()) {
                fs::path current_file = files_to_scan.back();
                files_to_scan.pop_back();
                if (scanned_files.contains(current_file)) continue;
                scanned_files.insert(current_file);
                std::ifstream file_stream(current_file);
                if (!file_stream.is_open()) continue;
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
    [[nodiscard]] std::vector<std::string> getAllUniqueIncludes(const std::vector<fs::path>& sourceFiles, const std::vector<std::string>& include_dirs) const {
        std::unordered_set<std::string> unique_includes;
        std::vector<fs::path> files_to_scan = sourceFiles;
        std::unordered_set<fs::path> scanned_files;
        while (!files_to_scan.empty()) {
            fs::path current_file = files_to_scan.back();
            files_to_scan.pop_back();
            if (scanned_files.contains(current_file)) continue;
            scanned_files.insert(current_file);
            std::ifstream file_stream(current_file);
            if (!file_stream.is_open()) continue;
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

    explicit AutoCC(Config cfg) : config(std::move(cfg)) {
        const auto ignored_dirs = getIgnoredDirs();
        source_files = find_source_files(root, ignored_dirs);
    }

    static std::optional<AutoCC> load_from_cache() {
        AutoCC instance;
        if (!instance.readConfigCache()) {
            return std::nullopt;
        }
        const auto ignored_dirs = instance.getIgnoredDirs();
        instance.source_files = find_source_files(instance.root, ignored_dirs);
        if (instance.source_files.empty()) {
            out::error("No source files found.");
            return std::nullopt;
        }
        return instance;
    }

    // This function is now only used by 'autoconfig' to discover and pre-populate the TOML.
    void discover_dependencies_for_config() {
        if (source_files.empty()) {
            out::warn("No source files found to scan for dependencies.");
            return;
        }
        if (!config.manual_mode) {
            out::info("Scanning for local headers and external libraries to suggest in config...");
            scanLocalHeaders();
            detectLibraries();
        }
    }

    void writeConfigCache() const {
        fs::create_directories(cache_dir);
        std::ofstream file(config_file);
        file << "cxx:" << config.cxx << "\n";
        file << "cc:" << config.cc << "\n";
        file << "as:" << config.as << "\n";
        file << "name:" << config.name << "\n";
        file << "cxxflags:" << config.cxxflags << "\n";
        file << "cflags:" << config.cflags << "\n";
        file << "ldflags:" << config.ldflags << "\n";
        file << "build_dir:" << config.build_dir << "\n";
        file << "use_pch:" << (config.use_pch ? "true" : "false") << "\n";
        for (const auto& dir : config.include_dirs) file << "include:" << dir << "\n";
        for (const auto& lib : config.external_libs) file << "lib:" << lib << "\n";
    }

    int build() {
        if (source_files.empty()) {
            out::error("No source files found to build.");
            return 1;
        }

        // --- REFACTOR: Auto-detection is now part of the build process ---
        run_auto_detection();

        const fs::path build_path = config.build_dir;
        fs::create_directories(build_path);

        out::info("Parsing source file dependencies for build...");
        dependency_map = include_parser.parseSourceDependencies(source_files, config.include_dirs);

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

        for (const auto& src_file : source_files) {
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
                    const auto& cached_info = build_cache[obj_file.string()];
                    if (cached_info.value("source_hash", "") != current_source_hash) reason = "source file changed";
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

        if (files_to_compile.empty() && !source_files.empty()) {
            out::success("All {} files are up to date.", source_files.size());
        } else {
            out::info("Compiling {}/{} source files...", files_to_compile.size(), source_files.size());
            std::atomic<bool> compilation_failed = false;
            std::atomic<size_t> file_index = 0;
            const unsigned int num_threads = std::max(1u, std::thread::hardware_concurrency());
            std::vector<std::thread> workers;
            for (unsigned int i = 0; i < num_threads; ++i) {
                workers.emplace_back([&]() {
                    while (true) {
                        if (compilation_failed) return;
                        const size_t index = file_index.fetch_add(1);
                        if (index >= files_to_compile.size()) return;
                        const auto& src = files_to_compile[index];
                        std::string compiler = getCompiler(src);
                        fs::path obj = build_path / src.filename().replace_extension(".o");
                        std::string cmd;
                        if (compiler == config.as) {
                            cmd = fmt::format("{} {} -felf64 -o {}", compiler, src, obj);
                        } else {
                            std::string_view flags = (compiler == config.cxx) ? config.cxxflags : config.cflags;
                            std::string current_pch_flags = (compiler == config.cxx) ? pch_flags : "";
                            cmd = fmt::format("{} -c {} -o {} {} {} {}", compiler, src, obj, flags, current_pch_flags, fmt::join(config.include_dirs, " "));
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

        const fs::path target_path = fs::path(config.build_dir) / config.name;
        if (files_to_compile.empty() && fs::exists(target_path)) {
             out::success("Build complete. Executable '{}' is up to date.", target_path.string());
             return 0;
        }

        out::info("Linking target...");
        const std::string link_cmd = fmt::format("{} -o {} {} {} {} {}",
            config.cxx, target_path, fmt::join(object_files, " "),
            config.cxxflags, config.ldflags, fmt::join(config.external_libs, " "));
        out::command("{}", link_cmd);

        if (auto [exit_code, stdout_output, stderr_output] = execute(link_cmd); exit_code != 0) {
            out::error("Failed to link target: {}", config.name);
            std::lock_guard lock(g_output_mutex);
            fmt::print(stderr, "{}\n", stderr_output);
            return 1;
        }
        std::ofstream out_cache(dep_cache_file);
        out_cache << new_build_cache.dump(2);
        out::success("Target '{}' built successfully in '{}'.", config.name, config.build_dir);
        return 0;
    }

private:
    AutoCC() = default;
    const fs::path root = ".";
    const fs::path cache_dir = root / CACHE_DIR_NAME;
    const fs::path config_file = cache_dir / CONFIG_FILE_NAME;
    const fs::path dep_cache_file = cache_dir / DEP_CACHE_FILE_NAME;
    std::vector<fs::path> source_files;
    LibraryDetector lib_detector;
    IncludeParser include_parser;
    DependencyMap dependency_map;

    void run_auto_detection() {
        if (config.manual_mode) return;
        out::info("Auto-detecting headers and libraries...");
        scanLocalHeaders();
        detectLibraries();
    }

    bool readConfigCache() {
        if (!fs::exists(config_file)) return false;
        std::ifstream file(config_file);
        std::string line;
        config.include_dirs.clear();
        config.external_libs.clear();
        while (std::getline(file, line)) {
            const auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            const std::string_view key = std::string_view(line).substr(0, pos);
            std::string_view value = std::string_view(line).substr(pos + 1);
            if (key == "cxx") config.cxx = value;
            else if (key == "cc") config.cc = value;
            else if (key == "as") config.as = value;
            else if (key == "name") config.name = value;
            else if (key == "cxxflags") config.cxxflags = value;
            else if (key == "cflags") config.cflags = value;
            else if (key == "ldflags") config.ldflags = value;
            else if (key == "build_dir") config.build_dir = value;
            else if (key == "use_pch") config.use_pch = (value == "true");
            else if (key == "include") config.include_dirs.emplace_back(value);
            else if (key == "lib") config.external_libs.emplace_back(value);
        }
        return true;
    }
    std::unordered_set<std::string> getIgnoredDirs() const {
        return {".git", config.build_dir, CACHE_DIR_NAME};
    }
    void scanLocalHeaders() {
        std::set<fs::path> header_dirs;
        for (const auto& entry : fs::recursive_directory_iterator(root)) {
            if (entry.is_regular_file()) {
                const std::string ext = entry.path().extension().string();
                if (ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".hh") {
                    header_dirs.insert(fs::canonical(entry.path().parent_path()));
                }
            }
        }
        // Use a set to avoid duplicate -I flags from TOML and scan
        std::unordered_set<std::string> final_includes;
        for (const auto& dir : config.include_dirs) final_includes.insert(dir);
        for (const auto& dir : header_dirs) final_includes.insert(fmt::format("-I{}", dir.string()));
        config.include_dirs.assign(final_includes.begin(), final_includes.end());
    }
    void detectLibraries() {
        const auto all_includes = include_parser.getAllUniqueIncludes(source_files, config.include_dirs);
        lib_detector.detect(all_includes, config);
    }
    std::string generatePCH(const fs::path& build_path) {
        out::info("Analyzing for Pre-Compiled Header generation...");
        std::unordered_map<std::string, int> include_counts;
        int cpp_file_count = 0;
        for (const auto& src : source_files) {
            if (getCompiler(src) != config.cxx) continue;
            cpp_file_count++;
            std::ifstream stream(src);
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
        for(const auto& header : pch_headers) pch_file << "#include <" << header << ">\n";
        pch_file.close();
        const std::string pch_compile_cmd = fmt::format("{} -x c++-header {} -o {} {} {}",
            config.cxx, pch_source, pch_out, config.cxxflags, fmt::join(config.include_dirs, " "));
        out::command("{}", pch_compile_cmd);
        if (auto [exit_code, stdout_output, stderr_output] = execute(pch_compile_cmd); exit_code != 0) {
            out::warn("PCH generation failed. Continuing without it.\n   Compiler error: {}", stderr_output);
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
};


// --- User Interaction and Main ---

void show_help() {
    using fmt::styled;
    out::info("AutoCC {} - A smaller C++ build system", VERSION);
    fmt::print(
        "\n"
        "Usage: autocc [command]\n\n"
        "Commands:\n"
        "  {}               Builds the project incrementally using cached settings.\n"
        "  {}        Auto-generated autocc.toml.\n"
        "  {}        Convert autocc.toml to autocc build cache.\n"
        "  {}              Same as no command (argc = 1).\n"
        "  {}                Remove build directory.\n"
        "  {}                Removes all autocc generated files\n"
        "  {}                Download/update the library detection database.\n"
        "  {}                 Show current version and build date.\n"
        "  {}              Shows this help message.\n",
        styled("<none>", out::color_prompt),
        styled("ac/autoconfig", out::color_prompt),
        styled("setup/sync/sc", out::color_prompt),
        styled("compile", out::color_prompt),
        styled("clean", out::color_prompt),
        styled("clean", out::color_prompt),
        styled("fetch", out::color_prompt),
        styled("wipe", out::color_prompt),
        styled("version", out::color_prompt),
        styled("help", out::color_prompt)
    );
}

void show_version() {
    fmt::print("AutoCC {} compiled on {} at {}\n",
        fmt::styled(VERSION, out::color_success),
        fmt::styled(DATE, out::color_info),
        fmt::styled(TIME, out::color_info)
    );
}

void user_init(Config& config) {
    auto get_input = [](const std::string_view prompt, const std::string_view default_val) -> std::string {
        fmt::print(stdout, "{} ({})? ",
            fmt::styled(prompt, out::color_prompt),
            fmt::styled(default_val, out::color_default));
        std::string input;
        std::getline(std::cin, input);
        return input.empty() ? std::string(default_val) : input;
    };

    config.cc = get_input("C Compiler", config.cc);
    config.cxx = get_input("C++ Compiler", config.cxx);
    config.as = get_input("Assembler", config.as);
    config.name = get_input("Executable Name", config.name);
    config.cxxflags = get_input("CXX Flags", config.cxxflags);
    config.cflags = get_input("CC Flags", config.cflags);
    config.ldflags = get_input("Linker Flags", config.ldflags);
    config.build_dir = get_input("Build Directory", config.build_dir);
    std::string pch_choice = get_input("Use Pre-Compiled Headers (yes/no)", config.use_pch ? "yes" : "no");
    config.use_pch = (pch_choice == "yes" || pch_choice == "y");

}
int main(const int argc, char* argv[]) {
    const fs::path config_toml_path = "autocc.toml";
    const fs::path cache_dir = CACHE_DIR_NAME;
    const fs::path base_db_path = DB_FILE_NAME;

    if (argc < 2) {
        if (!fs::exists(cache_dir / CONFIG_FILE_NAME)) {
            out::error("Project not set up. Run 'autocc setup' first.");
            out::info("If you have no 'autocc.toml', run 'autocc autoconfig' to create one.");
            return 1;
        }
        if (fs::exists(config_toml_path) && fs::exists(cache_dir / CONFIG_FILE_NAME) && fs::last_write_time(config_toml_path) > fs::last_write_time(cache_dir / CONFIG_FILE_NAME)) {
             out::warn("'autocc.toml' has been modified. Run 'autocc setup' to sync changes.");
        }
        auto autocc_opt = AutoCC::load_from_cache();
        if (!autocc_opt) {
            out::error("Failed to load project from cache. Try running 'autocc setup' again.");
            return 1;
        }
        return autocc_opt->build();
    }

    std::string command = argv[1];

    if (command == "fetch") { Fetcher::download_file(BASE_DB_URL, base_db_path); return 0; }
    if (command == "help") { show_help(); return 0; }
    if (command == "version") { show_version(); return 0; }

    if (command == "autoconfig" || command == "ac") {
        if (!fs::exists(DB_FILE_NAME)) {
            out::info("Fetching latest library database for initial configuration...");
            if (!Fetcher::download_file(BASE_DB_URL, base_db_path)) {
                out::warn("Failed to download library database. Library detection might be limited.");
            }
        }
        if (fs::exists(config_toml_path)) {
            out::warn("'autocc.toml' already exists. Overwriting.");
        }
        out::info("Starting interactive configuration...");
        Config config;
        user_init(config);

        // This scan is for PRE-POPULATING the TOML file with good suggestions.
        AutoCC scanner(config);
        scanner.discover_dependencies_for_config();

        write_config_to_toml(scanner.config, config_toml_path);
        out::info("Now run 'autocc setup' to prepare the build environment.");
        return 0;
    }

    if (command == "setup" || command == "sync" || command == "sc") {
        out::info("Syncing build environment from '{}'...", config_toml_path);
        const auto config_opt = load_config_from_toml(config_toml_path);
        if (!config_opt) {
            out::error(fmt::runtime("Could not load '{}'. Run 'autocc autoconfig' to create it."));
            return 1;
        }
        if (fs::exists(cache_dir)) {
            fs::remove_all(cache_dir);
        }
        AutoCC autocc(*config_opt);
        autocc.writeConfigCache(); // Core of "setup": create the internal cache from TOML.

        // Create an empty dependency cache to start with.
        std::ofstream out_cache(cache_dir / DEP_CACHE_FILE_NAME);
        out_cache << "{}";
        out_cache.close();

        out::success("Setup complete. You can now run 'autocc' to build.");
        return 0;
    }

    if (command == "compile") {
        if (!fs::exists(cache_dir / CONFIG_FILE_NAME)) {
            out::error("Project not set up. Run 'autocc setup' first.");
            return 1;
        }
        auto autocc_opt = AutoCC::load_from_cache();
        if (!autocc_opt) {
            out::error("Failed to load project from cache. Try 'autocc setup' again.");
            return 1;
        }
        return autocc_opt->build();
    }

    if (command == "clean") {
        if (const auto optional = AutoCC::load_from_cache()) {
            Config temp_cfg = optional->config;
            out::info("Cleaning build directory '{}'...", temp_cfg.build_dir);
            if (fs::exists(temp_cfg.build_dir)) fs::remove_all(temp_cfg.build_dir);
            out::success("Clean complete. Targets and objects removed.");
        } else {
            out::warn("Cache not found, cannot determine build directory. Nothing to clean.");
        }
        return 0;
    }

    if (command == "wipe") {
        Config temp_cfg;
        if (const auto optional = AutoCC::load_from_cache()) {
            temp_cfg = optional->config;
        }
        out::warn("Wiping all autocc files (build dir and cache)...");
        if (fs::exists(temp_cfg.build_dir)) fs::remove_all(temp_cfg.build_dir);
        if (fs::exists(cache_dir)) fs::remove_all(cache_dir);
        if (fs::exists(base_db_path)) fs::remove(base_db_path);
        out::success("Wipe complete. 'autocc.toml' was not removed.");
        return 0;
    }

    out::error("Unknown command: '{}'. Use 'autocc help' for usage.", command);
    return 1;
}
