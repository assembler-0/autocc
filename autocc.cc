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
#define VERSION "v0.1"

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
    // --- New Part: Manually create TOML arrays ---
    auto includes_arr = toml::array{};
    for (const auto& dir : config.include_dirs) {
        includes_arr.push_back(dir);
    }

    auto libs_arr = toml::array{};
    for (const auto& lib : config.external_libs) {
        libs_arr.push_back(lib);
    }
    // --- End of New Part ---

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
                // Now we use the arrays we created above
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

        // Helper to safely get values
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
            for (const auto& elem : *includes) { config.include_dirs.push_back(elem.value_or("")); }
        }
        if (auto* libs = tbl["paths"]["external_libs"].as_array()) {
            for (const auto& elem : *libs) { config.external_libs.push_back(elem.value_or("")); }
        }

        return config;

    } catch (const toml::parse_error& err) {
        out::error("Failed to parse '{}':\n{}", toml_path, err.description());
        return std::nullopt;
    }
}

class Fetcher {
public:

    bool download_file(const std::string& url, const fs::path& dest_path) {
        out::info("Attempting to download from {}...", url);

        try {
            std::string host, path;
            if (!parse_url(url, host, path)) {
                out::error("Invalid URL format: {}", url);
                return false;
            }

            // 1. Declare a unique_ptr to the BASE class in the outer scope.
            std::unique_ptr<httplib::Client> client;

            if (url.rfind("https://", 0) == 0) {
                auto client = std::make_unique<httplib::SSLClient>(host);

                if (auto* ssl_client = client.get()) {
                    ssl_client->set_ca_cert_path("/etc/ssl/certs/ca-certificates.crt");
                }
            } else {
                // Or create a regular Client.
                client = std::make_unique<httplib::Client>(host);
            }

            // Now you can use `client` polymorphically.
            client->set_follow_location(true);

            auto res = client->Get(path.c_str());

            if (!res) {
                out::error("Download failed. Could not connect or invalid response.");
                auto err = res.error();
                out::error("Reason: {}", httplib::to_string(err));
                return false;
            }

            if (res->status == 200) {
                std::ofstream file(dest_path, std::ios::binary);
                file.write(res->body.c_str(), res->body.size());
                // No need for file.close(), it happens automatically when `file` goes out of scope.
                out::success("Successfully downloaded and saved to '{}'.", dest_path);
                return true;
            } else {
                out::error("Download failed. Server responded with status code: {}", res->status);
                return false;
            }

        } catch (const std::exception& e) {
            out::error("An exception occurred during download: {}", e.what());
            return false;
        }
    }

private:
    bool parse_url(const std::string& url, std::string& host, std::string& path) {
        const std::string protocol_end = "://";
        size_t host_start = url.find(protocol_end);
        if (host_start == std::string::npos) {
            return false; // Invalid URL format
        }
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

    // The map is now a member, not a static initializer
    std::unordered_map<std::string, DetectionRule> detectionMap;
    bool rules_loaded = false;

    // A new method to load the rules
    void load_rules_from_file(const fs::path& db_path) {
        if (!fs::exists(db_path)) {
            out::warn("Library database '{}' not found. Library detection will be limited.", db_path);
            return;
        }
        try {
            std::ifstream f(db_path);

            for (json data = json::parse(f); auto& [header, rule_json] : data["libraries"].items()) {
                DetectionRule rule;
                if (rule_json.contains("direct_libs")) {
                    rule.direct_libs = rule_json["direct_libs"].get<std::vector<std::string>>();
                }
                if (rule_json.contains("pkg_configs")) {
                    rule.pkg_configs = rule_json["pkg_configs"].get<std::vector<std::string>>();
                }
                detectionMap[header] = rule;
            }
            out::info("Loaded {} library detection rules.", detectionMap.size());
            rules_loaded = true;
        } catch (const json::parse_error& e) {
            out::error("Failed to parse library database '{}': {}", db_path, e.what());
        }
    }

    std::unordered_map<std::string, std::string> pkg_cache; // Cache for pkg-config results

public:
    LibraryDetector() {
        load_rules_from_file(DB_FILE_NAME);
    }
    void detect(const std::vector<std::string>& includes, Config& config) {
        std::unordered_set found_direct_libs(config.external_libs.begin(), config.external_libs.end());
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

        const std::string cmd = fmt::format("pkg-config --libs --cflags {} 2>/dev/null", package);
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";

        std::string result;
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) result += buffer;
        pclose(pipe);

        if (!result.empty() && result.back() == '\n') result.pop_back();
        return pkg_cache[package] = result;
    }
};

class IncludeParser {

    std::regex include_regex{R"_(\s*#\s*include\s*(?:<([^>]+)>|"([^"]+)"))_"};

    // Finds a header file in the search paths.
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
    // This function now builds a complete dependency map for all source files.
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
                        const auto& header_name = matches[2].str();
                        if (fs::path header_path = findHeader(header_name, current_file.parent_path(), include_dirs); !header_path.empty()) {
                            dependencies.insert(header_path);
                            files_to_scan.push_back(header_path);
                        }
                    }
                }
            }
            dep_map[src_file] = dependencies;
        }
        return dep_map;
    }

    // A simpler function to get all unique includes for library detection.
    [[nodiscard]] std::vector<std::string> getAllUniqueIncludes(const std::vector<fs::path>& sourceFiles) const {
        std::unordered_set<std::string> unique_includes;
        for (const auto& file : sourceFiles) {
            std::ifstream stream(file);
            std::string line;
            while (std::getline(stream, line)) {
                if (std::smatch matches; std::regex_search(line, matches, include_regex)) {
                    unique_includes.insert(matches[1].matched ? matches[1].str() : matches[2].str());
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
        AutoCC instance; // Uses private default constructor
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

    bool scan_and_cache_dependencies() { // Renamed for clarity
        if (source_files.empty()) {
            out::error("No source files (.c, .cpp, .s, etc.) found in the current directory.");
            return false;
        }

        if (!config.manual_mode) {
            out::info("Scanning for local headers and external libraries...");
            scanLocalHeaders();
            detectLibraries();
        }

        // Create the dependency cache
        out::info("Creating dependency cache...");
        dependency_map = include_parser.parseSourceDependencies(source_files, config.include_dirs);
        std::ofstream out_cache(dep_cache_file);
        out_cache << "{}"; // Write an empty JSON object
        out_cache.close();

        return true;
    }

    // Writes the current configuration to the cache file.
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

    // The main explicit build function. Performs compilation and linking.
    // Returns an exit code (0 for success).
    int build() {
        if (source_files.empty()) {
            out::error("No source files found to build.");
            return 1;
        }

        const fs::path build_path = config.build_dir;
        fs::create_directories(build_path);

        out::info("Parsing source file dependencies...");
        dependency_map = include_parser.parseSourceDependencies(source_files, config.include_dirs);
        // --- Step 1: Update & Load Dependency Information ---
        if (fs::exists(dep_cache_file)) {
            // nothing here
        } else {
            // This is a fallback in case the dependency cache was deleted but the config cache wasn't.
            out::warn("Dependency cache not found. Performing a one-time dependency scan.");
            dependency_map = include_parser.parseSourceDependencies(source_files, config.include_dirs);
        }

        json build_cache;
        // --- Step 2: Generate PCH if enabled ---
        std::string pch_flags;
        auto pch_time = fs::file_time_type::min();
        if (config.use_pch) {
            fs::path pch_file;
            pch_file = generatePCH(build_path, pch_flags);
            if(fs::exists(pch_file)) pch_time = fs::last_write_time(pch_file);
        }

        if (fs::exists(dep_cache_file)) {
            std::ifstream f(dep_cache_file);
            build_cache = json::parse(f, nullptr, false); // No-throw parse
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

            // A. Check if object file even exists
            if (!fs::exists(obj_file)) {
                needs_recompile = true;
                reason = "object file missing";
            }

            // B. Calculate current build signature
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

            // C. Compare with cached signature
            if (!needs_recompile) {
                if (!build_cache.contains(obj_file.string())) {
                    needs_recompile = true;
                    reason = "not in cache";
                } else {
                    const auto& cached_info = build_cache[obj_file.string()];
                    if (cached_info.value("source_hash", "") != current_source_hash) {
                        needs_recompile = true;
                        reason = "source file changed";
                    } else if (cached_info.value("flags", "") != current_flags) {
                        needs_recompile = true;
                        reason = "compiler flags changed";
                    } else if (cached_info.value("dep_hashes", json::object()) != current_dep_hashes) {
                        needs_recompile = true;
                        reason = "a header dependency changed";
                    }
                }
            }

            if (needs_recompile) {
                files_to_compile.push_back(src_file);
                out::info("Will recompile {}: {}.", src_file, reason);
            }

            // D. Store the NEW build info for saving later
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
            // --- Step 4: Compile needed files in parallel ---
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
                            // Add PCH flags only for C++ files
                            std::string current_pch_flags = (compiler == config.cxx) ? pch_flags : "";
                            cmd = fmt::format("{} -c {} -o {} {} {} {}", compiler, src, obj, flags, current_pch_flags, fmt::join(config.include_dirs, " "));
                        }

                        out::command("{}", cmd);

                        if (auto [exit_code, stderr_output] = execute(cmd); exit_code != 0) {
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

        // --- Step 5: Link all object files ---
        const fs::path target_path = fs::path(config.build_dir) / config.name;
        // Check if linking is needed
        if (files_to_compile.empty() && fs::exists(target_path)) {
             out::success("Build complete. Executable '{}' is up to date.", target_path.string());
             return 0;
        }

        const std::string link_cmd = fmt::format("{} -o {} {} {} {} {}",
            config.cxx,
            target_path,
            fmt::join(object_files, " "),
            config.cxxflags, // Common flags like -march=native are often useful for linking too
            config.ldflags,
            fmt::join(config.external_libs, " ")
        );

        out::info("Linking target...");
        out::command("{}", link_cmd);
        auto result = execute(link_cmd);
        if (result.exit_code != 0) {
            out::error("Failed to link target: {}", config.name);
            std::lock_guard lock(g_output_mutex);
            fmt::print(stderr, "{}\n", result.stderr_output);
            return 1;
        }
        std::ofstream out_cache(dep_cache_file);
        out_cache << new_build_cache.dump(2);
        out::success("Target '{}' built successfully in '{}'.", config.name, config.build_dir);
        return 0;
    }

private:
    // Private constructor for use by the factory method.
    AutoCC() = default;

    const fs::path root = ".";
    const fs::path cache_dir = root / CACHE_DIR_NAME;
    const fs::path config_file = cache_dir / CONFIG_FILE_NAME;
    const fs::path dep_cache_file = cache_dir / DEP_CACHE_FILE_NAME;

    std::vector<fs::path> source_files;
    LibraryDetector lib_detector;
    IncludeParser include_parser;
    DependencyMap dependency_map;

    bool readConfigCache() {
        if (!fs::exists(config_file)) return false;
        std::ifstream file(config_file);
        std::string line;
        // Clear defaults before reading cache
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
                    header_dirs.insert(entry.path().parent_path());
                }
            }
        }
        for (const auto& dir : header_dirs) {
            config.include_dirs.push_back(fmt::format("-I{}", dir.string()));
        }
    }

    void detectLibraries() {
        const auto all_includes = include_parser.getAllUniqueIncludes(source_files);
        lib_detector.detect(all_includes, config);
    }

    // --- Cache Management ---
    void writeDepCache() const {
        std::ofstream file(dep_cache_file);
        for(const auto& [source, headers] : dependency_map) {
            file << source.string() << ";";
            for(const auto& header : headers) {
                file << header.string() << ",";
            }
            file << "\n";
        }
    }

    void readDepCache() {
        if (!fs::exists(dep_cache_file)) return;
        dependency_map.clear();
        std::ifstream file(dep_cache_file);
        std::string line;
        while(std::getline(file, line)) {
            auto semi_pos = line.find(';');
            if (semi_pos == std::string::npos) continue;
            fs::path source_file(line.substr(0, semi_pos));

            std::string headers_str = line.substr(semi_pos + 1);
            size_t start = 0;
            size_t end = headers_str.find(',');
            while(end != std::string::npos) {
                dependency_map[source_file].insert(fs::path(headers_str.substr(start, end-start)));
                start = end + 1;
                end = headers_str.find(',', start);
            }
        }
    }

    // --- Build Logic Helpers ---
    std::string getCompiler(const fs::path& file) const {
        const std::string ext = file.extension().string();
        if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".c++") return config.cxx;
        if (ext == ".c") return config.cc;
        if (ext == ".s" || ext == ".S" || ext == ".asm") return config.as;
        return config.cxx;
    }

    // --- Pre-Compiled Header (PCH) Generation ---
    fs::path generatePCH(const fs::path& build_path, std::string& pch_flags) {
        out::info("Analyzing for Pre-Compiled Header generation...");
        // Find headers included in > 50% of C++ files
        std::unordered_map<std::string, int> include_counts;
        int cpp_file_count = 0;
        for (const auto& src : source_files) {
            if (getCompiler(src) != config.cxx) continue;
            cpp_file_count++;
            // This is a simplified scan for PCH candidates.
            std::ifstream stream(src);
            std::string line;
            std::regex pch_candidate_regex(R"_(\s*#\s*include\s*<([^>]+)>)_"); // System headers only
            while(std::getline(stream, line)) {
                if(std::smatch matches; std::regex_search(line, matches, pch_candidate_regex)) {
                    include_counts[matches[1].str()]++;
                }
            }
        }

        if (cpp_file_count < 3) {
            out::info("PCH skipped: Not enough C++ source files.");
            return {};
        }

        std::vector<std::string> pch_headers;
        for(const auto& [header, count] : include_counts) {
            if (count > cpp_file_count / 2) {
                pch_headers.push_back(header);
            }
        }

        if (pch_headers.empty()) {
             out::info("PCH skipped: No sufficiently common headers found.");
             return {};
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
        if (const auto [exit_code, stderr_output] = execute(pch_compile_cmd); exit_code != 0) {
            out::warn("PCH generation failed. Continuing without it.");
            out::warn("Compiler error: {}", stderr_output);
            return {};
        }

        // Flag to use the PCH during compilation
        pch_flags = fmt::format("-include {}", pch_source.string());
        return pch_out;
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
        "  {}               Download/update the library detection database.\n"
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
    const fs::path base_db_path = "autocc.base.json";

    if (argc < 2) {
        if (!fs::exists(cache_dir / CONFIG_FILE_NAME)) {
            out::error("Project not set up. Run 'autocc setup' first.");
            out::info("If you have no 'autocc.toml', run 'autocc autoconfig' to create one.");
            return 1;
        }

        // 2. Check for sync (autocc.toml is newer than cache)
        if (fs::exists(config_toml_path) && fs::last_write_time(config_toml_path) > fs::last_write_time(cache_dir / CONFIG_FILE_NAME)) {
             out::warn("'autocc.toml' has been modified. Run 'autocc setup' to sync changes.");
        }

        // 3. Load from cache and build
        auto autocc_opt = AutoCC::load_from_cache();
        if (!autocc_opt) {
            out::error("Failed to load project from cache. Try running 'autocc setup' again.");
            return 1;
        }
        return autocc_opt->build();
    }

    std::string command = argv[1];

    if (command == "fetch") {
        out::info("Fetching latest library database...");
        Fetcher fetch;
        fetch.download_file(BASE_DB_URL, base_db_path);
        return 0;
    }
    
    if (command == "help") { show_help(); return 0; }
    if (command == "version") { show_version(); return 0; }

    // --- AUTOCONFIG command ---
    if (command == "autoconfig" || command == "ac") {
        if (fs::exists(config_toml_path)) {
            out::warn("'autocc.toml' already exists. Overwriting.");
        }
        out::info("Starting interactive configuration...");
        Config config;
        user_init(config); // This is your existing user input function

        out::info("Performing a deep scan for headers and libraries...");
        AutoCC scanner(config); // Create a temporary instance to use its scanning methods
        scanner.scan_and_cache_dependencies(); // This will populate the config object with scanned paths

        write_config_to_toml(scanner.config, config_toml_path);
        out::info("Now run 'autocc setup' to prepare the build environment.");
        return 0;
    }

    // --- SETUP command ---
    if (command == "setup" || command == "sync" || command == "sc") {
        out::info("Setting up build environment from '{}'...", config_toml_path);
        const auto config_opt = load_config_from_toml(config_toml_path);
        if (!config_opt) {
            out::error("Could not load '{}'. Run 'autocc autoconfig' to create it.", config_toml_path);
            return 1;
        }

        // Invalidate old cache
        if (fs::exists(cache_dir)) {
            fs::remove_all(cache_dir);
        }

        AutoCC autocc(*config_opt);
        autocc.writeConfigCache(); // This is the core of "setup": create the internal cache

        // Also create the initial dependency cache
        out::info("Creating dependency cache...");
        autocc.scan_and_cache_dependencies(); // Re-use the scan_and_cache_dependencies, it's perfect for this.

        out::success("Setup complete. You can now run 'autocc compile' or just 'autocc'.");
        return 0;
    }

    // --- COMPILE command (explicit) ---
    if (command == "compile") {
        if (command == "compile") {
            if (!fs::exists(cache_dir / CONFIG_FILE_NAME)) {
                out::error("Project not set up. Run 'autocc setup' first.");
                return 1;
            }
            auto autocc_opt = AutoCC::load_from_cache();
            if (!autocc_opt) {
                out::error("Failed to load project from cache. Try running 'autocc setup' again.");
                return 1;
            }
            return autocc_opt->build();
        }
    }

    // --- CLEAN command ---
    if (command == "clean") {
        if (const auto optional = AutoCC::load_from_cache()) {
            Config temp_cfg = optional->config;
            out::info("Cleaning build directory '{}'...", temp_cfg.build_dir);
            fs::remove_all(temp_cfg.build_dir);
            out::success("Clean complete. Targets and objects removed.");
        } else {
            out::warn("Cache not found, cannot determine build directory. Nothing to clean.");
        }
        return 0;
    }

    // --- WIPE command ---
    if (command == "wipe") {
        Config temp_cfg;
        if (const auto optional = AutoCC::load_from_cache()) {
            temp_cfg = optional->config;
        }
        out::warn("Wiping all autocc files (build dir and cache)...");
        fs::remove_all(temp_cfg.build_dir);
        fs::remove_all(cache_dir);
        fs::remove_all(DB_FILE_NAME);
        out::success("Wipe complete. 'autocc.toml' was not removed.");
        return 0;
    }


    out::error("Unknown command: '{}'. Use 'autocc help' for usage.", command);
    return 1;
}