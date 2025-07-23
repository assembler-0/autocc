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
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/chrono.h>

#include "log.hpp"
#include "utils.hpp"

#define DATE __DATE__
#define TIME __TIME__
#define VERSION "v0.1"
//TODO: FIX EVERYTHING
namespace fs = std::filesystem;
using DependencyMap = std::unordered_map<fs::path, std::unordered_set<fs::path>>;

std::mutex g_output_mutex; // Definition for the extern in out.hpp

// --- Constants ---
static constexpr auto CACHE_DIR_NAME = ".autocc_cache";
static constexpr auto CONFIG_FILE_NAME = "config.cache";
static constexpr auto DEP_CACHE_FILE_NAME = "deps.cache";
static constexpr auto PCH_HEADER_NAME = "autocc_pch.hpp";

template <>
struct fmt::formatter<fs::path> : formatter<std::string_view> {
    auto format(const fs::path& p, format_context& ctx) const {
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

class LibraryDetector {
private:
    struct DetectionRule {
        std::vector<std::string> direct_libs;
        std::vector<std::string> pkg_configs;
    };

    // The detection map remains largely the same...
    // (This map is good, so I'll omit it for brevity to focus on the new logic)
    std::unordered_map<std::string, DetectionRule> detectionMap = {
        // --- Core System & Standard-ish Libraries ---
        // These are fundamental and very common.
        {"math.h",          {.direct_libs = {"-lm"}}},
        {"cmath",           {.direct_libs = {"-lm"}}},
        {"pthread.h",       {.direct_libs = {"-lpthread"}}}, // POSIX Threads
        {"thread",          {.direct_libs = {"-lpthread"}}}, // C++ <thread> often needs this
        {"dlfcn.h",         {.direct_libs = {"-ldl"}}},      // For dynamic library loading (dlopen)
        {"ncurses.h",       {.pkg_configs = {"ncursesw"}}},  // Ncurses for terminal UI
        {"curses.h",        {.pkg_configs = {"ncursesw"}}},  // A common alternative include name

        // --- Graphics & Multimedia ---
        // Best to use pkg-config for these as dependencies can be complex.
        {"GL/gl.h",         {.pkg_configs = {"gl"}}},            // OpenGL
        {"vulkan/", {.pkg_configs = {"vulkan"}}},        // Vulkan
        {"SDL2/SDL.h",      {.pkg_configs = {"sdl2"}}},          // SDL2 Core
        {"SDL2/SDL_image.h",{.pkg_configs = {"SDL2_image"}}},    // SDL2 Image
        {"SDL2/SDL_ttf.h",  {.pkg_configs = {"SDL2_ttf"}}},      // SDL2 TrueType Fonts
        {"SDL2/SDL_mixer.h",{.pkg_configs = {"SDL2_mixer"}}},    // SDL2 Audio Mixer
        {"SFML/Graphics.hpp",{.pkg_configs = {"sfml-graphics"}}},// SFML Graphics
        {"SFML/Window.hpp", {.pkg_configs = {"sfml-window"}}},  // SFML Window
        {"SFML/System.hpp", {.pkg_configs = {"sfml-system"}}},  // SFML System
        {"GLFW/glfw3.h",    {.direct_libs = {"-lglfw"}, .pkg_configs = {"gl"}}}, // GLFW
        {"cairo.h",         {.pkg_configs = {"cairo"}}},         // Cairo 2D graphics
        {"png.h",           {.pkg_configs = {"libpng"}}},        // libpng
        {"jpeglib.h",       {.direct_libs = {"-ljpeg"}}},        // libjpeg
        {"turbojpeg.h",     {.direct_libs = {"-lturbojpeg"}}},   // libjpeg-turbo
        {"OpenAL/al.h",     {.pkg_configs = {"openal"}}},        // OpenAL 3D Audio
        {"AL/al.h",         {.pkg_configs = {"openal"}}},        // Alternative OpenAL path
        {"imgui.h",         {/* Header-only, but requires a backend (e.g., OpenGL, Vulkan) to be linked separately */}},

        // --- GUI Toolkits ---
        {"gtk/gtk.h",       {.pkg_configs = {"gtk+-3.0"}}}, // GTK+ 3
        {"gtk-4.0/gtk/gtk.h",{.pkg_configs = {"gtk4"}}},     // GTK 4
        {"QtWidgets/",      {.pkg_configs = {"Qt6Widgets", "Qt5Widgets"}}}, // Qt Widgets (tries Qt6 first)
        {"QtCore/",         {.pkg_configs = {"Qt6Core", "Qt5Core"}}},       // Qt Core
        {"wx/wx.h",         {.pkg_configs = {"wxwidgets"}}}, // wxWidgets (often needs a more specific .pc file like 'wxwidgets-3.2-gtk3-unicode')

        // --- Data Handling (JSON, XML, YAML, Databases) ---
        {"nlohmann/json.hpp", {/* Header-only */}},
        {"rapidjson/document.h", {/* Header-only */}},
        {"json/json.h",     {.pkg_configs = {"jsoncpp"}}},       // JsonCpp
        {"jansson.h",       {.pkg_configs = {"jansson"}}},       // Jansson C JSON library
        {"libxml/parser.h", {.pkg_configs = {"libxml-2.0"}}},    // libxml2
        {"pugixml.hpp",     {/* Header-only */}},               // pugixml
        {"yaml-cpp/yaml.h", {.pkg_configs = {"yaml-cpp"}}},      // yaml-cpp
        {"sqlite3.h",       {.pkg_configs = {"sqlite3"}}},       // SQLite3
        {"libpq-fe.h",      {.pkg_configs = {"libpq"}}},         // PostgreSQL client (libpq)
        {"mysql.h",         {.direct_libs = {"-lmysqlclient"}}}, // MySQL/MariaDB client

        // --- Networking & Web ---
        {"curl/curl.h",     {.pkg_configs = {"libcurl"}}},       // libcurl
        {"openssl/ssl.h",   {.pkg_configs = {"libssl", "libcrypto"}}}, // OpenSSL
        {"openssl/crypto.h",{.pkg_configs = {"libcrypto"}}},     // OpenSSL (crypto part only)
        {"grpcpp/grpcpp.h", {.pkg_configs = {"grpc++"}}},        // gRPC
        {"httplib.h",       {.pkg_configs = {"libssl", "libcrypto"}}}, // cpp-httplib (header-only, but needs SSL for https)
        {"zmq.h",           {.pkg_configs = {"libzmq"}}},        // ZeroMQ

        // --- Compression & Cryptography ---
        {"zlib.h",          {.direct_libs = {"-lz"}}},           // zlib
        {"zstd.h",          {.pkg_configs = {"libzstd"}}},       // Zstandard
        {"lzma.h",          {.pkg_configs = {"liblzma"}}},       // lzma (XZ Utils)
        {"bzlib.h",         {.direct_libs = {"-lbz2"}}},         // bzip2
        {"blake3.h",        {.direct_libs = {"-lblake3"}}},      // BLAKE3
        {"sodium.h",        {.pkg_configs = {"libsodium"}}},     // libsodium

        // --- General Utilities & Frameworks (Boost, Logging, etc.) ---
        {"fmt/",      {.pkg_configs = {"fmt"}}},           // {fmt} library
        {"spdlog/spdlog.h", {.pkg_configs = {"spdlog"}}},        // spdlog (often pulls in fmt)
        {"glog/logging.h",  {.direct_libs = {"-lglog"}}},        // Google Log
        {"boost/system/error_code.hpp", {.direct_libs = {"-lboost_system"}}},
        {"boost/filesystem.hpp", {.direct_libs = {"-lboost_system", "-lboost_filesystem"}}},
        {"boost/thread.hpp", {.direct_libs = {"-lboost_thread", "-lboost_system"}}},
        {"boost/asio.hpp",   {.direct_libs = {"-lboost_system"}}},
        {"tbb/tbb.h",       {.pkg_configs = {"tbb"}}},           // Intel TBB

        // --- Numerics & Science ---
        {"Eigen/Dense",     {/* Header-only */}},
        {"gsl/gsl_sf_bessel.h", {.pkg_configs = {"gsl"}}},       // GNU Scientific Library
        {"fftw3.h",         {.direct_libs = {"-lfftw3"}}},       // FFTW

        // --- Testing Frameworks ---
        {"gtest/gtest.h",   {.direct_libs = {"-lgtest", "-lgtest_main", "-lpthread"}}}, // Google Test
        {"catch2/catch.hpp",{/* Header-only */}},                // Catch2
    };
    std::unordered_map<std::string, std::string> pkg_cache; // Cache for pkg-config results

public:
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

                        auto pkg_result = getPkgConfigFlags(pkg_name);
                        if (!pkg_result.empty()) {
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
private:
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
                    std::smatch matches;
                    if (std::regex_search(line, matches, include_regex)) {
                        if (bool is_local_include = matches[2].matched) {
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

    // A simpler function to get all unique includes for library detection.
    [[nodiscard]] std::vector<std::string> getAllUniqueIncludes(const std::vector<fs::path>& sourceFiles) const {
        std::unordered_set<std::string> unique_includes;
        for (const auto& file : sourceFiles) {
            std::ifstream stream(file);
            std::string line;
            while (std::getline(stream, line)) {
                std::smatch matches;
                if (std::regex_search(line, matches, include_regex)) {
                    unique_includes.insert(matches[1].matched ? matches[1].str() : matches[2].str());
                }
            }
        }
        return {unique_includes.begin(), unique_includes.end()};
    }
};


class AutoCC {
public:
    int return_code = 0;
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

    bool readConfigCache() {
        if (!fs::exists(config_file)) return false;
        std::ifstream file(config_file);
        std::string line;
        while (std::getline(file, line)) {
            auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            std::string_view key = std::string_view(line).substr(0, pos);
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
    explicit AutoCC(Config cfg) : config(std::move(cfg)), is_fresh_build(true) {
        const auto ignored_dirs = getIgnoredDirs();
        source_files = find_source_files(root, ignored_dirs);
        if (source_files.empty()) {
            out::error("No source files (.c, .cpp, .s, etc.) found in the current directory.");
            return_code = 1;
            return;
        }

        if (!config.manual_mode) {
            out::info("Starting automatic dependency scan...");
            scanLocalHeaders();
            detectLibraries();
        }

        writeConfigCache();
        return_code = compileAndLink();
    }
//testing
    explicit AutoCC() : is_fresh_build(false) {
        if (!readConfigCache()) {
            out::error("Cache not found. Please run 'autocc init' or 'autocc rescan' to configure the project.");
            return_code = 1;
            return;
        }
        const auto ignored_dirs = getIgnoredDirs();
        source_files = find_source_files(root, ignored_dirs);
        if (source_files.empty()) {
            out::error("No source files found.");
            return_code = 1;
            return;
        }
        return_code = compileAndLink();
    }
    Config config;
private:

    const fs::path root = ".";
    const fs::path cache_dir = root / CACHE_DIR_NAME;
    const fs::path config_file = cache_dir / CONFIG_FILE_NAME;
    const fs::path dep_cache_file = cache_dir / DEP_CACHE_FILE_NAME;
    bool is_fresh_build;

    std::vector<fs::path> source_files;
    LibraryDetector lib_detector;
    IncludeParser include_parser;
    DependencyMap dependency_map;

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
    // --- Build Logic ---

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
                std::smatch matches;
                if(std::regex_search(line, matches, pch_candidate_regex)) {
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
        auto result = execute(pch_compile_cmd);
        if (result.exit_code != 0) {
            out::warn("PCH generation failed. Continuing without it.");
            out::warn("Compiler error: {}", result.stderr_output);
            return {};
        }

        // Flag to use the PCH during compilation
        pch_flags = fmt::format("-include {}", pch_source.string());
        return pch_out;
    }

    int compileAndLink() {
        const fs::path build_path = config.build_dir;
        fs::create_directories(build_path);

        // --- Step 1: Update & Load Dependency Information ---
        if(is_fresh_build) {
            dependency_map = include_parser.parseSourceDependencies(source_files, config.include_dirs);
            writeDepCache();
        } else {
            readDepCache();
        }

        // --- Step 2: Generate PCH if enabled ---
        std::string pch_flags;
        fs::path pch_file;
        auto pch_time = fs::file_time_type::min();
        if (config.use_pch) {
            pch_file = generatePCH(build_path, pch_flags);
            if(fs::exists(pch_file)) pch_time = fs::last_write_time(pch_file);
        }

        // --- Step 3: Identify files needing recompilation (The Smart Way) ---
        std::vector<fs::path> files_to_compile;
        std::vector<fs::path> object_files;
        out::info("Checking dependencies...");

        for (const auto& src_file : source_files) {
            fs::path obj_file = build_path / src_file.filename().replace_extension(".o");
            object_files.push_back(obj_file);

            if (!fs::exists(obj_file)) {
                files_to_compile.push_back(src_file);
                continue;
            }

            auto obj_time = fs::last_write_time(obj_file);
            if (fs::last_write_time(src_file) > obj_time) {
                files_to_compile.push_back(src_file);
                continue;
            }
            // Check against PCH timestamp
            if (!pch_file.empty() && pch_time > obj_time) {
                 files_to_compile.push_back(src_file);
                 continue;
            }

            // Check against this file's specific header dependencies
            if (dependency_map.contains(src_file)) {
                for (const auto& header : dependency_map.at(src_file)) {
                    if (fs::exists(header) && fs::last_write_time(header) > obj_time) {
                        files_to_compile.push_back(src_file);
                        break; // Found one, no need to check others for this source file
                    }
                }
            }
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
                        size_t index = file_index.fetch_add(1);
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

        out::success("Target '{}' built successfully in '{}'.", config.name, config.build_dir);
        return 0;
    }
};

// --- User Interaction and Main ---

void show_help() {
    using fmt::styled;
    out::info("AutoCC {} - A smarter C++ build system", VERSION);
    fmt::print(
        "\n"
        "Usage: autocc [command]\n\n"
        "Commands:\n"
        "  (no command)  Builds the project incrementally using cached settings.\n"
        "  {}          Prompts for configuration and creates a new build environment.\n"
        "  {}        Clears the cache and performs a full dependency scan before building.\n"
        "  {}        Interactive setup, but YOU must provide all compiler/linker flags manually.\n"
        "  {} <key> <val> Set a single config value (e.g., 'autocc set cxxflags -O3').\n"
        "  {}           Removes the build directory and cache.\n"
        "  {}         Show current version and build date.\n"
        "  {}/{}      Compile with default parameters (no config).\n"
        "  {}          Shows this help message.\n",
        styled("init", out::color_prompt),
        styled("rescan", out::color_prompt),
        styled("manual", out::color_prompt),
        styled("set", out::color_prompt),
        styled("clean", out::color_prompt),
        styled("version", out::color_prompt),
        styled("--autoconfig", out::color_prompt),
        styled("--autocompile", out::color_prompt),
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
    auto get_input = [](std::string_view prompt, std::string_view default_val) -> std::string {
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
    if (argc > 1) {
        std::string command = argv[1];

        if (command == "version" || command == "--version" || command == "-v") { show_version(); return 0; }
        if (command == "help" || command == "--help") { show_help(); return 0; }

        if (command == "clean") {
            // Try to read build_dir from cache to clean the right place
            Config temp_cfg;
            if (const AutoCC a; a.return_code == 0) temp_cfg = a.config; // TODO: Needs a better way to get config

            const fs::path build_dir_to_clean = temp_cfg.build_dir; // Use cached or default
            const fs::path cache_dir_to_clean = CACHE_DIR_NAME;
            out::info("Cleaning build dir '{}' and cache '{}'...", build_dir_to_clean.string(), cache_dir_to_clean.string());
            fs::remove_all(build_dir_to_clean);
            fs::remove_all(cache_dir_to_clean);
            out::success("Clean complete.");
            return 0;
        }

        if (command == "init" || command == "rescan" || command == "manual") {
            if (fs::exists(CACHE_DIR_NAME)) {
                out::info("Invalidating cache for '{}' command...", command);
                fs::remove_all(CACHE_DIR_NAME);
            }
            Config config;
            if (command != "rescan") user_init(config);
            if (command == "manual") config.manual_mode = true;

            AutoCC autocc(config);
            return autocc.return_code;
        }

        if (command == "--autoconfig" || command == "--autocompile") {
            Config config;
            AutoCC autocc(config);
            return autocc.return_code;
        }

        if (command == "set") {
             if (argc != 4) {
                 out::error("Usage: autocc set <key> <value>");
                 return 1;
             }
             if (!fs::exists(CACHE_DIR_NAME) || !fs::exists(fs::path(CACHE_DIR_NAME) / CONFIG_FILE_NAME)) {
                 out::error("'set' command requires a project to be initialized first. Run 'autocc init'.");
                 return 1;
             }
             Config config;
             AutoCC a; // Read existing config
             if (a.return_code != 0) return 1; // Failed to read

             std::string key = argv[2];
             std::string value = argv[3];
             if( key == "cxx") a.config.cxx = value;
             else if (key == "cc") a.config.cc = value;
             else if (key == "cflags") a.config.cflags = value;
             else if (key == "cxxflags") a.config.cxxflags = value;
             else if (key == "as") a.config.as = value;
             else if (key == "name") a.config.name = value;
             else if (key == "ldflags") a.config.ldflags = value;

             else {
                out::error("Unknown config key: '{}'", key);
                return 1;
             }
             a.writeConfigCache(); // Save the modified config
             out::success("Set '{}' to '{}'. Run 'autocc' to rebuild.", key, value);
             return 0;
        }

        out::error("Unknown command: '{}'. Use 'autocc help' for usage.", command);
        return 1;
    }

    // Default behavior: build from cache or prompt init
    if (fs::exists(fs::path(CACHE_DIR_NAME) / CONFIG_FILE_NAME)) {
        AutoCC autocc;
        return autocc.return_code;
    }

    out::info("No configuration found. Starting initial setup...");
    Config config;
    user_init(config);
    AutoCC autocc(config);
    return autocc.return_code;
}