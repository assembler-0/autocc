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
#include <cstdlib>
#include <thread> // For parallel compilation
#include <atomic> // For thread-safe operations
#include <mutex>  // For thread-safe output
#include <fmt/format.h>
#include <fmt/ranges.h>

#define DATE __DATE__
#define TIME __TIME__
#define VERSION "v0.1"

namespace fs = std::filesystem;

// A global mutex for ensuring threads do not interleave cout/cerr writes
std::mutex g_output_mutex;

template <>
struct fmt::formatter<std::filesystem::path> : formatter<std::string_view> {
    auto format(const std::filesystem::path& p, format_context& ctx) const {
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

public:
    void detect(const std::vector<std::string>& includes, Config& config) {
        std::unordered_set<std::string> found_direct_libs(config.external_libs.begin(), config.external_libs.end());
        std::unordered_set<std::string> processed_pkg_configs;
        std::string additional_ldflags;

        for (const auto& include : includes) {
            for (const auto& [header_signature, rule] : detectionMap) {
                if (include.find(header_signature) != std::string::npos) {
                    // Add direct library cxxflags
                    for (const auto& lib : rule.direct_libs) {
                        found_direct_libs.insert(lib);
                    }

                    // Process pkg-config dependencies
                    for (const auto& pkg_name : rule.pkg_configs) {
                        if (!processed_pkg_configs.contains(pkg_name)) {
                            auto pkg_result = getPkgConfigFlags(pkg_name);
                            if (!pkg_result.empty()) {
                                additional_ldflags += " " + pkg_result;
                                {
                                    std::lock_guard lock(g_output_mutex);
                                    fmt::print("[INFO] Found dependency '{}', adding cxxflags via pkg-config.\n", pkg_name);
                                }
                            } else {
                                 std::lock_guard lock(g_output_mutex);
                                 fmt::print(stderr, "[WARN] Found include for '{}' but 'pkg-config {}' failed. Is it installed?\n", pkg_name, pkg_name);
                            }
                            processed_pkg_configs.insert(pkg_name);
                        }
                    }
                }
            }
        }

        config.external_libs.assign(found_direct_libs.begin(), found_direct_libs.end());
        // Prepend a space only if there are cxxflags to add
        if (!additional_ldflags.empty()) {
            config.ldflags += " " + additional_ldflags;
        }
    }

private:
    static std::string getPkgConfigFlags(const std::string& package) {
        // Query for both library and compiler cxxflags from pkg-config
        const std::string cmd = fmt::format("pkg-config --libs --cflags {} 2>/dev/null", package);
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";

        std::string result;
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);

        if (!result.empty() && result.back() == '\n') {
            result.pop_back();
        }
        return result;
    }
};

class IncludeParser {
public:
    static std::vector<std::string> getAllIncludes(const std::vector<fs::path>& sourceFiles, const std::vector<std::string>& include_dirs) {
        std::unordered_set<std::string> unique_includes;
        std::vector<fs::path> files_to_scan;
        std::unordered_set<fs::path> scanned_files; // To prevent infinite loops

        // Start by scanning the main source files (.cpp, .c)
        files_to_scan.insert(files_to_scan.end(), sourceFiles.begin(), sourceFiles.end());

        std::regex include_regex(R"_(\s*#\s*include\s*(?:<([^>]+)>|"([^"]+)"))_");

        // --- The Recursive Scanning Loop ---
        while (!files_to_scan.empty()) {
            fs::path current_file = files_to_scan.back();
            files_to_scan.pop_back();

            // Skip files we've already processed to avoid cycles (e.g., a.h includes b.h, b.h includes a.h)
            if (scanned_files.contains(current_file)) {
                continue;
            }
            scanned_files.insert(current_file);

            std::ifstream file_stream(current_file);
            if (!file_stream.is_open()) {
                // This can happen if a local header can't be found. We'll just skip it.
                continue;
            }

            std::string line;
            while (std::getline(file_stream, line)) {
                std::smatch matches;
                if (std::regex_search(line, matches, include_regex)) {
                    bool is_system_include = matches[1].matched;
                    const auto& match_str = is_system_include ? matches[1].str() : matches[2].str();

                    unique_includes.insert(match_str);

                    // If it's a local include ("..."), we need to find that file and scan it too.
                    if (!is_system_include) {
                        fs::path included_path = findHeader(match_str, current_file.parent_path(), include_dirs);
                        if (!included_path.empty()) {
                            files_to_scan.push_back(included_path);
                        }
                    }
                }
            }
        }

        return {unique_includes.begin(), unique_includes.end()};
    }

private:
    // Helper function to find the full path of a local header file.
    static fs::path findHeader(const std::string& header_name, const fs::path& relative_to, const std::vector<std::string>& include_dirs) {
        // 1. Check relative to the current file's directory
        fs::path potential_path = relative_to / header_name;
        if (fs::exists(potential_path)) {
            return potential_path;
        }

        // 2. Check all the -I include directories
        for (const auto& dir_flag : include_dirs) {
            if (dir_flag.rfind("-I", 0) == 0) {
                fs::path base_dir = dir_flag.substr(2);
                potential_path = base_dir / header_name;
                if (fs::exists(potential_path)) {
                    return potential_path;
                }
            }
        }

        return {}; // Return empty path if not found
    }
};


// --- The Main Build System Logic ---

class AutoCC {
public:
    int return_code = 0;

    // Constructor for a fresh scan or re-scan
    explicit AutoCC(Config cfg) : config(std::move(cfg)) {
        source_files = findSourceFiles(root);
        if (source_files.empty()) {
            fmt::print(stderr, "[!] FATAL:  No source files (.c, .cpp, .s, etc.) found in the current directory.\n");
            return_code = 1;
            return;
        }

        if (!config.manual_mode) {
            fmt::print("[?] Starting automatic dependency scan...\n");
            scanLocalHeaders();
            detectLibraries();
        }

        writeCache();
        return_code = compileAndLink();
    }

    // Constructor for building from cache
    explicit AutoCC() {
        if (!readCache()) {
            fmt::print(stderr, "[!] FATAL:  Cache not found. Please run 'autocc init' to configure the project.\n");
            return_code = 1;
            return;
        }
        source_files = findSourceFiles(root);
        if (source_files.empty()) {
            fmt::print(stderr, "[!] FATAL:  No source files found.\n");
            return_code = 1;
            return;
        }
        return_code = compileAndLink();
    }

private:
    Config config;
    const fs::path root = ".";
    const fs::path cache_file_path = root / ".autocc_cache" / "config.cache";
    std::vector<fs::path> source_files;
    LibraryDetector lib_detector;

    void scanLocalHeaders() {
        std::set<std::string> header_dirs;
        for (const auto& entry : fs::recursive_directory_iterator(root)) {
            if (entry.is_regular_file()) {
                const std::string ext = entry.path().extension().string();
                if (ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".hh") {
                    header_dirs.insert(entry.path().parent_path().string());
                }
            }
        }
        for (const auto& dir : header_dirs) {
            config.include_dirs.push_back(fmt::format("-I{}", dir));
        }
    }

    void detectLibraries() {
        // The call to getAllIncludes now needs the include_dirs from the config
        const auto all_includes = IncludeParser::getAllIncludes(source_files, config.include_dirs);
        lib_detector.detect(all_includes, config);
    }

    void writeCache() const {
        fs::create_directories(cache_file_path.parent_path());
        std::ofstream cache_file(cache_file_path);
        cache_file << "cxx:" << config.cxx << std::endl;
        cache_file << "cc:" << config.cc << std::endl;
        cache_file << "as:" << config.as << std::endl;
        cache_file << "name:" << config.name << std::endl;
        cache_file << "cxxflags:" << config.cxxflags << std::endl;
        cache_file << "cflags:" << config.cflags << std::endl;
        cache_file << "ldflags:" << config.ldflags << std::endl;
        cache_file << "build_dir:" << config.build_dir << std::endl;
        for (const auto& dir : config.include_dirs) cache_file << "include:" << dir << std::endl;
        for (const auto& lib : config.external_libs) cache_file << "lib:" << lib << std::endl;
    }

    bool readCache() {
        if (!fs::exists(cache_file_path)) return false;
        std::ifstream cache_file(cache_file_path);
        std::string line;
        while (std::getline(cache_file, line)) {
            auto delimiter_pos = line.find(':');
            if (delimiter_pos == std::string::npos) continue;
            std::string_view key = std::string_view(line).substr(0, delimiter_pos);
            std::string_view value = std::string_view(line).substr(delimiter_pos + 1);

            if (key == "cxx") config.cxx = value;
            else if (key == "cc") config.cc = value;
            else if (key == "as") config.as = value;
            else if (key == "name") config.name = value;
            else if (key == "cxxflags") config.cxxflags = value;
            else if (key == "cflags") config.cflags = value;
            else if (key == "ldflags") config.ldflags = value;
            else if (key == "build_dir") config.build_dir = value;
            else if (key == "include") config.include_dirs.emplace_back(value);
            else if (key == "lib") config.external_libs.emplace_back(value);
        }
        return true;
    }

    std::string getCompiler(const fs::path& file) const {
        const std::string ext = file.extension().string();
        if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".c++") return config.cxx;
        if (ext == ".c") return config.cc;
        if (ext == ".s" || ext == ".S" || ext == ".asm") return config.as;
        return config.cxx; // Default to C++ compiler
    }

    static std::vector<fs::path> findSourceFiles(const fs::path& dir) {
        std::vector<fs::path> files;
        // Avoid recursing into build or cache directories
        std::unordered_set<std::string> ignored_dirs = {".git", ".autocc_build", ".autocc_cache"};

        for (auto& p : fs::recursive_directory_iterator(dir)) {
            // Skip ignored directories
            bool ignore = false;
            for(const auto& part : p.path()){
                if(ignored_dirs.contains(part.string())) {
                    ignore = true;
                    break;
                }
            }
            if(ignore) continue;

            if (p.is_regular_file()) {
                const std::string ext = p.path().extension().string();
                 if (ext == ".cpp" || ext == ".c" || ext == ".cc" || ext == ".s" ||
                     ext == ".S" || ext == ".asm" || ext == ".c++" || ext == ".cxx") {
                    files.push_back(p.path());
                }
            }
        }
        return files;
    }

    int compileAndLink() {
        const fs::path build_path = config.build_dir;
        fs::create_directories(build_path);

        // --- Step 1: Identify which files need to be recompiled ---
        std::vector<fs::path> files_to_compile;
        std::vector<fs::path> object_files;

        // Get the latest modification time of any header file for dependency checking.
        // A more advanced system would track per-file header dependencies.
        auto latest_header_time = fs::file_time_type::min();
        for (const auto& include_dir_str : config.include_dirs) {
             if (include_dir_str.rfind("-I", 0) == 0) {
                fs::path header_dir = include_dir_str.substr(2);
                if (!fs::exists(header_dir)) continue;
                for (const auto& entry : fs::recursive_directory_iterator(header_dir)) {
                    if (entry.is_regular_file()) {
                         const std::string ext = entry.path().extension().string();
                         if (ext == ".h" || ext == ".hpp") {
                             if (entry.last_write_time() > latest_header_time) {
                                 latest_header_time = entry.last_write_time();
                             }
                         }
                    }
                }
             }
        }

        for (const auto& src_file : source_files) {
            fs::path obj_file = build_path / (src_file.stem().string() + ".o");
            object_files.push_back(obj_file);

            bool needs_compile = false;
            if (!fs::exists(obj_file)) {
                needs_compile = true;
            } else {
                auto src_time = fs::last_write_time(src_file);
                auto obj_time = fs::last_write_time(obj_file);
                if (src_time > obj_time || latest_header_time > obj_time) {
                    needs_compile = true;
                }
            }

            if (needs_compile) {
                files_to_compile.push_back(src_file);
            }
        }

        if (files_to_compile.empty()) {
            fmt::print("[?] All files are up to date.\n");
            return 0;
        } else {
            // --- Step 2: Compile needed files in parallel ---
            fmt::print("[?] Compiling {}/{} source files...\n", files_to_compile.size(), source_files.size());
            std::atomic<bool> compilation_failed = false;
            std::atomic<size_t> file_index = 0;
            const unsigned int num_threads = std::thread::hardware_concurrency();
            std::vector<std::thread> workers;

            workers.reserve(num_threads);
            for (unsigned int i = 0; i < num_threads; ++i) {
                workers.emplace_back([&]() {
                    while (true) {
                        if (compilation_failed) return;
                        const size_t index = file_index.fetch_add(1);
                        if (index >= files_to_compile.size()) return;

                        const auto& src_file = files_to_compile[index];
                        std::string compiler = getCompiler(src_file);
                        fs::path obj_file = build_path / (src_file.stem().string() + ".o");

                        std::string cmd;
                        if (compiler == config.as) {
                            cmd = fmt::format("{} {} -felf64 -o {}", compiler, src_file.string(), obj_file.string());
                        } else if (compiler == config.cxx) {
                            cmd = fmt::format("{} -c {} -o {} {} {}", compiler, src_file.string(), obj_file.string(), config.cxxflags, fmt::join(config.include_dirs, " "));
                        } else {
                            cmd = fmt::format("{} -c {} -o {} {} {}", compiler, src_file.string(), obj_file.string(), config.cflags, fmt::join(config.include_dirs, " "));
                        }

                        {
                            std::lock_guard lock(g_output_mutex);
                            fmt::print("[C] {}\n", cmd);
                        }

                        int result = system(cmd.c_str());
                        if (result != 0) {
                            std::lock_guard lock(g_output_mutex);
                            fmt::print(stderr, "[!] FATAL:  Failed to compile: {}\n", src_file.string());
                            compilation_failed = true;
                        }
                    }
                });
            }

            for (auto& worker : workers) {
                worker.join();
            }

            if (compilation_failed) {
                fmt::print(stderr, "[!] FATAL:  Compilation failed. Aborting.\n");
                return 1;
            }
        }

        // --- Step 3: Link all object files ---
        const std::string link_cmd = fmt::format("{} -o {} {} {} {} {}",
            config.cxx,
            (build_path / config.name).string(),
            fmt::join(object_files, " "),
            config.cxxflags,
            config.ldflags,
            fmt::join(config.external_libs, " ")
        );

        fmt::print("[?] Linking target...\n");
        fmt::print("[C] {}\n", link_cmd);
        if (system(link_cmd.c_str()) != 0) {
            fmt::print(stderr, "[!] FATAL:  Failed to link target: {}\n", config.name);
            return 1;
        }

        fmt::print(stdout, "\n[+] Target '{}' built successfully in '{}'.\n", config.name, build_path.string());
        return 0;
    }
};

// --- User Interaction and Main ---

void show_help() {
    fmt::print(
        "AutoCC - A zero-config C++ build system\n\n"
        "Usage: autocc [command]\n\n"
        "Commands:\n"
        "  (no command)  Builds the project incrementally. If not configured, prompts for setup.\n"
        "  init          Prompts for configuration and creates a new build environment. Overwrites existing config.\n"
        "  rescan        Clears the cache and performs a full dependency scan before building.\n"
        "  manual        Prompts for configuration but does NOT scan for headers or libraries. You must provide all flags manually.\n"
        "  clean         Removes the build directory and cache.\n"
        "  version       Show current version, built date and time.\n"
        "  help          Shows this help message.\n"
    );
}

void show_version() {
    fmt::print("AutoCC {} compiled on {} {}", VERSION, TIME, DATE);
}

void user_init(Config& config) {
    auto get_input = [](std::string_view prompt, std::string_view default_val) -> std::string {
        fmt::print("[?] {} ({}): ", prompt, default_val);
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
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string command = argv[1];
        fs::path build_dir = ".autocc_build"; // Cache, may override default
        fs::path cache_dir = ".autocc_cache";

        // Read build_dir from cache if it exists, to ensure `clean` works correctly
        if (fs::exists(cache_dir / "config.cache")) {
            std::ifstream cache_file(cache_dir / "config.cache");
            std::string line;
            while(std::getline(cache_file, line)) {
                if (line.rfind("build_dir:", 0) == 0) {
                    build_dir = line.substr(10);
                    break;
                }
            }
        }
        if (command == "version" || command == "--version" || command == "-v") {
            show_version();
            return 0;
        }
        if (command == "help" || command == "--help") {
            show_help();
            return 0;
        }
        if (command == "clean") {
            fmt::print("[?] Cleaning build directory '{}' and cache '{}'...\n", build_dir.string(), cache_dir.string());
            fs::remove_all(build_dir);
            fs::remove_all(cache_dir);
            return 0;
        }
        if (command == "init" || command == "rescan" || command == "manual") {
            if (fs::exists(cache_dir)) {
                fmt::print("[?] Invalidating cache for '{}' command...\n", command);
                fs::remove_all(cache_dir);
            }
            Config config;
            if (command != "rescan") { // 'init' and 'manual' require user input
               user_init(config);
            }
            if (command == "manual") {
                config.manual_mode = true;
            }
            AutoCC autocc(config);
            return autocc.return_code;
        } else {
            fmt::print(stderr, "[!] FATAL: Unknown command: '{}'. Use 'autocc help' for usage.\n", command);
            return 1;
        }
    }

    // Default behavior: build from cache or prompt init
    if (fs::exists(".autocc_cache/config.cache")) {
        AutoCC autocc; // Reads from cache and builds incrementally
        return autocc.return_code;
    }

    fmt::print("[?] No configuration found. Starting initial setup...\n");
    Config config;
    user_init(config);
    AutoCC autocc(config); // Full scan and build
    return autocc.return_code;
}