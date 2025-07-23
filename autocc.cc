#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <optional>
#include <regex>
#include <fmt/base.h>
#include <fmt/ostream.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <cstdlib>

namespace fs = std::filesystem;

class Default {
public:
    static constexpr auto DEF_CC = "clang";
    static constexpr auto DEF_CXX = "clang++";
    static constexpr auto DEF_AS = "nasm";
    static constexpr auto DEF_FLAGS = "-Wall -march=native -fopenmp -std=c++23";
    static constexpr auto DEF_LDFLAGS = "";
    static constexpr auto DEF_NAME = "target_default";
    static constexpr auto DEF_BUILD = "autocc";
    static constexpr auto DEF_MANUAL = false;
};

class LibraryDetector {
private:
    std::unordered_map<std::string, std::vector<std::string>> headerToLibs = {
        // Standard C++ libraries that need explicit linking
        {"thread", {"-lpthread"}},
        {"filesystem", {"-lstdc++fs"}}, // For older GCC versions

        // Common system libraries
        {"math.h", {"-lm"}},
        {"cmath", {"-lm"}},
        {"pthread.h", {"-lpthread"}},
        {"X11/Xlib.h", {"-lX11"}},
        {"GL/gl.h", {"-lGL"}},
        {"GL/glu.h", {"-lGLU"}},
        {"GLFW/glfw3.h", {"-lglfw", "-lGL", "-lX11", "-lpthread", "-ldl"}},
        {"curl/curl.h", {"-lcurl"}},
        {"sqlite3.h", {"-lsqlite3"}},
        {"GL/", {"-lOpenGL"}},
        {"allegro5/", {"-lallegro"}},
        {"zlib.h", {"-lz"}},
        {"lzma.h", {"-llzma"}},
        {"openssl/ssl.h", {"-lssl", "-lcrypto"}},
        {"openssl/sha.h", {"-lssl", "-lcrypto"}},
        {"openssl/crypto.h", {"-lcrypto"}},
        {"blake3.h", {"-lblake3"}}, // Added blake3
        {"zstd.h", {"-lzstd"}},     // Added zstd
        {"pcre.h", {"-lpcre"}},
        {"yaml.h", {"-lyaml"}},
        {"json/json.h", {"-ljsoncpp"}},
        {"boost/", {"-lboost_system", "-lboost_filesystem"}},
        {"fmt/", {"-lfmt"}},
        {"spdlog/", {"-lfmt"}},
    };

    std::vector<std::string> pkgConfigLibs = {
        "gtk+-3.0", "qt5-core", "opencv", "cairo", "pango", "glib-2.0"
    };

public:
    struct DetectionResult {
        std::vector<std::string> libraries;
        std::vector<std::string> includePaths;
        std::vector<std::string> pkgConfigFlags;
        std::vector<std::string> compilerFlags; // New member for compiler-specific flags
    };

    DetectionResult detectFromIncludes(const std::vector<std::string>& includes) {
        DetectionResult result;
        std::unordered_set<std::string> addedLibs;

        for (const auto& include : includes) {
            // Direct header to library mapping
            for (const auto& [header, libs] : headerToLibs) {
                if (include.find(header) != std::string::npos) {
                    for (const auto& lib : libs) {
                        if (!addedLibs.contains(lib)) {
                            result.libraries.push_back(lib);
                            addedLibs.insert(lib);
                        }
                    }
                }
            }

            // Check for pkg-config managed libraries
            for (const auto& pkgLib : pkgConfigLibs) {
                if (include.find(pkgLib) != std::string::npos ||
                    include.find("gtk") != std::string::npos && pkgLib == "gtk+-3.0") {
                    auto pkgResult = getPkgConfigFlags(pkgLib);
                    if (!pkgResult.empty()) {
                        result.pkgConfigFlags.push_back(pkgResult);
                    }
                }
            }
        }

        return result;
    }

private:
    static std::string getPkgConfigFlags(const std::string& package) {
        const std::string cmd = fmt::format("pkg-config --libs --cflags {} 2>/dev/null", package);

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";

        std::string result;
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);

        // Remove trailing newline
        if (!result.empty() && result.back() == '\n') {
            result.pop_back();
        }

        return result;
    }
};

class IncludeParser {
public:
    struct ParseResult {
        std::vector<std::string> systemIncludes;
        std::vector<std::string> localIncludes;
    };

    static ParseResult parseFile(const fs::path& filePath) {
        ParseResult result;
        std::ifstream file(filePath);
        std::string line;

        // Regex patterns for different include formats
        std::regex systemIncludeRegex(R"_((^\s*#\s*include\s*<([^>]+)>))_");
        std::regex localIncludeRegex(R"_((^\s*#\s*include\s*"([^"]+)"))_");

        while (std::getline(file, line)) {
            std::smatch matches;

            if (std::regex_search(line, matches, systemIncludeRegex)) {
                result.systemIncludes.push_back(matches[1].str());
            } else if (std::regex_search(line, matches, localIncludeRegex)) {
                result.localIncludes.push_back(matches[1].str());
            }
        }

        return result;
    }

    static std::vector<std::string> getAllIncludes(const std::vector<fs::path>& sourceFiles) {
        std::unordered_set<std::string> uniqueIncludes;

        for (const auto& file : sourceFiles) {
            if (file.extension() == ".c" || file.extension() == ".cpp" ||
                file.extension() == ".cc" || file.extension() == ".cxx" ||
                file.extension() == ".c++") {

                auto parseResult = parseFile(file);

                for (const auto& inc : parseResult.systemIncludes) {
                    uniqueIncludes.insert(inc);
                }
                for (const auto& inc : parseResult.localIncludes) {
                    uniqueIncludes.insert(inc);
                }
            }
        }

        return {uniqueIncludes.begin(), uniqueIncludes.end()};
    }
};

class SystemPathDetector {
public:
    static std::vector<std::string> getSystemIncludePaths() {
        std::vector<std::string> paths;

        // Try to get the system include paths from compiler
        auto gccPaths = getCompilerIncludePaths("gcc");
        auto clangPaths = getCompilerIncludePaths("clang");

        paths.insert(paths.end(), gccPaths.begin(), gccPaths.end());
        paths.insert(paths.end(), clangPaths.begin(), clangPaths.end());

        // Add common system paths
        std::vector<std::string> commonPaths = {
            "/usr/include",
            "/usr/local/include",
            "/opt/local/include",
            "/usr/include/c++/11",
            "/usr/include/c++/12",
            "/usr/include/c++/13",
            "/usr/include/x86_64-linux-gnu",
        };

        for (const auto& path : commonPaths) {
            if (fs::exists(path)) {
                paths.push_back("-I" + path);
            }
        }

        return paths;
    }

    static std::vector<std::string> getSystemLibraryPaths() {
        std::vector<std::string> paths;

        std::vector<std::string> commonPaths = {
            "/usr/lib",
            "/usr/local/lib",
            "/opt/local/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
        };

        for (const auto& path : commonPaths) {
            if (fs::exists(path)) {
                paths.push_back("-L" + path);
            }
        }

        return paths;
    }

private:
    static std::vector<std::string> getCompilerIncludePaths(const std::string& compiler) {
        std::string cmd = fmt::format("{} -E -v -x c++ /dev/null 2>&1 | "
                                     "sed -n '/#include <...> search starts here:/,/End of search list./p' | "
                                     "grep '^/' || true", compiler);

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return {};

        std::vector<std::string> paths;
        char buffer[512];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string path = buffer;
            path.erase(path.find_last_not_of(" \n\r\t") + 1); // trim
            if (!path.empty() && path[0] == '/') {
                paths.push_back("-I" + path);
            }
        }
        pclose(pipe);

        return paths;
    }
};

// Your existing Parser class remains the same
class Parser {
public:
    std::string cc;
    std::string cxx;
    std::string name;
    std::string flags;
    std::string ldflags;
    std::string as;
    std::string build;

    void UserInput() {
        std::string input;
        fmt::print("[?] C compiler? (clang) ");
        std::getline(std::cin, input);
        cc = input.empty() ? "clang" : input;

        fmt::print("[?] C++ compiler? (clang++) ");
        std::getline(std::cin, input);
        cxx = input.empty() ? "clang++" : input;

        fmt::print("[?] Assembler? (nasm) ");
        std::getline(std::cin, input);
        as = input.empty() ? "nasm" : input;

        fmt::print("[?] Executable name? (default) ");
        std::getline(std::cin, input);
        name = input.empty() ? "default" : input;

        fmt::print("[?] Compiler flags? (-Wall) ");
        std::getline(std::cin, input);
        flags = input.empty() ? "-Wall" : input;

        fmt::print("[?] Linker flags? () ");
        std::getline(std::cin, input);
        ldflags = input.empty() ? "" : input;

        fmt::print("[?] Build directory? (autocc) ");
        std::getline(std::cin, input);
        build = input.empty() ? "autocc" : input;
    }
};

class AutoCC {
public:
    int Success = 0;

    explicit AutoCC(const std::optional<std::string>& cxx,
                    const std::optional<std::string>& cc,
                    const std::optional<std::string>& name,
                    const std::optional<std::string>& flags,
                    const std::optional<std::string>& ldflags,
                    const std::optional<std::string>& as,
                    const std::optional<std::string>& build,
                    bool manual_mode = false) // Added manual_mode with default false
    : CXX(cxx.value_or("clang++")), CC(cc.value_or("clang")), AS(as.value_or("nasm")),
      NAME(name.value_or("default")), FLAGS(flags.value_or("-Wall")),
      LDFLAGS(ldflags.value_or("")), BUILD(build.value_or("autocc")) {

        const auto sourceFiles = FindSourceFiles(root);
        if (!manual_mode) { // Only perform auto-detection and cache if not in manual mode
            HeaderScan();
            DetectSystemDependencies(sourceFiles);
            WriteCache();
        }
        Success = Compile(sourceFiles);
    }

    explicit AutoCC() {
        ReadCache();
        Success = Compile(FindSourceFiles(root));
    }

private:
    std::string CXX;
    std::string CC;
    std::string AS;
    std::string NAME;
    std::string FLAGS;
    std::string LDFLAGS;
    std::string BUILD;
    const fs::path root = ".";

    std::vector<std::string> includeDirs;
    std::vector<std::string> externalLibs;
    LibraryDetector libDetector;

    void DetectSystemDependencies(const std::vector<fs::path>& sourceFiles) {
        fmt::print("[+] Analyzing source files for dependencies...\n");

        // Parse all includes from source files
        const auto allIncludes = IncludeParser::getAllIncludes(sourceFiles);

        // Detect libraries based on includes
        const auto detection = libDetector.detectFromIncludes(allIncludes);

        // Add detected libraries
        for (const auto& lib : detection.libraries) {
            externalLibs.push_back(lib);
            fmt::print("[+] Auto-detected library: {}\n", lib);
        }

        // Add pkg-config flags
        for (const auto& pkgFlag : detection.pkgConfigFlags) {
            LDFLAGS += " " + pkgFlag;
            fmt::print("[+] Added pkg-config flags: {}\n", pkgFlag);
        }

        // Add system includes paths
        for (const auto systemIncludes = SystemPathDetector::getSystemIncludePaths(); const auto& inc : systemIncludes) {
            includeDirs.push_back(inc);
        }

        // Add system library paths to LDFLAGS
        for (const auto systemLibPaths = SystemPathDetector::getSystemLibraryPaths(); const auto& libPath : systemLibPaths) {
            LDFLAGS += " " + libPath;
        }

        fmt::print("[+] Final LDFLAGS: {}\n", LDFLAGS);
        fmt::print("[+] Final externalLibs: {}\n", externalLibs);
        fmt::print("[+] Found {} system includes, {} libraries\n",
                  includeDirs.size(), externalLibs.size());
    }

    void HeaderScan(const fs::path& startDir = ".") {
        std::set<std::string> headerDirs;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(startDir)) {
                if (entry.is_regular_file()) {
                    const std::string ext = entry.path().extension().string();

                    if (ext == ".h" || ext == ".hpp" || ext == ".hxx" ||
                        ext == ".hh" || ext == ".pch") {

                        std::string dir = entry.path().parent_path().string();
                        if (!dir.empty()) {
                            headerDirs.insert(dir);
                        }
                    }
                }
            }
        } catch (const fs::filesystem_error& e) {
            fmt::print(stderr, "[!] Error scanning directories: {}\n", e.what());
        }

        for (const auto& dir : headerDirs) {
            includeDirs.push_back("-I" + dir);
            fmt::print("[+] Found local headers in: {}\n", dir);
        }
    }

    void WriteCache() const {
        fs::create_directory(root / ".autocc_cache");
        std::ofstream cache_file(root / ".autocc_cache/libs.cache");
        cache_file << "cxx:" << CXX << std::endl;
        cache_file << "cc:" << CC << std::endl;
        cache_file << "as:" << AS << std::endl;
        cache_file << "name:" << NAME << std::endl;
        cache_file << "flags:" << FLAGS << std::endl;
        cache_file << "ldflags:" << LDFLAGS << std::endl;
        cache_file << "build:" << BUILD << std::endl;
        for (const auto& dir : includeDirs) {
            cache_file << "include:" << dir << std::endl;
        }
        for (const auto& lib : externalLibs) {
            cache_file << "lib:" << lib << std::endl;
        }
    }

    void ReadCache() {
        std::ifstream cache_file(root / ".autocc_cache/libs.cache");
        std::string line;
        while (std::getline(cache_file, line)) {
            if (line.rfind("cxx:", 0) == 0) {
                CXX = line.substr(4);
            } else if (line.rfind("cc:", 0) == 0) {
                CC = line.substr(3);
            } else if (line.rfind("as:", 0) == 0) {
                AS = line.substr(3);
            } else if (line.rfind("name:", 0) == 0) {
                NAME = line.substr(5);
            } else if (line.rfind("flags:", 0) == 0) {
                FLAGS = line.substr(6);
            } else if (line.rfind("ldflags:", 0) == 0) {
                LDFLAGS = line.substr(8);
            } else if (line.rfind("build:", 0) == 0) {
                BUILD = line.substr(6);
            } else if (line.rfind("include:", 0) == 0) {
                includeDirs.push_back(line.substr(8));
            } else if (line.rfind("lib:", 0) == 0) {
                externalLibs.push_back(line.substr(4));
            }
        }
    }

    [[nodiscard]] std::string GetCompiler(const fs::path& file) const {
        const std::string ext = file.extension().string();
        if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".c++") return CXX;
        if (ext == ".c") return CC;
        if (ext == ".s" || ext == ".S" || ext == ".asm") return AS;
        return CXX;
    }

    static std::vector<fs::path> FindSourceFiles(const fs::path& dir) {
        std::vector<fs::path> files;
        for (auto& p : fs::recursive_directory_iterator(dir)) {
            if (p.path().extension() == ".cpp" || p.path().extension() == ".c" ||
                p.path().extension() == ".cc" || p.path().extension() == ".s" ||
                p.path().extension() == ".S" || p.path().extension() == ".asm" ||
                p.path().extension() == ".c++" || p.path().extension() == ".cxx") {
                files.push_back(p.path());
            }
        }
        return files;
    }

    [[nodiscard]] int Compile(const std::vector<fs::path>& files) const {
        std::vector<std::string> Objects;
        if (files.empty()) {
            fmt::print(std::cerr, "[!] FATAL: No source files found.\n");
            return 1;
        }

        if (const std::filesystem::path build_path = BUILD;
            std::filesystem::create_directories(build_path)) {
            fmt::print("[+] Build directory '{}' created.\n", BUILD);
        }

        for (const auto& file : files) {
            std::string compiler = GetCompiler(file);
            std::string objFile = file.stem().string() + ".o";
            std::string cmd;

            if (compiler == AS) {
                cmd = fmt::format("{} {} -felf64 -o {}/{}",
                                compiler, file.string(), BUILD, objFile);
            } else {
                cmd = fmt::format("{} -c {} -o {}/{} {} {}",
                                compiler, file.string(), BUILD, objFile,
                                FLAGS, fmt::join(includeDirs, " "));
            }

            fmt::print("[+] Compiling {} with {}...\n", file.filename().string(), compiler);
            if (system(cmd.c_str()) != 0) {
                fmt::print(stderr, "[!] FATAL: Failed to compile: {}\n", file.string());
                return 1;
            }
            Objects.push_back(objFile);
        }

        // Link all object files
        std::vector<std::string> FullObjectPaths;
        FullObjectPaths.reserve(Objects.size());
        for (const auto& obj : Objects) {
            FullObjectPaths.push_back(fmt::format("{}/{}", BUILD, obj));
        }

        const std::string LinkCmd = fmt::format("{} -o {}/{} {} {} {} {}",
                                              CXX, BUILD, NAME,
                                              fmt::join(FullObjectPaths, " "),
                                              FLAGS, LDFLAGS,
                                              fmt::join(externalLibs, " "));

        fmt::print("[+] Linking with {}...\n", CXX);
        if (system(LinkCmd.c_str()) != 0) {
            fmt::print(stderr, "[!] FATAL: Failed to link target: {}\n", NAME);
            return 1;
        }

        fmt::print("[+] Target '{}' compiled successfully\n", NAME);
        return 0;
    }
};

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (std::string arg1 = argv[1]; arg1 == "override") {
            if (fs::exists(".autocc_cache")) {
                fmt::print("[+] Invalidating cache...\n");
                fs::remove_all(".autocc_cache");
            }
            Parser parser;
            parser.UserInput();
            AutoCC autocc(parser.cxx, parser.cc, parser.name, parser.flags,
                         parser.ldflags, parser.as, parser.build, false); // false for auto-scan/cache
            if (autocc.Success != 0) {
                fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
                return 1;
            }
            return 0;
        }
        else if (arg1 == "autoscan") {
            if (fs::exists(".autocc_cache")) {
                fmt::print("[+] Invalidating cache...\n");
                fs::remove_all(".autocc_cache");
            }
            AutoCC autocc{Default::DEF_CXX, Default::DEF_CC, Default::DEF_NAME, Default::DEF_FLAGS, Default::DEF_LDFLAGS, Default::DEF_AS, Default::DEF_BUILD, Default::DEF_MANUAL};
            if (autocc.Success != 0) {
                fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
                return 1;
            }
            return 0;
        }
        else if (arg1 == "manual") {
            Parser parser;
            parser.UserInput();
            AutoCC autocc(parser.cxx, parser.cc, parser.name, parser.flags,
                         parser.ldflags, parser.as, parser.build, true); // true for manual mode
            if (autocc.Success != 0) {
                fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
                return 1;
            }
            return 0;
        }
        else if (arg1 == "rescan") {
            if (fs::exists(".autocc_cache")) {
                fmt::print("[+] Invalidating cache and rescanning...\n");
                fs::remove_all(".autocc_cache");
            }
            // Fall through to the no-argument case, which will trigger a full scan and cache writing
        } else {
            fmt::print(std::cerr, "[!] FATAL: Unknown command: {}. Use 'override', 'manual', or 'rescan'.\n", arg1);
            return 1;
        }
    }

    // Default behavior (argc == 1 or after 'rescan')
    if (fs::exists(".autocc_cache/libs.cache")) {
        AutoCC autocc{}; // Reads from cache
        if (autocc.Success != 0) {
            fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
            return 1;
        }
        return 0;
    } // No cache found, perform a full scan and new build
    fmt::print("[+] No cache found. Performing full scan and building...\n");
    Parser parser;
    parser.UserInput();
    AutoCC autocc(parser.cxx, parser.cc, parser.name, parser.flags,
                 parser.ldflags, parser.as, parser.build, false); // false for auto-scan/cache
    if (autocc.Success != 0) {
        fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
        return 1;
    }
    return 0;
}
