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
#include <toml.hpp>

namespace fs = std::filesystem;

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
                    const std::optional<std::string>& build)
    : CXX(cxx.value_or("clang++")), CC(cc.value_or("clang")), AS(as.value_or("nasm")),
      NAME(name.value_or("default")), FLAGS(flags.value_or("-Wall")), LDFLAGS(ldflags.value_or("")), BUILD(build.value_or("autocc")) {
        HeaderScan();
        ScanForLibs();
        WriteCache();
        Success = Compile(FindSourceFiles(root));
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

    void ScanForLibs() {
        // Dummy implementation for now
        // In a real-world scenario, this would scan system directories
        includeDirs.push_back("-I/usr/include");
        externalLibs.push_back("-L/usr/lib");
    }

    void WriteCache() {
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

    void HeaderScan(const fs::path& startDir = ".") {
        std::set<std::string> headerDirs; // Use set to avoid duplicates

        try {
            for (const auto& entry : fs::recursive_directory_iterator(startDir)) {
                if (entry.is_regular_file()) {
                    const std::string ext = entry.path().extension().string();

                    // Check for header extensions
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

        // Convert set to vector and add -I prefix
        for (const auto& dir : headerDirs) {
            includeDirs.push_back("-I" + dir);
            fmt::print("[+] Found headers in: {}\n", dir);
        }
    }


    [[nodiscard]] std::string GetCompiler(const fs::path& file) const {
        const std::string ext = file.extension().string();
        if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".c++") return CXX;
        if (ext == ".c") return CC;
        if (ext == ".s" || ext == ".S" || ext == ".asm") return AS;
        return CXX; // fallback
    }

    static std::vector<fs::path> FindSourceFiles(const fs::path& dir) {
        std::vector<fs::path> files;
        for (auto& p : fs::recursive_directory_iterator(dir)) {
            if (p.path().extension() == ".cpp" || p.path().extension() == ".c" || p.path().extension() == ".cc"
                || p.path().extension() == ".s" || p.path().extension() == ".S" || p.path().extension() == ".asm"
                || p.path().extension() == ".c++" || p.path().extension() == ".cxx") {
                files.push_back(p.path());
            }
        }
        return files;
    }

    [[nodiscard]] int Compile(const std::vector<fs::path>& files) const {
        std::vector<std::string> Objects;
        if (files.empty()) {
            fmt::print(std::cerr, "[!] FATAL: No source files (.c, .cc, .cpp) found.\n");
            return 1;
        }
        if (const std::filesystem::path build_path = BUILD; std::filesystem::create_directory(build_path)) {
            fmt::print("[+] Build directory '{}' created.\n", BUILD);
        }
        for (const auto& file : files) {
            std::string compiler = GetCompiler(file);
            std::string objFile = file.stem().string() + ".o";
            std::string cmd;
            if (compiler == AS) {
                cmd = fmt::format("{} {} -felf64 -o {}/{}",compiler, file.string(), BUILD, objFile);
            } else {
                cmd = fmt::format("{} -c {} -o {}/{} {} {} ",
                        compiler, file.string(), BUILD,objFile, FLAGS, fmt::join(includeDirs, " "));
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
        const std::string LinkCmd = fmt::format("{} -o {}/{} {} {} {} {}", CXX, BUILD, NAME, fmt::join(FullObjectPaths, " "), FLAGS, LDFLAGS, fmt::join(externalLibs, " "));
        fmt::print("[+] Linking with {}...\n", CXX);
        if (system(LinkCmd.c_str()) != 0) {
            fmt::print(stderr, "[!] FATAL: Failed to link target: {}\n", NAME);
            return 1;
        }

        fmt::print("[+] Target '{}' compiled\n", NAME);
        return 0;
    }
};

int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string arg1 = argv[1];
        if (arg1 == "override") {
            Parser parser;
            parser.UserInput();
            AutoCC autocc(parser.cxx, parser.cc, parser.name, parser.flags, parser.ldflags, parser.as, parser.build);
            if (autocc.Success != 0) {
                fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
                return 1;
            }
            return 0;
        }
        fmt::print(std::cerr, "[!] FATAL: Unknown command: {}. Use 'default' or 'override'.\n", arg1);
        return 1;
    }
    if (fs::exists(".autocc_cache/libs.cache")) {
        AutoCC autocc{};
        if (autocc.Success != 0) {
            fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
            return 1;
        }
        return 0;
    }
    Parser parser;
    parser.UserInput();
    AutoCC autocc(parser.cxx, parser.cc, parser.name, parser.flags, parser.ldflags, parser.as, parser.build);
    if (autocc.Success !=.0) {
        fmt::print(std::cerr, "[!] FATAL: Compilation failed. Exiting...\n");
        return 1;
    }
    return 0;

}