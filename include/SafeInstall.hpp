#pragma once
#include <filesystem>
#include <vector>
#include <string>
#include <unordered_set>

#include "log.hpp"
#include "structs.hpp"
#include "utils.hpp"

struct Target;
namespace fs = std::filesystem;

// Enhanced installation options

class SafeInstaller {
    InstallOptions options;
    std::vector<fs::path> installed_files; // For rollback
    std::unordered_set<std::string> backup_files;

public:
    explicit SafeInstaller(InstallOptions opts = {}) : options(std::move(opts)) {
        // Use user directories if not system install
        if (!options.system_install) {
            options.prefix = get_user_prefix();
        }
    }

    int install_target(const Target& target, const fs::path& target_path) {
        // Pre-installation validation
        if (auto result = validate_installation(target, target_path); result != 0) {
            return result;
        }

        // Check permissions early
        if (!check_permissions()) {
            out::error("Insufficient permissions for installation to '{}'", options.prefix);
            suggest_alternatives();
            return 1;
        }

        // Create backup plan
        backup_existing_files(target);

        try {
            // Perform installation based on type
            int result = 0;
            if (target.type == "Executable") {
                result = install_executable_safe(target_path, target.name);
            } else if (target.type == "DLibrary") {
                result = install_dynamic_library_safe(target_path, target.name);
            } else if (target.type == "SLibrary") {
                result = install_static_library_safe(target_path, target.name);
            } else {
                out::error("Unknown target type: {}", target.type);
                return 1;
            }

            if (result != 0) {
                rollback_installation();
                return result;
            }

            // Post-installation tasks
            post_install_tasks(target);
            cleanup_backups();

            return 0;
        } catch (const std::exception& e) {
            out::error("Installation failed: {}", e.what());
            rollback_installation();
            return 1;
        }
    }

private:
    int validate_installation(const Target& target, const fs::path& target_path) {
        // Check if target exists
        if (!fs::exists(target_path)) {
            out::error("Target '{}' not found at '{}'. Please build it first.",
                      target.name, target_path);
            return 1;
        }

        // Validate target integrity (basic checks)
        if (auto error_code = std::error_code{};
            fs::file_size(target_path, error_code) == 0 || error_code) {
            out::error("Target file '{}' appears to be empty or corrupted", target_path);
            return 1;
        }

        // For executables, check if they're actually executable
        if (target.type == "Executable") {
            auto perms = fs::status(target_path).permissions();
            if ((perms & fs::perms::owner_exec) == fs::perms::none) {
                out::warn("Target executable '{}' is not marked as executable", target_path);
            }
        }

        // Check for conflicting installations
        if (!options.force && check_conflicts(target)) {
            return 1;
        }

        return 0;
    }

    bool check_permissions() {
        // Test write access to target directories
        std::vector<fs::path> test_dirs = {
            fs::path(options.prefix) / options.bin_dir,
            fs::path(options.prefix) / options.lib_dir,
            fs::path(options.prefix) / options.include_dir
        };

        for (const auto& dir : test_dirs) {
            if (!ensure_directory_exists(dir)) {
                return false;
            }

            // Test write permission with a temporary file
            auto temp_file = dir / ".autocc_test_write";
            try {
                std::ofstream test(temp_file);
                if (!test.good()) {
                    return false;
                }
                fs::remove(temp_file);
            } catch (...) {
                return false;
            }
        }
        return true;
    }

    void suggest_alternatives() {
        out::info("Consider these alternatives:");
        out::info("  1. Run with sudo: sudo autocc install");
        out::info("  2. Install to user directory: autocc install --user");
        out::info("  3. Set custom prefix: autocc install --prefix=$HOME/.local");
    }

    bool check_conflicts(const Target& target) {
        fs::path dest_path;

        if (target.type == "Executable") {
            dest_path = fs::path(options.prefix) / options.bin_dir / target.name;
        } else {
            dest_path = fs::path(options.prefix) / options.lib_dir / target.output_name;
        }

        if (fs::exists(dest_path)) {
            out::warn("File '{}' already exists", dest_path);

            // Check if it's the same file (by comparing size and timestamp)
            auto existing_time = fs::last_write_time(dest_path);
            auto new_time = fs::last_write_time(fs::path(target.output_name));

            if (existing_time >= new_time) {
                out::info("Existing file is newer or same age. Use --force to overwrite.");
                return true;
            }
        }
        return false;
    }

    void backup_existing_files(const Target& target) {
        if (options.dry_run) return;

        std::vector<fs::path> files_to_backup;

        // Determine what files might be overwritten
        if (target.type == "Executable") {
            files_to_backup.push_back(
                fs::path(options.prefix) / options.bin_dir / target.name
            );
        } else {
            files_to_backup.push_back(
                fs::path(options.prefix) / options.lib_dir / target.output_name
            );

            // Also backup headers if they exist
            auto header_dir = fs::path(options.prefix) / options.include_dir / target.name;
            if (fs::exists(header_dir)) {
                files_to_backup.push_back(header_dir);
            }
        }

        for (const auto& file : files_to_backup) {
            if (fs::exists(file)) {
                auto backup_path = file.string() + ".autocc.bak";
                try {
                    if (fs::is_directory(file)) {
                        fs::copy(file, backup_path, fs::copy_options::recursive);
                    } else {
                        fs::copy_file(file, backup_path);
                    }
                    backup_files.insert(backup_path);
                    out::info("Backed up '{}' to '{}'", file, backup_path);
                } catch (const std::exception& e) {
                    out::warn("Failed to create backup of '{}': {}", file, e.what());
                }
            }
        }
    }

    int install_executable_safe(const fs::path& target_path, const std::string& target_name) {
        auto dest_dir = fs::path(options.prefix) / options.bin_dir;
        auto dest_path = dest_dir / target_name;

        if (options.dry_run) {
            out::info("Would install '{}' to '{}'", target_path, dest_path);
            return 0;
        }

        // Ensure destination directory exists
        if (!ensure_directory_exists(dest_dir)) {
            return 1;
        }

        // Copy with proper permissions
        if (!copy_file_with_permissions(target_path, dest_path, 0755)) {
            return 1;
        }

        // Verify installation
        if (!verify_executable_installation(dest_path)) {
            return 1;
        }

        installed_files.push_back(dest_path);
        out::success("Installed executable '{}' to '{}'", target_name, dest_path);
        return 0;
    }

    int install_dynamic_library_safe(const fs::path& target_path, const std::string& target_name) {
        auto lib_dir = fs::path(options.prefix) / options.lib_dir;
        auto dest_path = lib_dir / target_path.filename();

        if (options.dry_run) {
            out::info("Would install '{}' to '{}'", target_path, dest_path);
            return 0;
        }

        if (!ensure_directory_exists(lib_dir)) {
            return 1;
        }

        // Copy library file
        if (!copy_file_with_permissions(target_path, dest_path, 0644)) {
            return 1;
        }

        installed_files.push_back(dest_path);

        // Install headers
        if (auto header_result = install_headers_safe(target_name); header_result != 0) {
            return header_result;
        }

        // Handle library linking and caching
        handle_library_cache(dest_path);

        out::success("Installed dynamic library '{}' to '{}'", target_name, dest_path);
        return 0;
    }

    int install_static_library_safe(const fs::path& target_path, const std::string& target_name) {
        auto lib_dir = fs::path(options.prefix) / options.lib_dir;
        auto dest_path = lib_dir / target_path.filename();

        if (options.dry_run) {
            out::info("Would install '{}' to '{}'", target_path, dest_path);
            return 0;
        }

        if (!ensure_directory_exists(lib_dir)) {
            return 1;
        }

        // Copy library file
        if (!copy_file_with_permissions(target_path, dest_path, 0644)) {
            return 1;
        }

        installed_files.push_back(dest_path);

        // Install headers
        if (auto header_result = install_headers_safe(target_name); header_result != 0) {
            return header_result;
        }

        out::success("Installed static library '{}' to '{}'", target_name, dest_path);
        return 0;
    }

    int install_headers_safe(const std::string& target_name) {
        const std::vector<std::string> header_dirs = {"include", "inc", "headers"};

        for (const auto& dir : header_dirs) {
            if (!fs::exists(dir) || !fs::is_directory(dir)) continue;

            auto dest_dir = fs::path(options.prefix) / options.include_dir / target_name;

            if (options.dry_run) {
                out::info("Would install headers from '{}' to '{}'", dir, dest_dir);
                return 0;
            }

            if (!ensure_directory_exists(dest_dir)) {
                return 1;
            }

            // Copy headers recursively with proper error handling
            try {
                for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                    if (entry.is_regular_file()) {
                        auto rel_path = fs::relative(entry.path(), dir);
                        auto dest_file = dest_dir / rel_path;

                        // Ensure parent directory exists
                        ensure_directory_exists(dest_file.parent_path());

                        if (!copy_file_with_permissions(entry.path(), dest_file, 0644)) {
                            out::warn("Failed to copy header '{}'", entry.path());
                            continue;
                        }
                        installed_files.push_back(dest_file);
                    }
                }

                out::info("Installed headers from '{}' to '{}'", dir, dest_dir);
                return 0; // Only install from first found directory

            } catch (const std::exception& e) {
                out::error("Failed to install headers: {}", e.what());
                return 1;
            }
        }

        out::warn("No header directory found. Consider creating an 'include/' directory.");
        return 0;
    }

    bool ensure_directory_exists(const fs::path& dir) {
        if (fs::exists(dir)) return true;

        try {
            fs::create_directories(dir);
            return true;
        } catch (const std::exception& e) {
            out::error("Failed to create directory '{}': {}", dir, e.what());
            return false;
        }
    }

    bool copy_file_with_permissions(const fs::path& src, const fs::path& dest, int mode) {
        try {
            fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
            fs::permissions(dest, static_cast<fs::perms>(mode));
            return true;
        } catch (const std::exception& e) {
            out::error("Failed to copy '{}' to '{}': {}", src, dest, e.what());
            return false;
        }
    }

    bool verify_executable_installation(const fs::path& exe_path) {
        // Basic verification that the executable is functional
        if (!fs::exists(exe_path)) {
            out::error("Installation verification failed: '{}' does not exist", exe_path);
            return false;
        }

        auto perms = fs::status(exe_path).permissions();
        if ((perms & fs::perms::owner_exec) == fs::perms::none) {
            out::error("Installation verification failed: '{}' is not executable", exe_path);
            return false;
        }

        return true;
    }

    void handle_library_cache(const fs::path& lib_path) {
        // Only run ldconfig if we're installing to system directories
        if (options.system_install && Execution::isCommandExecutable("ldconfig")) {
            // Check if library is in a standard path that ldconfig will find
            std::string lib_dir = lib_path.parent_path();
            if (lib_dir.find("/usr/local/lib") != std::string::npos ||
                lib_dir.find("/usr/lib") != std::string::npos) {

                if (auto result = Execution::execute("ldconfig"); result.exit_code == 0) {
                    out::info("Updated system library cache");
                } else {
                    out::warn("Failed to update library cache, you may need to run 'ldconfig' manually");
                }
            }
        }
    }

    void post_install_tasks(const Target& target) {
        if (options.dry_run) return;

        // Create symbolic links if requested
        if (options.create_symlinks && target.type == "Executable") {
            create_symlinks(target);
        }

        // Update PATH suggestion for user installations
        if (!options.system_install) {
            suggest_path_update();
        }
    }

    void create_symlinks(const Target& target) {
        // Create common symlinks (e.g., versioned names)
        // This is target-specific logic that could be expanded
    }

    void suggest_path_update() {
        auto bin_dir = fs::path(options.prefix) / options.bin_dir;
        out::info("Add '{}' to your PATH to use installed executables:", bin_dir);
        out::info("  echo 'export PATH=\"{}:$PATH\"' >> ~/.bashrc", bin_dir);
    }

    void rollback_installation() {
        out::info("Rolling back installation...");

        for (const auto& file : installed_files) {
            try {
                if (fs::exists(file)) {
                    if (fs::is_directory(file)) {
                        fs::remove_all(file);
                    } else {
                        fs::remove(file);
                    }
                    out::info("Removed '{}'", file);
                }
            } catch (const std::exception& e) {
                out::warn("Failed to remove '{}' during rollback: {}", file, e.what());
            }
        }

        // Restore backups
        for (const auto& backup : backup_files) {
            auto original = backup.substr(0, backup.find(".autocc.bak"));
            try {
                if (fs::exists(backup)) {
                    fs::rename(backup, original);
                    out::info("Restored '{}' from backup", original);
                }
            } catch (const std::exception& e) {
                out::warn("Failed to restore backup '{}': {}", backup, e.what());
            }
        }
    }

    void cleanup_backups() {
        for (const auto& backup : backup_files) {
            try {
                if (fs::exists(backup)) {
                    fs::remove_all(backup);
                }
            } catch (...) {
                // Ignore cleanup failures
            }
        }
    }

    std::string get_user_prefix() {
        if (auto home = std::getenv("HOME")) {
            return std::string(home) + "/.local";
        }
        return "/tmp/autocc_install"; // Fallback
    }
};
