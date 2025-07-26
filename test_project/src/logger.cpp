#include "../include/logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>

Logger::Logger() {
    // Constructor
}

void Logger::log(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
}

void Logger::error(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::cerr << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] ERROR: " << message << std::endl;
}