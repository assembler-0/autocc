#include "../include/utils.h"
#include <sstream>
#include <chrono>

std::string get_message() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << "Hello from utils.cpp at " << std::ctime(&time_t);
    
    std::string result = ss.str();
    // Remove trailing newline
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    
    return result;
}

int calculate_sum(int a, int b) {
    return a + b;
}