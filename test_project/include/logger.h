#pragma once

#include <string>

class Logger {
public:
    Logger();
    void log(const std::string& message);
    void error(const std::string& message);
};