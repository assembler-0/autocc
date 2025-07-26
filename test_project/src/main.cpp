#include <iostream>
#include <string>
#include "../include/utils.h"
#include "../include/logger.h"

int main() {
    Logger logger;
    logger.log("Starting application...");
    
    std::string message = get_message();
    std::cout << "Message from utils: " << message << std::endl;
    
    logger.log("Application completed successfully");
    return 0;
}