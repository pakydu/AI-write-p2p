#include "port_analysis.h"
#include <iostream>
#include <fstream>
//#include <nlohmann/json.hpp>

//using json = nlohmann::json;

void load_config(const std::string& path) {
    std::ifstream f(path);
    //json config = json::parse(f);
    // 加载配置项...
}

void show_dashboard(const NATCharacteristics& info) {
    std::cout << "Public IP: " << info.public_ip << "\n"
              << "Base Port: " << info.base_port << "\n"
              << "Detection Results:\n"
              << "  NAT Type: " << static_cast<int>(info.type) << "\n"
              << "  Port Mode: " << static_cast<int>(info.port_mode) << "\n";
}

int main() {
    try {
        load_config("config.json");
        auto nat_info = enhanced_detection();
        show_dashboard(nat_info);
        
        // P2P连接逻辑...
        
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}