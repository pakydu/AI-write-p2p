#include "port_analysis.h"
#include "nat_detection.h"
#include <algorithm>
#include <future>

std::vector<uint16_t> collect_port_samples(const std::string& server, uint16_t port) {
    const int SAMPLE_SIZE = 5;
    std::vector<uint16_t> ports;
    
    for(int i=0; i<SAMPLE_SIZE; ++i) {
        try {
            auto res = query_stun(server, port);
            ports.push_back(res.mapped_port);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        } catch(...) {
            if(ports.empty()) throw;
            break;
        }
    }
    return ports;
}

PortAllocationMode analyze_port_pattern(const std::vector<uint16_t>& ports) {
    // 实现之前的分析算法
    // ...
    return PortAllocationMode::SEQUENTIAL; // 示例返回值
}

NATCharacteristics enhanced_detection() {
    const std::string server = "10.180.145.151";//"stun1.l.google.com";//"stun1.l.google.com";
    const uint16_t port = 3478;

    NATCharacteristics result;
    result.type = detectNatType(server, port);
    
    auto ports = collect_port_samples(server, port);
    result.port_mode = analyze_port_pattern(ports);
    
    if(!ports.empty()) {
        result.base_port = ports.back();
        result.public_ip = query_stun(server, port).mapped_ip;
    }
    
    return result;
}