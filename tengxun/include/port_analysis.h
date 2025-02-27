#pragma once
#include <cstdint>
#include <vector>
#include "nat_detection.h"

enum class PortAllocationMode {
    STATIC, SEQUENTIAL, INCREMENTAL, RANDOM, MIXED, UNKNOWN
};

struct NATCharacteristics {
    NatType type;
    PortAllocationMode port_mode;
    uint16_t base_port;
    int expected_step;
    std::string public_ip;
};

NATCharacteristics enhanced_detection();
std::vector<uint16_t> collect_port_samples(const std::string& server, uint16_t port);