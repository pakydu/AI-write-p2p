#define CATCH_CONFIG_MAIN
#include "catch2/catch.hpp"
#include "../include/port_analysis.h"
#include "mock_stun.h"

TEST_CASE("Full Cone NAT Detection") {
    MockNAT nat(NatType::FULL_CONE, PortAllocationMode::STATIC);
    REQUIRE(detectNatType(nat) == NatType::FULL_CONE);
}

TEST_CASE("Sequential Port Analysis") {
    std::vector<uint16_t> ports {1000, 1001, 1002, 1003};
    REQUIRE(analyze_port_pattern(ports) == PortAllocationMode::SEQUENTIAL);
}