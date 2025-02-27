#ifndef STUN_HPP__
#define STUN_HPP__

#include <cstdint>

const uint32_t MAGIC_COOKIE = 0x2112A442;

struct StunHeader {
        uint16_t type;
        uint16_t length;
        uint32_t magic;
        uint8_t transaction_id[12];
};

#endif // STUN_SER_HPP__