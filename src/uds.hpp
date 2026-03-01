#pragma once

#include <cstdint>
#include <sodium.h>

class uds {
public:
    uds() {
        randombytes_buf(uds_seed, sizeof(uds_seed));
    }
private:
    uint32_t uds_seed[8];
};