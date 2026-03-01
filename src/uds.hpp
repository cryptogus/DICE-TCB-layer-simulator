#pragma once

#include <cstdint>
#include <sys/random.h>

class uds {
public:
    uds() {
        getrandom(uds_seed, sizeof(uds_seed), 0);  // 0 = /dev/urandom
    }
private:
    uint32_t uds_seed[8];
};