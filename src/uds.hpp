#pragma once

#include <cstdint>
#include <sodium.h>

struct uds {
    uds() {
        randombytes_buf(uds_seed, sizeof(uds_seed));
    }
    uint32_t uds_seed[8];
};