#pragma once

#include <cstdint>
#include <sodium.h>

namespace sodium_crypto
{
class sha256 {
public:
    sha256(const void *input, size_t input_len)
    {        crypto_hash_sha256(hash, (uint8_t*)input, input_len);
    };
    static inline uint8_t hash[crypto_hash_sha256_BYTES];  // 32B
};
}