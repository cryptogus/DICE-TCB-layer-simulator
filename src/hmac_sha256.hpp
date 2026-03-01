#pragma once

#include <cstdint>
#include <sodium.h>

namespace sodium_crypto {
    struct hmac_sha256 {
        hmac_sha256(const void* msg, size_t msg_len, const void* key)
        {
            crypto_auth_hmacsha256(mac, reinterpret_cast<const uint8_t*>(msg), msg_len, reinterpret_cast<const uint8_t*>(key));
        };
        static inline uint8_t mac[crypto_auth_hmacsha256_BYTES];
    };
}