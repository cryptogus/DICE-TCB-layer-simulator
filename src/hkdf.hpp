#pragma once

#include <cstdint>
#include <cstring>
#include <sodium.h>

// HKDF-SHA256 (RFC 5869) using libsodium's HMAC-SHA256
namespace sodium_crypto {
struct hkdf_sha256 {
    static constexpr size_t HASH_LEN = crypto_auth_hmacsha256_BYTES;  // 32

    // Extract: salt + IKM -> PRK
    // PRK = HMAC-SHA256(salt, IKM)
    static void extract(uint8_t prk[HASH_LEN],
                        const void* ikm, size_t ikm_len,
                        const void* salt = nullptr, size_t salt_len = 0)
    {
        crypto_auth_hmacsha256_state state;

        // RFC 5869: if salt not provided, use zeros of HashLen
        uint8_t default_salt[HASH_LEN] = {};
        const auto* s = salt ? reinterpret_cast<const uint8_t*>(salt) : default_salt;
        size_t slen = salt ? salt_len : HASH_LEN;

        crypto_auth_hmacsha256_init(&state, s, slen);
        crypto_auth_hmacsha256_update(&state,
            reinterpret_cast<const uint8_t*>(ikm), ikm_len);
        crypto_auth_hmacsha256_final(&state, prk);
    }

    // Expand: PRK + info -> OKM
    // T(0) = empty, T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    static void expand(uint8_t* okm, size_t okm_len,
                       const void* info, size_t info_len,
                       const uint8_t prk[HASH_LEN])
    {
        uint8_t t[HASH_LEN] = {};
        size_t offset = 0;
        uint8_t counter = 1;

        while (offset < okm_len) {
            crypto_auth_hmacsha256_state state;
            crypto_auth_hmacsha256_init(&state, prk, HASH_LEN);

            if (counter > 1)
                crypto_auth_hmacsha256_update(&state, t, HASH_LEN);

            crypto_auth_hmacsha256_update(&state,
                reinterpret_cast<const uint8_t*>(info), info_len);
            crypto_auth_hmacsha256_update(&state, &counter, 1);
            crypto_auth_hmacsha256_final(&state, t);

            size_t to_copy = okm_len - offset;
            if (to_copy > HASH_LEN) to_copy = HASH_LEN;
            std::memcpy(okm + offset, t, to_copy);

            offset += to_copy;
            counter++;
        }
    }
};
}
