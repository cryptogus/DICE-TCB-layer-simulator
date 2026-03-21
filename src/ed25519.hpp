#pragma once

#include <cstdint>
#include <span>
#include <sodium.h>

namespace sodium_crypto {
struct ed25519 {
    static constexpr size_t SEED_BYTES = crypto_sign_ed25519_SEEDBYTES;       // 32
    static constexpr size_t PK_BYTES   = crypto_sign_ed25519_PUBLICKEYBYTES;  // 32
    static constexpr size_t SK_BYTES   = crypto_sign_ed25519_SECRETKEYBYTES;  // 64
    static constexpr size_t SIG_BYTES  = crypto_sign_ed25519_BYTES;           // 64

    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];

    // 랜덤 키 쌍 생성
    ed25519()
    {
        crypto_sign_ed25519_keypair(pk, sk);
    }

    // seed로부터 결정적 키 쌍 생성 (DICE CDI → 키 파생 용도)
    explicit ed25519(const uint8_t (&seed)[SEED_BYTES])
    {
        crypto_sign_ed25519_seed_keypair(pk, sk, seed);
    }

    // 서명
    static void sign(uint8_t (&sig)[SIG_BYTES],
                     std::span<const uint8_t> msg,
                     const uint8_t (&sk)[SK_BYTES])
    {
        crypto_sign_ed25519_detached(sig, nullptr, msg.data(), msg.size(), sk);
    }

    // 검증: 성공 시 true
    static bool verify(const uint8_t (&sig)[SIG_BYTES],
                       std::span<const uint8_t> msg,
                       const uint8_t (&pk)[PK_BYTES])
    {
        return crypto_sign_ed25519_verify_detached(sig, msg.data(), msg.size(), pk) == 0;
    }

    ~ed25519()
    {
        sodium_memzero(sk, SK_BYTES);
    }
};
}
