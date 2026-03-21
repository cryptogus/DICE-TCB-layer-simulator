#include <gtest/gtest.h>
#include <cstring>
#include "ed25519.hpp"

TEST(Ed25519, SignAndVerify)
{
    sodium_crypto::ed25519 kp;
    const uint8_t msg[] = "Hello DICE";

    uint8_t sig[sodium_crypto::ed25519::SIG_BYTES];
    sodium_crypto::ed25519::sign(sig, msg, kp.sk);
    EXPECT_TRUE(sodium_crypto::ed25519::verify(sig, msg, kp.pk));
}

TEST(Ed25519, VerifyRejectsTampered)
{
    sodium_crypto::ed25519 kp;
    const uint8_t msg[] = "Hello DICE";

    uint8_t sig[sodium_crypto::ed25519::SIG_BYTES];
    sodium_crypto::ed25519::sign(sig, msg, kp.sk);

    // 메시지 변조 시 검증 실패
    const uint8_t tampered[] = "Hello RICE";
    EXPECT_FALSE(sodium_crypto::ed25519::verify(sig, tampered, kp.pk));
}

TEST(Ed25519, DeterministicFromSeed)
{
    const uint8_t seed[sodium_crypto::ed25519::SEED_BYTES] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    // 같은 seed → 같은 키 쌍
    sodium_crypto::ed25519 a(seed), b(seed);
    EXPECT_EQ(memcmp(a.pk, b.pk, sodium_crypto::ed25519::PK_BYTES), 0);
    EXPECT_EQ(memcmp(a.sk, b.sk, sodium_crypto::ed25519::SK_BYTES), 0);

    // seed로 생성한 키로 서명/검증
    const uint8_t msg[] = "deterministic test";
    uint8_t sig[sodium_crypto::ed25519::SIG_BYTES];
    sodium_crypto::ed25519::sign(sig, msg, a.sk);
    EXPECT_TRUE(sodium_crypto::ed25519::verify(sig, msg, b.pk));
}

TEST(Ed25519, WrongKeyRejects)
{
    sodium_crypto::ed25519 kp1, kp2;
    const uint8_t msg[] = "key mismatch test";

    uint8_t sig[sodium_crypto::ed25519::SIG_BYTES];
    sodium_crypto::ed25519::sign(sig, msg, kp1.sk);

    // 다른 키의 공개키로 검증 실패
    EXPECT_FALSE(sodium_crypto::ed25519::verify(sig, msg, kp2.pk));
}
