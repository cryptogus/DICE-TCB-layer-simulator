#include <gtest/gtest.h>
#include "sha256.hpp"

TEST(SHA256Test, HelloWorld) {
    const char* input = "Hello, World!";
    sodium_crypto::sha256(input, strlen(input));

    // "Hello, World!"의 SHA-256 기대값
    const uint8_t expected[32] = {
        0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
        0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
        0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
        0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
    };
    std::cout << "Computed SHA-256: ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << (int)sodium_crypto::sha256::hash[i];
    }
    std::cout << std::dec << std::endl;  // Reset to decimal
    EXPECT_EQ(memcmp(sodium_crypto::sha256::hash, expected, 32), 0);
}