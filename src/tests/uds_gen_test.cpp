#include <gtest/gtest.h>
#include <cstring>
#include "uds.hpp"

TEST(UDS, GenerateSeed)
{
    uds my_uds;

    // 랜덤 시드가 all-zero가 아닌지 확인
    uint32_t zeros[8] = {};
    EXPECT_NE(memcmp(my_uds.uds_seed, zeros, sizeof(zeros)), 0);

    // sodium_memzero는 컴파일러가 절대 최적화로 제거하지 못하도록 보장된 제로화 함수
    // 비밀값이 메모리에 그대로 남아서, 메모리 덤프나 cold boot 공격 같은 걸로 유출될 수 있음
    sodium_memzero(my_uds.uds_seed, sizeof(my_uds.uds_seed));
}

TEST(UDS, UniqueSeed)
{
    uds a, b;

    // 두 UDS 인스턴스의 시드가 서로 다른지 확인
    EXPECT_NE(memcmp(a.uds_seed, b.uds_seed, sizeof(a.uds_seed)), 0);

    sodium_memzero(a.uds_seed, sizeof(a.uds_seed));
    sodium_memzero(b.uds_seed, sizeof(b.uds_seed));
}
