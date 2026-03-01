#include <gtest/gtest.h>
#include "uds.hpp"

TEST(UDSTest, GenerateSeed) {
    uds my_uds;
    // UDS 객체가 생성될 때마다 랜덤한 시드가 생성되는지 확인
    // 시드의 유효성은 랜덤하게 생성된다는 가정하에, 시드가 모두 0이 아닌지 확인
    std::cout << "Generated UDS Seed: ";
    for (int i = 0; i < 8; i++) {
        std::cout << std::hex << my_uds.uds_seed[i] << " ";
    }
    std::cout << std::dec << std::endl;  // Reset to decimal
    for (int i = 0; i < 8; i++) {
        EXPECT_NE(my_uds.uds_seed[i], 0);
    }
    // sodium_memzero는 컴파일러가 절대 최적화로 제거하지 못하도록 보장된 제로화 함수
    // 비밀값이 메모리에 그대로 남아서, 메모리 덤프나 cold boot 공격 같은 걸로 유출될 수 있음
    sodium_memzero(reinterpret_cast<void*>(my_uds.uds_seed), sizeof(my_uds.uds_seed));
}