#include <gtest/gtest.h>
#include <cstring>
#include "dice_engine.hpp"

// 고정 UDS와 같은 펌웨어를 넣으면 항상 같은 CDI가 나오는지 확인
// DICE의 핵심 속성: 결정론적 유도 (deterministic derivation)
// 같은 디바이스(UDS) + 같은 펌웨어 → 부팅할 때마다 동일한 CDI → 동일한 키
TEST(DiceEngine, DeterministicCDI)
{
    const uint8_t fixed_uds[32] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x17, 0x28,
        0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0
    };
    const uint8_t firmware[] = "bootloader v1.0";

    // 같은 UDS + 같은 펌웨어로 두 번 시도
    dice::DiceEngine engine1(fixed_uds);
    dice::Cdi cdi1 = engine1.compute_first_cdi(firmware);

    dice::DiceEngine engine2(fixed_uds);
    dice::Cdi cdi2 = engine2.compute_first_cdi(firmware);

    // 두 CDI는 동일해야 함
    EXPECT_TRUE(cdi1.valid);
    EXPECT_TRUE(cdi2.valid);
    EXPECT_EQ(memcmp(cdi1.buf, cdi2.buf, 32), 0);
}

// 같은 UDS라도 펌웨어가 다르면 CDI가 완전히 달라지는지 확인
// 펌웨어 변조 시 CDI가 바뀌어 기존 키와 인증서가 모두 무효화됨
TEST(DiceEngine, DifferentFirmwareDifferentCDI)
{
    const uint8_t fixed_uds[32] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21
    };
    const uint8_t fw_good[] = "bootloader v1.0";
    const uint8_t fw_bad[]  = "bootloader v1.1";  // 버전 1바이트 차이

    dice::DiceEngine engine1(fixed_uds);
    dice::Cdi cdi1 = engine1.compute_first_cdi(fw_good);

    dice::DiceEngine engine2(fixed_uds);
    dice::Cdi cdi2 = engine2.compute_first_cdi(fw_bad);

    // 펌웨어가 다르면 CDI도 달라야 함
    EXPECT_TRUE(cdi1.valid);
    EXPECT_TRUE(cdi2.valid);
    EXPECT_NE(memcmp(cdi1.buf, cdi2.buf, 32), 0);
}

// compute_first_cdi() 호출 후 UDS가 영구 파괴되는지 확인
// 실제 HW: fuse 잠금으로 물리적 접근 차단
// 시뮬레이터: 메모리 제로화 + 플래그로 재사용 차단
TEST(DiceEngine, UDSDestroyedAfterUse)
{
    const uint8_t fixed_uds[32] = {0xff};
    const uint8_t firmware[] = "test firmware";

    dice::DiceEngine engine(fixed_uds);
    EXPECT_TRUE(engine.uds_available);

    // 첫 번째 호출: 정상적으로 CDI 생성
    dice::Cdi cdi = engine.compute_first_cdi(firmware);
    EXPECT_TRUE(cdi.valid);

    // UDS 파괴 확인
    EXPECT_FALSE(engine.uds_available);

    // UDS 메모리가 전부 0인지 확인
    uint8_t zeros[32] = {};
    EXPECT_EQ(memcmp(engine.uds_bytes, zeros, 32), 0);
}

// UDS 파괴 후 두 번째 호출 시 invalid CDI를 반환하는지 확인
// 실제 HW에서는 접근 자체가 불가능하지만,
// 시뮬레이터에서는 valid=false인 CDI로 이를 표현
TEST(DiceEngine, SecondCallReturnsInvalid)
{
    const uint8_t fixed_uds[32] = {0x42};
    const uint8_t firmware[] = "test firmware";

    dice::DiceEngine engine(fixed_uds);

    // 첫 번째 호출: 성공
    dice::Cdi cdi1 = engine.compute_first_cdi(firmware);
    EXPECT_TRUE(cdi1.valid);

    // 두 번째 호출: UDS가 이미 파괴됨 → invalid
    dice::Cdi cdi2 = engine.compute_first_cdi(firmware);
    EXPECT_FALSE(cdi2.valid);
}
