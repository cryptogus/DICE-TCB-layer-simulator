#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>
#include "secure_buf.hpp"

// 이동 후 원본 버퍼가 전부 0으로 제로화되는지 확인
// DICE에서 CDI를 다음 레이어로 넘기면 이전 레이어에는 비밀이 남지 않아야 함
TEST(SecureBuf, MoveZeroesSource)
{
    const uint8_t data[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    dice::Cdi src(data);
    EXPECT_TRUE(src.valid);

    // 이동 수행: 소유권이 dst로 넘어감
    dice::Cdi dst(std::move(src));

    // 원본은 제로화되어야 함
    uint8_t zeros[32] = {};
    EXPECT_EQ(memcmp(src.buf, zeros, 32), 0);
    EXPECT_FALSE(src.valid);
}

// 이동된 대상이 원본 데이터를 정확히 보존하는지 확인
TEST(SecureBuf, MovePreservesData)
{
    const uint8_t data[32] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf0, 0x13, 0x57, 0x9b, 0xdf, 0x24
    };

    dice::Cdi src(data);
    dice::Cdi dst(std::move(src));

    // 이동된 대상은 원본 데이터와 동일해야 함
    EXPECT_EQ(memcmp(dst.buf, data, 32), 0);
    EXPECT_TRUE(dst.valid);
}

// 이동 대입 연산자 테스트
// 기존 데이터가 있는 버퍼에 새 데이터를 이동 대입할 때
// 기존 데이터가 먼저 제로화된 뒤 새 데이터로 교체되는지 확인
TEST(SecureBuf, MoveAssignment)
{
    const uint8_t data_a[32] = {0xaa};
    const uint8_t data_b[32] = {0xbb};

    dice::Cdi a(data_a);
    dice::Cdi b(data_b);

    // b를 a에 이동 대입
    a = std::move(b);

    // a는 이제 b의 데이터를 가져야 함
    EXPECT_EQ(memcmp(a.buf, data_b, 32), 0);
    EXPECT_TRUE(a.valid);

    // b는 제로화되어야 함
    uint8_t zeros[32] = {};
    EXPECT_EQ(memcmp(b.buf, zeros, 32), 0);
    EXPECT_FALSE(b.valid);
}

// 복사 생성자와 복사 대입이 컴파일 타임에 금지되는지 확인
// 비밀 데이터의 복사본이 메모리에 남는 것을 원천 차단
TEST(SecureBuf, CopyDisabled)
{
    // 컴파일 타임 검증: 복사 불가능한 타입이어야 함
    static_assert(!std::is_copy_constructible_v<dice::Cdi>,
                  "SecureBuf must not be copy constructible");
    static_assert(!std::is_copy_assignable_v<dice::Cdi>,
                  "SecureBuf must not be copy assignable");

    // 이동은 가능해야 함
    static_assert(std::is_move_constructible_v<dice::Cdi>,
                  "SecureBuf must be move constructible");
    static_assert(std::is_move_assignable_v<dice::Cdi>,
                  "SecureBuf must be move assignable");
}

// 기본 생성자로 만든 SecureBuf는 invalid 상태여야 함
TEST(SecureBuf, DefaultIsInvalid)
{
    dice::Cdi empty;
    EXPECT_FALSE(empty.valid);

    // 버퍼는 0으로 초기화되어 있어야 함
    uint8_t zeros[32] = {};
    EXPECT_EQ(memcmp(empty.buf, zeros, 32), 0);
}

// span 접근자가 올바른 크기와 포인터를 반환하는지 확인
TEST(SecureBuf, SpanAccessor)
{
    const uint8_t data[32] = {0x42};
    dice::Cdi buf(data);

    auto sp = buf.as_span();
    EXPECT_EQ(sp.size(), 32u);
    EXPECT_EQ(sp.data(), buf.buf);
}
