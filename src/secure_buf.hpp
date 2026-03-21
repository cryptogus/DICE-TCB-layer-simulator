#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <sodium.h>

namespace dice {

// SecureBuf<N>: RAII 이동 전용 보안 버퍼
//
// DICE에서 CDI, 키 시드 등 비밀값은 사용 후 반드시 메모리에서 제거해야 한다.
// 이 클래스는 다음을 보장한다:
//   1. 소멸자에서 sodium_memzero로 안전하게 제로화
//      (컴파일러 최적화로 제거되지 않음)
//   2. 복사 불가 — 비밀값의 복사본이 메모리에 남는 것을 방지
//   3. 이동 시 원본 즉시 제로화 — 소유권 이전 후 원본 비밀 파괴
//
// 사용 예:
//   dice::Cdi cdi(raw_bytes);      // 32바이트 비밀값을 SecureBuf로 감싸기
//   dice::Cdi moved = std::move(cdi); // 소유권 이전, cdi는 제로화됨
//   // moved 스코프 종료 시 자동 제로화
template<size_t N>
struct SecureBuf {
    uint8_t buf[N] = {};    // 내부 데이터 버퍼 (기본 0 초기화)
    bool valid = false;     // 유효한 비밀 데이터를 보유 중인지 여부

    // 기본 생성자: 빈(무효) 상태
    SecureBuf() = default;

    // 고정 크기 배열로부터 생성
    // src를 복사한 뒤 유효 상태로 설정
    explicit SecureBuf(const uint8_t (&src)[N]) : valid(true)
    {
        std::memcpy(buf, src, N);
    }

    // span으로부터 생성 (런타임 크기 일치 필요)
    explicit SecureBuf(std::span<const uint8_t> src) : valid(src.size() == N)
    {
        if (valid)
            std::memcpy(buf, src.data(), N);
    }

    // 복사 금지: 비밀 데이터의 복사본이 메모리에 남는 것을 방지
    // CDI가 두 군데에 동시에 존재하면 "레이어 격리" 원칙에 위배됨
    SecureBuf(const SecureBuf&) = delete;
    SecureBuf& operator=(const SecureBuf&) = delete;

    // 이동 생성자: 원본 데이터를 가져온 뒤 원본을 즉시 제로화
    // DICE에서 CDI 소유권을 다음 레이어로 넘길 때 사용
    // 이동 후 원본은 valid=false가 되어 재사용 불가
    SecureBuf(SecureBuf&& other) noexcept : valid(other.valid)
    {
        std::memcpy(buf, other.buf, N);
        sodium_memzero(other.buf, N);   // 원본 비밀 즉시 파괴
        other.valid = false;
    }

    // 이동 대입 연산자
    SecureBuf& operator=(SecureBuf&& other) noexcept
    {
        if (this != &other) {
            sodium_memzero(buf, N);     // 기존 데이터 먼저 제로화
            std::memcpy(buf, other.buf, N);
            valid = other.valid;
            sodium_memzero(other.buf, N);
            other.valid = false;
        }
        return *this;
    }

    // 소멸자: 메모리에서 비밀 완전 제거
    // sodium_memzero는 컴파일러가 "어차피 사라질 데이터"라고 판단해
    // 제로화를 생략하는 최적화를 방지함
    ~SecureBuf()
    {
        sodium_memzero(buf, N);
    }

    // 접근자
    uint8_t*       data()       { return buf; }
    const uint8_t* data() const { return buf; }
    constexpr size_t size() const { return N; }
    std::span<uint8_t>       as_span()       { return {buf, N}; }
    std::span<const uint8_t> as_span() const { return {buf, N}; }
};

// 자주 사용하는 크기의 타입 별칭
using Cdi = SecureBuf<32>;  // CDI: 32바이트 비밀값 (Compound Device Identifier)

} // namespace dice
