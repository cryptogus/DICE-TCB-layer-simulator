#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <sodium.h>
#include "sha256.hpp"
#include "hmac_sha256.hpp"
#include "uds.hpp"
#include "secure_buf.hpp"

namespace dice {

// DiceEngine: DICE 신뢰 체인의 시작점
//
// 실제 하드웨어에서는:
//   - UDS(Unique Device Secret)가 제조 시 fuse에 기록됨
//   - DICE ROM이 부팅 시 UDS를 읽어 첫 번째 CDI를 계산
//   - CDI 계산 후 UDS fuse는 하드웨어적으로 잠금 (다시 읽기 불가)
//
// 이 시뮬레이터에서는:
//   - randombytes_buf()로 UDS를 생성 (fuse 기록 시뮬레이션)
//   - compute_first_cdi() 호출 후 UDS를 sodium_memzero로 파괴 (fuse 잠금 시뮬레이션)
//   - 두 번째 호출 시 invalid CDI 반환 (접근 차단 시뮬레이션)
//
// CDI 계산 공식:
//   FWID = SHA-256(firmware_image)
//   CDI  = HMAC-SHA256(key=UDS, msg=FWID)
struct DiceEngine {
    uint8_t uds_bytes[32];  // UDS 저장소 (32바이트)
    bool uds_available;     // UDS가 아직 유효한지 (true: 사용 전, false: 파괴됨)

    // 랜덤 UDS 생성 (제조 시 fuse 기록 시뮬레이션)
    // 내부적으로 libsodium의 CSPRNG을 사용
    DiceEngine() : uds_available(true)
    {
        uds my_uds;
        std::memcpy(uds_bytes, my_uds.uds_seed, 32);
        // uds 구조체의 시드를 즉시 제로화 (복사본만 남기고 원본 파괴)
        sodium_memzero(my_uds.uds_seed, sizeof(my_uds.uds_seed));
    }

    // 고정 UDS로 초기화 (결정론적 테스트용)
    // 같은 UDS + 같은 펌웨어 → 항상 같은 CDI가 나오는 것을 검증할 때 사용
    explicit DiceEngine(const uint8_t (&fixed_uds)[32]) : uds_available(true)
    {
        std::memcpy(uds_bytes, fixed_uds, 32);
    }

    // 복사 금지: UDS가 두 군데에 존재하면 보안 모델이 깨짐
    DiceEngine(const DiceEngine&) = delete;
    DiceEngine& operator=(const DiceEngine&) = delete;

    // 첫 번째 CDI 계산
    //
    // fw_image: Layer 0 펌웨어 이미지 (바이트 배열)
    //
    // 처리 흐름:
    //   1. FWID = SHA-256(fw_image) — 펌웨어 식별자 계산
    //   2. CDI = HMAC-SHA256(key=UDS, msg=FWID) — UDS와 FWID를 결합
    //   3. UDS 영구 파괴 (하드웨어 fuse 잠금 시뮬레이션)
    //
    // 반환: CDI를 담은 SecureBuf<32> (valid=true)
    //       UDS가 이미 파괴된 경우 valid=false인 빈 CDI 반환
    Cdi compute_first_cdi(std::span<const uint8_t> fw_image)
    {
        // UDS가 이미 파괴된 경우: 실제 HW에서는 접근 자체가 불가능
        if (!uds_available)
            return Cdi{};

        // 1단계: 펌웨어 해시 계산
        // FWID = SHA-256(firmware)
        // ※ sha256는 static 버퍼를 사용하므로 즉시 로컬에 복사해야 함
        sodium_crypto::sha256(fw_image.data(), fw_image.size());
        uint8_t fwid[32];
        std::memcpy(fwid, sodium_crypto::sha256::hash, 32);

        // 2단계: CDI 유도
        // CDI = HMAC-SHA256(key=UDS, msg=FWID)
        // UDS를 키로 사용하고, 펌웨어 해시를 메시지로 사용
        // → 같은 UDS + 같은 펌웨어 = 항상 같은 CDI (결정론적)
        // → 펌웨어 1바이트만 바뀌어도 CDI가 완전히 달라짐
        // ※ hmac_sha256도 static 버퍼 사용 → 즉시 복사
        sodium_crypto::hmac_sha256(fwid, 32, uds_bytes);
        uint8_t cdi_raw[32];
        std::memcpy(cdi_raw, sodium_crypto::hmac_sha256::mac, 32);

        // 3단계: UDS 영구 파괴
        // 실제 하드웨어: fuse 잠금으로 물리적 접근 차단
        // 시뮬레이터: sodium_memzero로 메모리에서 완전 제거
        sodium_memzero(uds_bytes, 32);
        uds_available = false;

        // 4단계: CDI를 SecureBuf로 감싸서 반환
        // 임시 버퍼도 제로화하여 스택에 비밀이 남지 않도록 함
        Cdi result(cdi_raw);
        sodium_memzero(cdi_raw, 32);
        sodium_memzero(fwid, 32);
        return result;
    }

    // 소멸자: 혹시 남아있을 수 있는 UDS 제로화
    ~DiceEngine()
    {
        sodium_memzero(uds_bytes, 32);
    }
};

} // namespace dice
