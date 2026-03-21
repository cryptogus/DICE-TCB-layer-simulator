#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <span>
#include "ed25519.hpp"

namespace dice {

// SimpleCert: DICE용 간이 인증서 구조
//
// X.509 전체를 구현하는 대신, DICE 인증에 필요한 핵심 필드만 포함:
//   - subject_pk: 이 인증서의 주체(소유자)의 Ed25519 공개키
//   - issuer_pk:  이 인증서를 발행(서명)한 자의 Ed25519 공개키
//   - fwid:       해당 레이어 펌웨어의 SHA-256 해시 (Firmware IDentifier)
//   - signature:  issuer의 비밀키로 TBS 데이터에 대해 생성한 Ed25519 서명
//
// 인증서 체인에서의 역할:
//   DeviceID Cert (자체 서명: subject_pk == issuer_pk)
//     └─ Alias L0 Cert (DeviceID SK로 서명, FWID_L0 포함)
//          └─ Alias L1 Cert (Alias L0 SK로 서명, FWID_L1 포함)
//
// TBS(To-Be-Signed) 구조:
//   subject_pk(32B) || issuer_pk(32B) || fwid(32B) = 총 96바이트
//   이 96바이트가 서명/검증의 대상
struct SimpleCert {
    static constexpr size_t PK_BYTES   = 32;
    static constexpr size_t FWID_BYTES = 32;
    static constexpr size_t SIG_BYTES  = 64;
    static constexpr size_t TBS_BYTES  = PK_BYTES + PK_BYTES + FWID_BYTES;  // 96

    uint8_t subject_pk[PK_BYTES];   // 주체의 공개키 (이 인증서가 증명하는 키)
    uint8_t issuer_pk[PK_BYTES];    // 발행자의 공개키 (이 인증서에 서명한 키)
    uint8_t fwid[FWID_BYTES];       // 펌웨어 식별자 (SHA-256 해시)
    uint8_t signature[SIG_BYTES];   // Ed25519 서명 (TBS 데이터에 대한 서명)

    // TBS(To-Be-Signed) 데이터 생성
    // 서명과 검증 모두 이 함수가 만든 동일한 바이트열을 사용
    // 순서: subject_pk || issuer_pk || fwid
    std::array<uint8_t, TBS_BYTES> tbs() const
    {
        std::array<uint8_t, TBS_BYTES> result;
        std::memcpy(result.data(),      subject_pk, PK_BYTES);
        std::memcpy(result.data() + 32, issuer_pk,  PK_BYTES);
        std::memcpy(result.data() + 64, fwid,       FWID_BYTES);
        return result;
    }

    // 서명 생성
    // issuer_sk: 발행자의 Ed25519 비밀키 (64바이트)
    // TBS 데이터에 대해 Ed25519 detached 서명을 생성하여 signature에 저장
    void sign(const uint8_t (&issuer_sk)[sodium_crypto::ed25519::SK_BYTES])
    {
        auto payload = tbs();
        sodium_crypto::ed25519::sign(signature, payload, issuer_sk);
    }

    // 서명 검증
    // 인증서에 기록된 issuer_pk로 TBS 데이터의 서명을 검증
    // 성공 시 true 반환
    // - 인증서의 어떤 필드라도 변조되면 TBS가 달라져 검증 실패
    // - 발행자가 아닌 다른 키로 서명했다면 검증 실패
    bool verify() const
    {
        auto payload = tbs();
        return sodium_crypto::ed25519::verify(signature, payload, issuer_pk);
    }

    // 자체 서명 인증서인지 확인
    // DeviceID Cert는 자기 자신의 키로 서명하므로 subject_pk == issuer_pk
    bool is_self_signed() const
    {
        return std::memcmp(subject_pk, issuer_pk, PK_BYTES) == 0;
    }
};

} // namespace dice
