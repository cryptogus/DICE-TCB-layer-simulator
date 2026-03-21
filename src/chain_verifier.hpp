#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <array>
#include <string>
#include "simple_cert.hpp"

namespace dice {

// ChainVerifier: DICE 인증서 체인 검증기
//
// 원격 검증자(Verifier)가 디바이스의 신뢰성을 확인하는 과정을 구현:
//   1. 인증서 체인의 루트(DeviceID Cert)가 자체 서명이고 유효한지 확인
//   2. 각 인증서가 이전 인증서의 주체(subject)에 의해 서명되었는지 확인
//   3. 각 인증서의 FWID가 기대하는 펌웨어 해시와 일치하는지 확인
//
// 검증 체인 구조:
//   certs[0]: DeviceID Cert (자체 서명, FWID 없음)
//   certs[1]: Alias L0 Cert (DeviceID SK로 서명, FWID = SHA-256(fw_L0))
//   certs[2]: Alias L1 Cert (Alias L0 SK로 서명, FWID = SHA-256(fw_L1))
//   ...
//
// expected_fwids[i]는 certs[i+1]의 FWID와 비교됨:
//   expected_fwids[0] ↔ certs[1].fwid (Alias L0의 FWID)
//   expected_fwids[1] ↔ certs[2].fwid (Alias L1의 FWID)
struct ChainVerifier {

    // 검증 결과
    struct Result {
        bool success;           // 전체 검증 성공 여부
        int failed_layer;       // 실패한 인증서 인덱스 (-1이면 성공)
        std::string reason;     // 실패 사유 (한국어)
    };

    // 인증서 체인 검증
    //
    // certs:          인증서 배열 [DeviceID, Alias L0, Alias L1, ...]
    // expected_fwids: 기대 FWID 배열 (certs보다 1개 적어야 함)
    //                 expected_fwids[i] ↔ certs[i+1].fwid
    //
    // 검증 단계:
    //   (1) 체인이 비어있지 않은지
    //   (2) 루트 인증서가 자체 서명이고 서명이 유효한지
    //   (3) 각 후속 인증서에 대해:
    //       - issuer_pk가 이전 인증서의 subject_pk와 일치하는지 (체인 연결)
    //       - 서명이 유효한지
    //       - FWID가 기대값과 일치하는지
    static Result verify_chain(
        std::span<const SimpleCert> certs,
        std::span<const std::array<uint8_t, 32>> expected_fwids)
    {
        // 빈 체인 검사
        if (certs.empty())
            return {false, -1, "인증서 체인이 비어있음"};

        // ── 루트 인증서 (DeviceID Cert) 검증 ──

        const auto& root = certs[0];

        // 루트는 반드시 자체 서명이어야 함
        if (!root.is_self_signed())
            return {false, 0, "루트 인증서가 자체 서명이 아님"};

        // 루트 서명 검증
        if (!root.verify())
            return {false, 0, "루트 인증서 서명 검증 실패"};

        // ── 후속 인증서 (Alias Certs) 순차 검증 ──

        for (size_t i = 1; i < certs.size(); i++) {
            const auto& cert = certs[i];
            const auto& prev = certs[i - 1];

            // 체인 연결 확인: 이 인증서의 issuer_pk == 이전 인증서의 subject_pk
            // 이것이 끊어지면 인증서가 올바른 발행자에 의해 서명되지 않은 것
            if (std::memcmp(cert.issuer_pk, prev.subject_pk, 32) != 0)
                return {false, static_cast<int>(i),
                        "인증서 " + std::to_string(i) + ": issuer_pk 체인 단절"};

            // 서명 검증
            if (!cert.verify())
                return {false, static_cast<int>(i),
                        "인증서 " + std::to_string(i) + ": 서명 검증 실패"};

            // FWID 일치 확인
            // expected_fwids[i-1]이 certs[i]의 FWID에 대응
            size_t fwid_idx = i - 1;
            if (fwid_idx < expected_fwids.size()) {
                if (std::memcmp(cert.fwid, expected_fwids[fwid_idx].data(), 32) != 0)
                    return {false, static_cast<int>(i),
                            "인증서 " + std::to_string(i) + ": FWID 불일치 "
                            "(펌웨어 변조 의심)"};
            }
        }

        return {true, -1, ""};
    }
};

} // namespace dice
