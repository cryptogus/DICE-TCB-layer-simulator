#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>
#include <sodium.h>
#include "sha256.hpp"
#include "hmac_sha256.hpp"
#include "hkdf.hpp"
#include "ed25519.hpp"
#include "secure_buf.hpp"
#include "simple_cert.hpp"

namespace dice {

// DiceLayer: DICE TCB(Trusted Computing Base) 레이어 하나를 표현
//
// 부트 체인의 각 레이어(부트로더, 커널, 앱 등)는 이 클래스를 통해:
//   1. 이전 레이어에서 받은 CDI로부터 암호키를 유도
//   2. 해당 레이어의 인증서를 생성 (이전 레이어의 키로 서명)
//   3. 다음 레이어를 위한 CDI를 계산
//   4. 사용한 비밀값(CDI, 시드, PRK)을 전부 파괴
//
// 키 유도 과정:
//   HKDF-Extract(salt=0x00...00, ikm=CDI)       → PRK (32바이트)
//   HKDF-Expand(PRK, "DEVICEID_KEY")             → DeviceID seed → Ed25519 키 쌍 (Layer 0만)
//   HKDF-Expand(PRK, "ALIAS_KEY")                → Alias seed    → Ed25519 키 쌍 (모든 레이어)
//
// 다음 CDI 계산:
//   next_CDI = HMAC-SHA256(key=current_CDI, msg=SHA-256(next_firmware))
//   ※ 반드시 현재 CDI를 파괴하기 전에 계산해야 함!

// 레이어 처리 결과를 담는 구조체
// 다음 레이어에 전달할 CDI와 서명에 필요한 Alias 키 정보를 포함
struct LayerResult {
    Cdi next_cdi;                                              // 다음 레이어용 CDI
    uint8_t alias_sk[sodium_crypto::ed25519::SK_BYTES] = {};   // 이 레이어의 Alias SK (다음 인증서 서명용)
    uint8_t alias_pk[sodium_crypto::ed25519::PK_BYTES] = {};   // 이 레이어의 Alias PK

    // 소멸자: Alias SK를 메모리에서 안전하게 제거
    ~LayerResult() { sodium_memzero(alias_sk, sizeof(alias_sk)); }

    // 복사 금지 (비밀키 보호)
    LayerResult(const LayerResult&) = delete;
    LayerResult& operator=(const LayerResult&) = delete;
    LayerResult(LayerResult&&) = default;
    LayerResult& operator=(LayerResult&&) = default;
    LayerResult() = default;
};

struct DiceLayer {
    // ─────────────── 유틸리티 함수 ───────────────

    // 펌웨어 해시(FWID) 계산: FWID = SHA-256(firmware_image)
    // ※ sha256는 static 버퍼를 사용하므로 결과를 즉시 로컬에 복사
    static void compute_fwid(uint8_t (&out)[32], std::span<const uint8_t> fw)
    {
        sodium_crypto::sha256(fw.data(), fw.size());
        std::memcpy(out, sodium_crypto::sha256::hash, 32);
    }

    // CDI에서 PRK 유도: PRK = HKDF-Extract(salt=zeros, ikm=CDI)
    // salt을 생략하면 RFC 5869에 따라 32바이트 0이 사용됨
    static void derive_prk(uint8_t (&prk)[32], const Cdi& cdi)
    {
        sodium_crypto::hkdf_sha256::extract(prk, cdi.as_span());
    }

    // PRK에서 키 시드 유도: seed = HKDF-Expand(PRK, info_string)
    // info 문자열이 다르면 완전히 다른 시드가 나옴
    // → "DEVICEID_KEY"와 "ALIAS_KEY"로 독립적인 키를 파생
    static void derive_seed(uint8_t (&seed)[32],
                            const uint8_t (&prk)[32],
                            const char* info_str)
    {
        auto info = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(info_str), std::strlen(info_str));
        sodium_crypto::hkdf_sha256::expand(
            std::span<uint8_t>(seed, 32), info, prk);
    }

    // 다음 레이어 CDI 계산: next_CDI = HMAC(current_CDI, SHA-256(next_firmware))
    // ※ hmac_sha256도 static 버퍼 → 즉시 복사
    static Cdi compute_next_cdi(const Cdi& current, std::span<const uint8_t> next_fw)
    {
        // 다음 펌웨어의 FWID 계산
        uint8_t fw_hash[32];
        compute_fwid(fw_hash, next_fw);

        // HMAC(key=current_CDI, msg=next_FWID)
        sodium_crypto::hmac_sha256(fw_hash, 32, current.data());
        uint8_t raw[32];
        std::memcpy(raw, sodium_crypto::hmac_sha256::mac, 32);

        Cdi result(raw);
        sodium_memzero(raw, 32);
        sodium_memzero(fw_hash, 32);
        return result;
    }

    // ─────────────── Layer 0 처리 ───────────────
    //
    // Layer 0는 특별: DeviceID 키를 생성하는 유일한 레이어
    //
    // 처리 흐름:
    //   1. FWID = SHA-256(fw_image)
    //   2. PRK = HKDF-Extract(ikm=CDI)
    //   3. DeviceID seed = HKDF-Expand(PRK, "DEVICEID_KEY") → Ed25519 키 쌍
    //   4. Alias seed = HKDF-Expand(PRK, "ALIAS_KEY") → Ed25519 키 쌍
    //   5. DeviceID Cert: 자체 서명 (subject_pk == issuer_pk == DeviceID PK)
    //   6. Alias L0 Cert: DeviceID SK로 서명, FWID 포함
    //   7. next_CDI = HMAC(CDI, SHA-256(next_fw))  ← CDI 파괴 전에 계산!
    //   8. CDI, 모든 시드, PRK, DeviceID SK 제로화
    //
    // out_device_id_cert: DeviceID 자체서명 인증서 (출력)
    // out_alias_cert:     Alias L0 인증서 (출력)
    // 반환: LayerResult (다음 CDI + Alias SK/PK)
    static LayerResult process_layer0(
        Cdi cdi,
        std::span<const uint8_t> fw_image,
        std::span<const uint8_t> next_fw,
        SimpleCert& out_device_id_cert,
        SimpleCert& out_alias_cert)
    {
        LayerResult result;

        // 1. 이 레이어의 FWID 계산
        uint8_t fwid[32];
        compute_fwid(fwid, fw_image);

        // 2. 다음 CDI를 먼저 계산 (현재 CDI 파괴 전에!)
        // ※ 순서가 중요: CDI는 아래에서 PRK 유도에도 사용되므로
        //   여기서 먼저 다음 CDI를 확보해둬야 함
        result.next_cdi = compute_next_cdi(cdi, next_fw);

        // 3. PRK 유도: HKDF-Extract(salt=zeros, ikm=CDI)
        uint8_t prk[32];
        derive_prk(prk, cdi);

        // 4. DeviceID 키 유도
        // info="DEVICEID_KEY" → 디바이스 고유 장기 신원 키
        uint8_t did_seed[32];
        derive_seed(did_seed, prk, "DEVICEID_KEY");
        sodium_crypto::ed25519 device_id(did_seed);
        sodium_memzero(did_seed, 32);  // 시드 즉시 파괴

        // 5. Alias 키 유도
        // info="ALIAS_KEY" → 이 레이어의 단기 인증 키
        uint8_t alias_seed[32];
        derive_seed(alias_seed, prk, "ALIAS_KEY");
        sodium_crypto::ed25519 alias(alias_seed);
        sodium_memzero(alias_seed, 32);

        // 6. DeviceID 인증서 (자체 서명)
        // subject_pk == issuer_pk == DeviceID PK
        // FWID는 0으로 비움 (DeviceID는 특정 레이어가 아닌 장치 신원)
        std::memcpy(out_device_id_cert.subject_pk, device_id.pk, 32);
        std::memcpy(out_device_id_cert.issuer_pk,  device_id.pk, 32);
        std::memset(out_device_id_cert.fwid, 0, 32);
        out_device_id_cert.sign(device_id.sk);

        // 7. Alias L0 인증서 (DeviceID SK로 서명)
        // subject_pk = Alias PK, issuer_pk = DeviceID PK
        // FWID = 이 레이어의 펌웨어 해시
        std::memcpy(out_alias_cert.subject_pk, alias.pk, 32);
        std::memcpy(out_alias_cert.issuer_pk,  device_id.pk, 32);
        std::memcpy(out_alias_cert.fwid,       fwid, 32);
        out_alias_cert.sign(device_id.sk);

        // 8. 결과에 Alias 키 정보 저장 (다음 레이어 서명용)
        std::memcpy(result.alias_sk, alias.sk, 64);
        std::memcpy(result.alias_pk, alias.pk, 32);

        // 9. 비밀값 전부 제로화
        sodium_memzero(prk, 32);
        sodium_memzero(fwid, 32);
        // device_id, alias의 SK는 ed25519 소멸자에서 자동 제로화
        // cdi는 SecureBuf 소멸자에서 자동 제로화

        return result;
    }

    // ─────────────── Layer N (N≥1) 처리 ───────────────
    //
    // Layer 1 이후는 Alias 키만 유도 (DeviceID 키 없음)
    //
    // 처리 흐름:
    //   1. FWID = SHA-256(fw_image)
    //   2. next_CDI = HMAC(CDI, SHA-256(next_fw))  ← CDI 파괴 전에!
    //   3. PRK = HKDF-Extract(ikm=CDI)
    //   4. Alias seed = HKDF-Expand(PRK, "ALIAS_KEY") → Ed25519 키 쌍
    //   5. Alias LN Cert: 이전 레이어 Alias SK로 서명, FWID 포함
    //   6. 비밀값 전부 제로화
    //
    // prev_alias_sk: 이전 레이어의 Alias 비밀키 (이 인증서의 서명자)
    // prev_alias_pk: 이전 레이어의 Alias 공개키 (issuer_pk에 기록됨)
    // next_fw:       다음 레이어 펌웨어 (빈 span이면 마지막 레이어)
    static LayerResult process_layer_n(
        Cdi cdi,
        std::span<const uint8_t> fw_image,
        const uint8_t (&prev_alias_sk)[64],
        const uint8_t (&prev_alias_pk)[32],
        SimpleCert& out_alias_cert,
        std::span<const uint8_t> next_fw = {})
    {
        LayerResult result;

        // 1. FWID 계산
        uint8_t fwid[32];
        compute_fwid(fwid, fw_image);

        // 2. 다음 CDI 계산 (마지막 레이어가 아닌 경우만)
        if (!next_fw.empty())
            result.next_cdi = compute_next_cdi(cdi, next_fw);

        // 3. PRK 유도
        uint8_t prk[32];
        derive_prk(prk, cdi);

        // 4. Alias 키 유도
        uint8_t alias_seed[32];
        derive_seed(alias_seed, prk, "ALIAS_KEY");
        sodium_crypto::ed25519 alias(alias_seed);
        sodium_memzero(alias_seed, 32);

        // 5. Alias LN 인증서 생성
        // subject_pk = 이 레이어의 Alias PK
        // issuer_pk  = 이전 레이어의 Alias PK
        // fwid       = 이 레이어의 펌웨어 해시
        // 서명       = 이전 레이어의 Alias SK로 서명
        std::memcpy(out_alias_cert.subject_pk, alias.pk, 32);
        std::memcpy(out_alias_cert.issuer_pk,  prev_alias_pk, 32);
        std::memcpy(out_alias_cert.fwid,       fwid, 32);
        out_alias_cert.sign(prev_alias_sk);

        // 6. 결과에 Alias 키 정보 저장
        std::memcpy(result.alias_sk, alias.sk, 64);
        std::memcpy(result.alias_pk, alias.pk, 32);

        // 7. 비밀값 제로화
        sodium_memzero(prk, 32);
        sodium_memzero(fwid, 32);

        return result;
    }
};

} // namespace dice
