#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <array>
#include "sha256.hpp"
#include "dice_engine.hpp"
#include "dice_layer.hpp"
#include "chain_verifier.hpp"

// ═══════════════════════════════════════════════════════════════
// DICE 통합 테스트
//
// 전체 흐름을 검증:
//   UDS → DiceEngine → CDI_L0
//   CDI_L0 → DiceLayer(L0) → DeviceID Cert + Alias L0 Cert + CDI_L1
//   CDI_L1 → DiceLayer(L1) → Alias L1 Cert + CDI_L2
//   CDI_L2 → DiceLayer(L2) → Alias L2 Cert
//   ChainVerifier로 전체 체인 검증
// ═══════════════════════════════════════════════════════════════

static const uint8_t TEST_UDS[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};
static const uint8_t FW_L0[] = "bootloader v1.0";
static const uint8_t FW_L1[] = "kernel v2.3";
static const uint8_t FW_L2[] = "app v1.1";

// FWID 계산 헬퍼
static std::array<uint8_t, 32> fwid_of(std::span<const uint8_t> fw)
{
    std::array<uint8_t, 32> fwid;
    sodium_crypto::sha256(fw.data(), fw.size());
    std::memcpy(fwid.data(), sodium_crypto::sha256::hash, 32);
    return fwid;
}

// ─────────────────────────────────────────────
// 3레이어 전체 체인 구성 → 검증 성공
// 정상 부트 시나리오의 전체 흐름
// ─────────────────────────────────────────────
TEST(DiceIntegration, FullChain_3Layers)
{
    // ── 1단계: DiceEngine에서 첫 번째 CDI 유도 ──
    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);
    EXPECT_TRUE(cdi0.valid);
    EXPECT_FALSE(engine.uds_available);  // UDS 파괴 확인

    // ── 2단계: Layer 0 처리 ──
    // DeviceID 자체서명 인증서 + Alias L0 인증서 생성
    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), FW_L0, FW_L1, did_cert, alias_cert0);
    EXPECT_TRUE(r0.next_cdi.valid);

    // ── 3단계: Layer 1 처리 ──
    dice::SimpleCert alias_cert1;
    dice::LayerResult r1 = dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), FW_L1,
        r0.alias_sk, r0.alias_pk,
        alias_cert1, FW_L2);
    EXPECT_TRUE(r1.next_cdi.valid);

    // ── 4단계: Layer 2 처리 (마지막 레이어) ──
    dice::SimpleCert alias_cert2;
    dice::DiceLayer::process_layer_n(
        std::move(r1.next_cdi), FW_L2,
        r1.alias_sk, r1.alias_pk,
        alias_cert2);

    // ── 5단계: 인증서 체인 검증 ──
    std::vector<dice::SimpleCert> certs = {
        did_cert, alias_cert0, alias_cert1, alias_cert2
    };
    std::vector<std::array<uint8_t, 32>> expected_fwids = {
        fwid_of(FW_L0), fwid_of(FW_L1), fwid_of(FW_L2)
    };

    auto result = dice::ChainVerifier::verify_chain(certs, expected_fwids);
    EXPECT_TRUE(result.success) << "실패 사유: " << result.reason;
}

// ─────────────────────────────────────────────
// Layer 0 펌웨어 변조 탐지
// 부트로더가 변조되면 CDI_L0부터 전부 달라짐 → 체인 전체 무효
// ─────────────────────────────────────────────
TEST(DiceIntegration, TamperLayer0Firmware)
{
    const uint8_t fw_l0_tampered[] = "bootloader v1.0-HACKED";

    // 변조된 펌웨어로 체인 구성
    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(fw_l0_tampered);

    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), fw_l0_tampered, FW_L1, did_cert, alias_cert0);

    dice::SimpleCert alias_cert1;
    dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), FW_L1,
        r0.alias_sk, r0.alias_pk,
        alias_cert1);

    std::vector<dice::SimpleCert> certs = {did_cert, alias_cert0, alias_cert1};

    // 검증자는 원본 펌웨어의 FWID를 기대
    std::vector<std::array<uint8_t, 32>> expected_fwids = {
        fwid_of(FW_L0), fwid_of(FW_L1)
    };

    auto result = dice::ChainVerifier::verify_chain(certs, expected_fwids);
    EXPECT_FALSE(result.success);
    // Layer 0의 FWID가 다르므로 certs[1] (Alias L0)에서 실패
    EXPECT_EQ(result.failed_layer, 1);
}

// ─────────────────────────────────────────────
// Layer 1 펌웨어만 변조
// CDI_L0은 동일하지만 CDI_L1부터 달라짐
// → Layer 1 이후에서 검증 실패
// ─────────────────────────────────────────────
TEST(DiceIntegration, TamperLayer1Firmware)
{
    const uint8_t fw_l1_tampered[] = "kernel v2.3-BACKDOOR";

    // Layer 0은 정상, Layer 1만 변조
    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);

    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), FW_L0, fw_l1_tampered, did_cert, alias_cert0);

    dice::SimpleCert alias_cert1;
    dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), fw_l1_tampered,
        r0.alias_sk, r0.alias_pk,
        alias_cert1);

    std::vector<dice::SimpleCert> certs = {did_cert, alias_cert0, alias_cert1};
    std::vector<std::array<uint8_t, 32>> expected_fwids = {
        fwid_of(FW_L0), fwid_of(FW_L1)  // 원본 FWID 기대
    };

    auto result = dice::ChainVerifier::verify_chain(certs, expected_fwids);
    EXPECT_FALSE(result.success);
    // Layer 1의 FWID가 다르므로 certs[2] (Alias L1)에서 실패
    EXPECT_EQ(result.failed_layer, 2);
}

// ─────────────────────────────────────────────
// 결정론적 End-to-End 검증
// 같은 UDS + 같은 펌웨어 세트 → 완전히 동일한 인증서 체인
// 부팅마다 동일한 결과가 나와야 원격 검증자가 신뢰할 수 있음
// ─────────────────────────────────────────────
TEST(DiceIntegration, DeterministicEndToEnd)
{
    auto build_full_chain = []() {
        dice::DiceEngine engine(TEST_UDS);
        dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);

        dice::SimpleCert did_cert, alias_cert0;
        dice::LayerResult r0 = dice::DiceLayer::process_layer0(
            std::move(cdi0), FW_L0, FW_L1, did_cert, alias_cert0);

        dice::SimpleCert alias_cert1;
        dice::DiceLayer::process_layer_n(
            std::move(r0.next_cdi), FW_L1,
            r0.alias_sk, r0.alias_pk,
            alias_cert1);

        return std::vector<dice::SimpleCert>{did_cert, alias_cert0, alias_cert1};
    };

    // 두 번 독립적으로 체인 구성
    auto chain1 = build_full_chain();
    auto chain2 = build_full_chain();

    // 모든 인증서가 바이트 단위로 동일해야 함
    ASSERT_EQ(chain1.size(), chain2.size());
    for (size_t i = 0; i < chain1.size(); i++) {
        EXPECT_EQ(memcmp(chain1[i].subject_pk, chain2[i].subject_pk, 32), 0)
            << "인증서 " << i << ": subject_pk 불일치";
        EXPECT_EQ(memcmp(chain1[i].issuer_pk,  chain2[i].issuer_pk,  32), 0)
            << "인증서 " << i << ": issuer_pk 불일치";
        EXPECT_EQ(memcmp(chain1[i].fwid,       chain2[i].fwid,       32), 0)
            << "인증서 " << i << ": fwid 불일치";
        EXPECT_EQ(memcmp(chain1[i].signature,  chain2[i].signature,  64), 0)
            << "인증서 " << i << ": signature 불일치";
    }
}

// ─────────────────────────────────────────────
// 전체 처리 후 모든 비밀이 파괴되었는지 확인
// UDS, 중간 CDI가 메모리에 남아있으면 cold boot 공격 등으로 유출될 수 있음
// ─────────────────────────────────────────────
TEST(DiceIntegration, AllSecretsDestroyed)
{
    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);

    // UDS 파괴 확인
    uint8_t zeros[32] = {};
    EXPECT_EQ(memcmp(engine.uds_bytes, zeros, 32), 0);

    // Layer 0 처리 후 CDI 소유권 이전 → 원본 cdi0은 moved
    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), FW_L0, FW_L1, did_cert, alias_cert0);

    // cdi0은 이동 후 제로화되었어야 함
    EXPECT_EQ(memcmp(cdi0.buf, zeros, 32), 0);
    EXPECT_FALSE(cdi0.valid);
}
