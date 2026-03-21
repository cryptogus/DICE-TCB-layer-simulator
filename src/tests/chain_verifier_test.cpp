#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <array>
#include "sha256.hpp"
#include "dice_engine.hpp"
#include "dice_layer.hpp"
#include "chain_verifier.hpp"

// 테스트 공통 상수
static const uint8_t TEST_UDS[32] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x17, 0x28,
    0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0
};
static const uint8_t FW_L0[] = "bootloader v1.0";
static const uint8_t FW_L1[] = "kernel v2.3";
static const uint8_t FW_L2[] = "app v1.1";

// 3레이어 체인을 구성하는 헬퍼 함수
// 반환: {인증서 벡터, 기대 FWID 벡터}
static auto build_chain()
{
    struct ChainData {
        std::vector<dice::SimpleCert> certs;
        std::vector<std::array<uint8_t, 32>> fwids;
    };
    ChainData chain;

    // DiceEngine → CDI_L0
    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);

    // Layer 0 처리: DeviceID Cert + Alias L0 Cert
    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), FW_L0, FW_L1, did_cert, alias_cert0);

    // Layer 1 처리: Alias L1 Cert
    dice::SimpleCert alias_cert1;
    dice::LayerResult r1 = dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), FW_L1,
        r0.alias_sk, r0.alias_pk,
        alias_cert1, FW_L2);

    // Layer 2 처리: Alias L2 Cert (마지막 레이어 → next_fw 없음)
    dice::SimpleCert alias_cert2;
    dice::DiceLayer::process_layer_n(
        std::move(r1.next_cdi), FW_L2,
        r1.alias_sk, r1.alias_pk,
        alias_cert2);

    // 인증서 체인 구성: [DeviceID, Alias L0, Alias L1, Alias L2]
    chain.certs = {did_cert, alias_cert0, alias_cert1, alias_cert2};

    // 기대 FWID 배열: [FWID_L0, FWID_L1, FWID_L2]
    // certs[1].fwid ↔ fwids[0], certs[2].fwid ↔ fwids[1], ...
    for (auto fw : {std::span<const uint8_t>(FW_L0), std::span<const uint8_t>(FW_L1), std::span<const uint8_t>(FW_L2)}) {
        std::array<uint8_t, 32> fwid;
        sodium_crypto::sha256(fw.data(), fw.size());
        std::memcpy(fwid.data(), sodium_crypto::sha256::hash, 32);
        chain.fwids.push_back(fwid);
    }

    return chain;
}

// 정상 체인이 검증을 통과하는지 확인
TEST(ChainVerifier, ValidChainPasses)
{
    auto chain = build_chain();

    auto result = dice::ChainVerifier::verify_chain(chain.certs, chain.fwids);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.failed_layer, -1);
}

// 기대 FWID를 변조하면 해당 레이어에서 검증이 실패하는지 확인
// 시나리오: 검증자가 알고 있는 펌웨어 해시와 실제 인증서의 FWID가 다른 경우
// → 펌웨어가 변조되었음을 의미
TEST(ChainVerifier, TamperedFWIDFails)
{
    auto chain = build_chain();

    // Layer 1의 기대 FWID를 변조 (fwids[1] ↔ certs[2].fwid)
    chain.fwids[1][0] ^= 0xff;

    auto result = dice::ChainVerifier::verify_chain(chain.certs, chain.fwids);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failed_layer, 2);  // certs[2]에서 실패
}

// 인증서 서명을 직접 변조하면 검증이 실패하는지 확인
// 시나리오: 공격자가 인증서를 위조하여 체인에 삽입
TEST(ChainVerifier, BrokenSignatureFails)
{
    auto chain = build_chain();

    // Alias L1 인증서(certs[2])의 서명 1바이트 변조
    chain.certs[2].signature[0] ^= 0xff;

    auto result = dice::ChainVerifier::verify_chain(chain.certs, chain.fwids);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failed_layer, 2);
}

// issuer_pk 체인이 끊어진 경우 (중간 인증서의 issuer가 이전 subject와 불일치)
// 시나리오: 공격자가 다른 디바이스의 인증서를 섞어 넣은 경우
TEST(ChainVerifier, IssuerChainBrokenFails)
{
    auto chain = build_chain();

    // Alias L1 인증서(certs[2])의 issuer_pk를 임의 값으로 변경
    chain.certs[2].issuer_pk[0] ^= 0xff;

    auto result = dice::ChainVerifier::verify_chain(chain.certs, chain.fwids);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failed_layer, 2);
}

// DeviceID 인증서 하나만 있는 최소 체인도 검증 가능한지 확인
TEST(ChainVerifier, SingleCertChain)
{
    auto chain = build_chain();

    // DeviceID Cert만 남기기
    std::vector<dice::SimpleCert> single = {chain.certs[0]};
    std::vector<std::array<uint8_t, 32>> empty_fwids;

    auto result = dice::ChainVerifier::verify_chain(single, empty_fwids);
    EXPECT_TRUE(result.success);
}
