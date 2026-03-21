#include <gtest/gtest.h>
#include <cstring>
#include "dice_engine.hpp"
#include "dice_layer.hpp"

// 테스트에서 공통으로 사용할 고정값
static const uint8_t FIXED_UDS[32] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x17, 0x28,
    0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0
};
static const uint8_t FW_L0[] = "bootloader v1.0";
static const uint8_t FW_L1[] = "kernel v2.3";
static const uint8_t FW_L2[] = "app v1.1";

// CDI 체이닝: UDS → CDI_L0 → CDI_L1 → CDI_L2
// 각 CDI가 서로 다른 값인지 확인
// 같은 CDI가 나오면 레이어 간 격리가 되지 않음
TEST(DiceLayer, CDIChaining)
{
    dice::DiceEngine engine(FIXED_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);
    EXPECT_TRUE(cdi0.valid);

    // CDI_L0 → CDI_L1
    dice::Cdi cdi1 = dice::DiceLayer::compute_next_cdi(cdi0, FW_L1);
    EXPECT_TRUE(cdi1.valid);

    // CDI_L1 → CDI_L2
    dice::Cdi cdi2 = dice::DiceLayer::compute_next_cdi(cdi1, FW_L2);
    EXPECT_TRUE(cdi2.valid);

    // 모든 CDI가 서로 달라야 함
    EXPECT_NE(memcmp(cdi0.buf, cdi1.buf, 32), 0);
    EXPECT_NE(memcmp(cdi1.buf, cdi2.buf, 32), 0);
    EXPECT_NE(memcmp(cdi0.buf, cdi2.buf, 32), 0);
}

// 동일한 CDI로부터 항상 같은 키가 유도되는지 확인 (결정론적)
// DICE의 핵심: 부팅마다 동일한 키가 재생성되어야 원격 검증자가 신뢰 가능
TEST(DiceLayer, DeterministicKeyDerivation)
{
    // 같은 UDS + 같은 FW로 CDI 두 번 생성
    dice::DiceEngine engine1(FIXED_UDS);
    dice::Cdi cdi1 = engine1.compute_first_cdi(FW_L0);

    dice::DiceEngine engine2(FIXED_UDS);
    dice::Cdi cdi2 = engine2.compute_first_cdi(FW_L0);

    // 각각 Layer 0 처리
    dice::SimpleCert did_cert1, alias_cert1;
    dice::LayerResult r1 = dice::DiceLayer::process_layer0(
        std::move(cdi1), FW_L0, FW_L1, did_cert1, alias_cert1);

    dice::SimpleCert did_cert2, alias_cert2;
    dice::LayerResult r2 = dice::DiceLayer::process_layer0(
        std::move(cdi2), FW_L0, FW_L1, did_cert2, alias_cert2);

    // DeviceID 공개키가 동일해야 함
    EXPECT_EQ(memcmp(did_cert1.subject_pk, did_cert2.subject_pk, 32), 0);

    // Alias 공개키가 동일해야 함
    EXPECT_EQ(memcmp(r1.alias_pk, r2.alias_pk, 32), 0);

    // 인증서 서명도 동일해야 함 (결정론적 Ed25519)
    EXPECT_EQ(memcmp(alias_cert1.signature, alias_cert2.signature, 64), 0);
}

// Layer 0에서 생성된 인증서들이 검증을 통과하는지 확인
TEST(DiceLayer, Layer0CertsVerify)
{
    dice::DiceEngine engine(FIXED_UDS);
    dice::Cdi cdi = engine.compute_first_cdi(FW_L0);

    dice::SimpleCert did_cert, alias_cert;
    dice::LayerResult r = dice::DiceLayer::process_layer0(
        std::move(cdi), FW_L0, FW_L1, did_cert, alias_cert);

    // DeviceID 인증서: 자체 서명
    EXPECT_TRUE(did_cert.verify());
    EXPECT_TRUE(did_cert.is_self_signed());

    // Alias L0 인증서: DeviceID SK로 서명
    EXPECT_TRUE(alias_cert.verify());
    EXPECT_FALSE(alias_cert.is_self_signed());

    // Alias 인증서의 issuer_pk == DeviceID 인증서의 subject_pk
    EXPECT_EQ(memcmp(alias_cert.issuer_pk, did_cert.subject_pk, 32), 0);
}

// Layer N 처리 후 생성된 인증서가 이전 레이어의 키로 검증되는지 확인
TEST(DiceLayer, LayerNCertVerifies)
{
    dice::DiceEngine engine(FIXED_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);

    // Layer 0 처리
    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), FW_L0, FW_L1, did_cert, alias_cert0);

    // Layer 1 처리: r0의 Alias SK로 서명
    dice::SimpleCert alias_cert1;
    dice::LayerResult r1 = dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), FW_L1,
        r0.alias_sk, r0.alias_pk,
        alias_cert1, FW_L2);

    // Alias L1 인증서 검증
    EXPECT_TRUE(alias_cert1.verify());

    // Alias L1의 issuer_pk == Alias L0의 subject_pk (체인 연결)
    EXPECT_EQ(memcmp(alias_cert1.issuer_pk, alias_cert0.subject_pk, 32), 0);

    // FWID가 올바른지 확인
    uint8_t expected_fwid[32];
    dice::DiceLayer::compute_fwid(expected_fwid, FW_L1);
    EXPECT_EQ(memcmp(alias_cert1.fwid, expected_fwid, 32), 0);
}

// 펌웨어 변경 시 해당 레이어 이후의 CDI가 전부 달라지는지 확인
// Layer 1 펌웨어만 변경하면 CDI_L1부터 달라지고, CDI_L0은 동일해야 함
TEST(DiceLayer, FirmwareChangeBreaksChain)
{
    const uint8_t fw_l1_good[] = "kernel v2.3";
    const uint8_t fw_l1_bad[]  = "kernel v2.4";  // 변조된 펌웨어

    // 정상 체인
    dice::DiceEngine eng1(FIXED_UDS);
    dice::Cdi cdi0_good = eng1.compute_first_cdi(FW_L0);
    dice::Cdi cdi1_good = dice::DiceLayer::compute_next_cdi(cdi0_good, fw_l1_good);

    // 변조된 체인
    dice::DiceEngine eng2(FIXED_UDS);
    dice::Cdi cdi0_bad = eng2.compute_first_cdi(FW_L0);
    dice::Cdi cdi1_bad = dice::DiceLayer::compute_next_cdi(cdi0_bad, fw_l1_bad);

    // CDI_L0은 동일 (Layer 0 펌웨어는 같으니까)
    EXPECT_EQ(memcmp(cdi0_good.buf, cdi0_bad.buf, 32), 0);

    // CDI_L1은 달라야 함 (Layer 1 펌웨어가 다르니까)
    EXPECT_NE(memcmp(cdi1_good.buf, cdi1_bad.buf, 32), 0);
}
