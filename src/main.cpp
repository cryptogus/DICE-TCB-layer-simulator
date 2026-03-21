#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <span>
#include <sodium.h>

#include "sha256.hpp"
#include "dice_engine.hpp"
#include "dice_layer.hpp"
#include "chain_verifier.hpp"

// ═══════════════════════════════════════════════════════════════
// DICE TCB 레이어 시뮬레이터 데모 프로그램
//
// 전체 부트 체인을 시뮬레이션하고, 각 단계의 중간값을 출력하여
// DICE의 동작 원리를 시각적으로 보여준다.
//
// 데모 시나리오:
//   1단계: UDS → CDI_L0 (최초 CDI 유도, UDS 파괴)
//   2단계: Layer 0 처리 (DeviceID + Alias L0 인증서 생성)
//   3단계: Layer 1 처리 (Alias L1 인증서 생성)
//   4단계: Layer 2 처리 (최종 레이어)
//   5단계: 인증서 체인 검증
//   6단계: 펌웨어 변조 탐지 시뮬레이션
//   7단계: 비밀값 파괴 검증
// ═══════════════════════════════════════════════════════════════

// ── 시뮬레이션용 상수 ──

// 결정론적 테스트를 위한 고정 UDS (32바이트)
// 실제 하드웨어에서는 제조 시 fuse에 기록되는 랜덤 비밀값
static const uint8_t TEST_UDS[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

// 3개 레이어 펌웨어 이미지 (실제로는 부트로더, 커널, 앱의 바이너리)
static const uint8_t FW_L0[] = "bootloader v1.0";
static const uint8_t FW_L1[] = "kernel v2.3";
static const uint8_t FW_L2[] = "app v1.1";

// 변조 탐지 시뮬레이션용 변조된 펌웨어
static const uint8_t FW_L1_TAMPERED[] = "kernel v2.3-BACKDOOR";

// ── 부트 과정 중간값 스냅샷 (비교 출력용) ──
// ※ 데모 목적으로만 CDI 값을 캡처함
//    실제 하드웨어에서는 CDI가 외부에 노출되지 않음
struct BootSnapshot {
    std::array<uint8_t, 32> cdi_l0;     // CDI_L0 (이동 전 복사)
    std::array<uint8_t, 32> cdi_l1;     // CDI_L1
    std::array<uint8_t, 32> cdi_l2;     // CDI_L2
    std::array<uint8_t, 32> did_pk;     // DeviceID 공개키
    std::array<uint8_t, 32> alias0_pk;  // Alias L0 공개키
    std::array<uint8_t, 32> alias1_pk;  // Alias L1 공개키
    std::array<uint8_t, 32> alias2_pk;  // Alias L2 공개키
};

// ── 유틸리티 함수 ──

// 바이트 배열을 16진수 문자열로 출력
static void print_hex(const char* label, const uint8_t* data, size_t len)
{
    std::printf("  %-18s: ", label);
    for (size_t i = 0; i < len; i++)
        std::printf("%02x", data[i]);
    std::printf("\n");
}

// SimpleCert의 모든 필드를 출력
static void print_cert(const char* name, const dice::SimpleCert& cert)
{
    std::printf("\n  [%s]\n", name);
    print_hex("subject_pk", cert.subject_pk, 32);
    print_hex("issuer_pk",  cert.issuer_pk,  32);
    print_hex("fwid",       cert.fwid,       32);
    print_hex("signature",  cert.signature,  64);
    std::printf("  %-18s: %s\n", "self-signed",
                cert.is_self_signed() ? "Yes (DeviceID)" : "No");
}

// 펌웨어의 FWID(SHA-256 해시) 계산
static std::array<uint8_t, 32> fwid_of(std::span<const uint8_t> fw)
{
    std::array<uint8_t, 32> fwid;
    sodium_crypto::sha256(fw.data(), fw.size());
    std::memcpy(fwid.data(), sodium_crypto::sha256::hash, 32);
    return fwid;
}

// 구분선 출력
static void print_separator(const char* title)
{
    std::printf("\n");
    std::printf("================================================================\n");
    std::printf("  %s\n", title);
    std::printf("================================================================\n\n");
}

// 바이트 배열이 전부 0인지 확인
static bool is_all_zero(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (data[i] != 0) return false;
    return true;
}

// ═══════════════════════════════════════════════════════════════
// 3레이어 DICE 부트 시뮬레이션 실행
//
// 전체 흐름:
//   UDS → CDI_L0 → Layer0(DeviceID+AliasL0+CDI_L1)
//                 → Layer1(AliasL1+CDI_L2)
//                 → Layer2(AliasL2)
//
// verbose=true이면 각 단계의 상세 정보를 콘솔에 출력
// ═══════════════════════════════════════════════════════════════
static void run_boot(
    std::span<const uint8_t> fw_l0,
    std::span<const uint8_t> fw_l1,
    std::span<const uint8_t> fw_l2,
    std::vector<dice::SimpleCert>& out_certs,
    BootSnapshot& snap,
    bool verbose)
{
    // ── 1단계: DiceEngine에서 첫 번째 CDI 유도 ──
    // UDS + SHA-256(firmware) → HMAC → CDI_L0
    // 이후 UDS는 영구 파괴 (하드웨어 fuse 잠금 시뮬레이션)

    if (verbose)
        print_separator("[1단계] DiceEngine: UDS -> CDI_L0");

    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(fw_l0);

    // CDI를 이동하기 전에 스냅샷 캡처 (데모용)
    std::memcpy(snap.cdi_l0.data(), cdi0.buf, 32);

    if (verbose) {
        print_hex("UDS", TEST_UDS, 32);
        std::printf("  %-18s: \"%s\"\n", "FW Layer 0",
                    reinterpret_cast<const char*>(fw_l0.data()));
        print_hex("FWID_L0", fwid_of(fw_l0).data(), 32);
        print_hex("CDI_L0", cdi0.buf, 32);
        std::printf("\n  * UDS 파괴 완료 (uds_available = %s)\n",
                    engine.uds_available ? "true" : "false");
        std::printf("  * UDS 메모리    : %s\n",
                    is_all_zero(engine.uds_bytes, 32) ? "전부 0 (제로화 확인)" : "잔존!");
    }

    // ── 2단계: Layer 0 처리 ──
    // CDI_L0에서 DeviceID 키와 Alias L0 키를 유도하고
    // 자체서명 DeviceID 인증서 + Alias L0 인증서 생성
    // 다음 레이어를 위한 CDI_L1도 계산

    if (verbose)
        print_separator("[2단계] Layer 0: CDI_L0 -> DeviceID + Alias L0 + CDI_L1");

    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), fw_l0, fw_l1, did_cert, alias_cert0);

    // 스냅샷 캡처
    std::memcpy(snap.cdi_l1.data(), r0.next_cdi.buf, 32);
    std::memcpy(snap.did_pk.data(), did_cert.subject_pk, 32);
    std::memcpy(snap.alias0_pk.data(), alias_cert0.subject_pk, 32);

    if (verbose) {
        print_cert("DeviceID Cert (자체 서명)", did_cert);
        print_cert("Alias L0 Cert (DeviceID SK로 서명)", alias_cert0);
        std::printf("\n");
        print_hex("CDI_L1", r0.next_cdi.buf, 32);
        std::printf("\n  * CDI_L0 이동 후 상태: valid=%s, 메모리=%s\n",
                    cdi0.valid ? "true" : "false",
                    is_all_zero(cdi0.buf, 32) ? "제로화 완료" : "잔존!");
    }

    // ── 3단계: Layer 1 처리 ──
    // CDI_L1에서 Alias L1 키를 유도하고
    // 이전 레이어(Alias L0)의 SK로 서명된 Alias L1 인증서 생성

    if (verbose)
        print_separator("[3단계] Layer 1: CDI_L1 -> Alias L1 + CDI_L2");

    dice::SimpleCert alias_cert1;
    dice::LayerResult r1 = dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), fw_l1,
        r0.alias_sk, r0.alias_pk,
        alias_cert1, fw_l2);

    // 스냅샷 캡처
    std::memcpy(snap.cdi_l2.data(), r1.next_cdi.buf, 32);
    std::memcpy(snap.alias1_pk.data(), alias_cert1.subject_pk, 32);

    if (verbose) {
        print_cert("Alias L1 Cert (Alias L0 SK로 서명)", alias_cert1);
        std::printf("\n");
        print_hex("CDI_L2", r1.next_cdi.buf, 32);
    }

    // ── 4단계: Layer 2 (최종 레이어) 처리 ──
    // 마지막 레이어이므로 다음 펌웨어 없음 → next_cdi는 비어있음

    if (verbose)
        print_separator("[4단계] Layer 2 (최종): CDI_L2 -> Alias L2");

    dice::SimpleCert alias_cert2;
    dice::DiceLayer::process_layer_n(
        std::move(r1.next_cdi), fw_l2,
        r1.alias_sk, r1.alias_pk,
        alias_cert2);

    // 스냅샷 캡처
    std::memcpy(snap.alias2_pk.data(), alias_cert2.subject_pk, 32);

    if (verbose) {
        print_cert("Alias L2 Cert (Alias L1 SK로 서명)", alias_cert2);
    }

    // 인증서 체인 수집
    out_certs = {did_cert, alias_cert0, alias_cert1, alias_cert2};
}

// ═══════════════════════════════════════════════════════════════
// 인증서 체인 검증
//
// 검증 과정:
//   1. 루트(DeviceID): 자체 서명 확인
//   2. 각 후속 인증서:
//      - issuer_pk == 이전 인증서의 subject_pk (체인 연결)
//      - Ed25519 서명 유효성
//      - FWID == SHA-256(해당 레이어 펌웨어) (변조 탐지)
// ═══════════════════════════════════════════════════════════════
static void verify_and_print(
    const std::vector<dice::SimpleCert>& certs,
    std::span<const uint8_t> fw_l0,
    std::span<const uint8_t> fw_l1,
    std::span<const uint8_t> fw_l2)
{
    print_separator("[5단계] 인증서 체인 검증");

    std::printf("  체인 구조:\n");
    std::printf("    DeviceID Cert (자체 서명, 루트)\n");
    std::printf("      +-- Alias L0 Cert (DeviceID가 서명, FWID_L0)\n");
    std::printf("           +-- Alias L1 Cert (Alias L0가 서명, FWID_L1)\n");
    std::printf("                +-- Alias L2 Cert (Alias L1이 서명, FWID_L2)\n");
    std::printf("\n  검증 시작...\n\n");

    // 개별 인증서 수동 검증 (교육 목적)
    const char* cert_names[] = {
        "DeviceID Cert", "Alias L0 Cert", "Alias L1 Cert", "Alias L2 Cert"
    };

    for (size_t i = 0; i < certs.size(); i++) {
        const auto& cert = certs[i];
        bool sig_ok = cert.verify();

        if (i == 0) {
            // 루트 인증서: 자체 서명 확인
            std::printf("  [%zu] %s: 자체서명=%s, 서명=%s\n",
                        i, cert_names[i],
                        cert.is_self_signed() ? "O" : "X",
                        sig_ok ? "유효" : "무효");
        } else {
            // 후속 인증서: 체인 연결 + 서명 확인
            bool chain_ok = (std::memcmp(cert.issuer_pk,
                                         certs[i-1].subject_pk, 32) == 0);
            std::printf("  [%zu] %s: 체인연결=%s, 서명=%s\n",
                        i, cert_names[i],
                        chain_ok ? "O" : "X",
                        sig_ok ? "유효" : "무효");
        }
    }

    // ChainVerifier로 전체 검증
    std::vector<std::array<uint8_t, 32>> expected_fwids = {
        fwid_of(fw_l0), fwid_of(fw_l1), fwid_of(fw_l2)
    };

    auto result = dice::ChainVerifier::verify_chain(certs, expected_fwids);
    std::printf("\n  >>> 체인 검증 결과: %s <<<\n",
                result.success ? "성공" : "실패");
    if (!result.success) {
        std::printf("  >>> 실패 위치: 인증서 %d\n", result.failed_layer);
        std::printf("  >>> 사유: %s\n", result.reason.c_str());
    }
}

// ═══════════════════════════════════════════════════════════════
// 변조 탐지 시뮬레이션
//
// 시나리오: Layer 1 펌웨어(커널)가 변조됨
//   - Layer 0은 동일 → CDI_L0, DeviceID, Alias L0 동일
//   - Layer 1부터 다름 → CDI_L1, Alias L1 이후 전부 변경
//   - 원본 FWID로 검증하면 Layer 1에서 불일치 탐지
// ═══════════════════════════════════════════════════════════════
static void run_tamper_demo(const BootSnapshot& normal_snap)
{
    print_separator("[6단계] 변조 탐지 시뮬레이션");

    std::printf("  시나리오: Layer 1 펌웨어(커널)가 변조됨\n");
    std::printf("    원본: \"%s\"\n", reinterpret_cast<const char*>(FW_L1));
    std::printf("    변조: \"%s\"\n\n", reinterpret_cast<const char*>(FW_L1_TAMPERED));

    // 변조된 펌웨어로 부트 체인 재구성
    std::vector<dice::SimpleCert> tampered_certs;
    BootSnapshot tampered_snap;
    run_boot(FW_L0, FW_L1_TAMPERED, FW_L2,
             tampered_certs, tampered_snap, false);

    // ── 정상 vs 변조 비교 출력 ──
    std::printf("  --- 정상 vs 변조 비교 ---\n\n");

    // CDI_L0 비교 (동일해야 함)
    bool cdi0_same = (std::memcmp(normal_snap.cdi_l0.data(),
                                   tampered_snap.cdi_l0.data(), 32) == 0);
    std::printf("  CDI_L0     : %s (Layer 0 FW 동일)\n",
                cdi0_same ? "[동일]" : "[다름!]");

    // DeviceID PK 비교
    bool did_same = (std::memcmp(normal_snap.did_pk.data(),
                                  tampered_snap.did_pk.data(), 32) == 0);
    std::printf("  DeviceID PK: %s\n", did_same ? "[동일]" : "[다름!]");

    // Alias L0 PK 비교
    bool a0_same = (std::memcmp(normal_snap.alias0_pk.data(),
                                 tampered_snap.alias0_pk.data(), 32) == 0);
    std::printf("  Alias L0 PK: %s\n", a0_same ? "[동일]" : "[다름!]");

    // CDI_L1 비교 (달라야 함)
    bool cdi1_same = (std::memcmp(normal_snap.cdi_l1.data(),
                                   tampered_snap.cdi_l1.data(), 32) == 0);
    std::printf("  CDI_L1     : %s (Layer 1 FW 변조됨)\n",
                cdi1_same ? "[동일]" : "[다름!]");
    if (!cdi1_same) {
        print_hex("  원본", normal_snap.cdi_l1.data(), 32);
        print_hex("  변조", tampered_snap.cdi_l1.data(), 32);
    }

    // Alias L1 PK 비교
    bool a1_same = (std::memcmp(normal_snap.alias1_pk.data(),
                                 tampered_snap.alias1_pk.data(), 32) == 0);
    std::printf("  Alias L1 PK: %s\n", a1_same ? "[동일]" : "[다름!]");

    // Alias L2 PK 비교
    bool a2_same = (std::memcmp(normal_snap.alias2_pk.data(),
                                 tampered_snap.alias2_pk.data(), 32) == 0);
    std::printf("  Alias L2 PK: %s\n", a2_same ? "[동일]" : "[다름!]");

    // ── 변조 체인을 원본 FWID로 검증 ──
    std::printf("\n  변조 체인에 대해 원본 FWID로 검증 시도...\n");

    std::vector<std::array<uint8_t, 32>> original_fwids = {
        fwid_of(FW_L0), fwid_of(FW_L1), fwid_of(FW_L2)
    };

    auto result = dice::ChainVerifier::verify_chain(tampered_certs, original_fwids);
    std::printf("\n  >>> 체인 검증 결과: %s <<<\n",
                result.success ? "성공" : "실패");
    if (!result.success) {
        std::printf("  >>> 실패 위치: 인증서 %d\n", result.failed_layer);
        std::printf("  >>> 사유: %s\n", result.reason.c_str());
    }

    // ── 결론 ──
    std::printf("\n  -- 결론 --\n");
    std::printf("  펌웨어가 1바이트라도 변조되면:\n");
    std::printf("    1. 해당 레이어의 FWID가 달라짐\n");
    std::printf("    2. CDI가 달라져 이후 모든 키가 변경됨\n");
    std::printf("    3. 인증서 체인 검증에서 즉시 탐지됨\n");
}

// ═══════════════════════════════════════════════════════════════
// 비밀값 파괴 검증
//
// DICE 보안 모델의 핵심:
//   - UDS는 CDI 계산 후 즉시 파괴
//   - CDI는 키 유도 후 다음 레이어에 이전되며 원본 파괴
//   - cold boot 공격 등으로 메모리를 덤프해도 비밀이 남아있지 않아야 함
// ═══════════════════════════════════════════════════════════════
static void verify_secret_destruction()
{
    print_separator("[7단계] 비밀값 파괴 검증");

    std::printf("  DICE 보안 모델: 사용이 끝난 비밀은 반드시 메모리에서 제거\n\n");

    // DiceEngine 생성 → CDI 계산 → UDS 파괴 확인
    dice::DiceEngine engine(TEST_UDS);
    dice::Cdi cdi0 = engine.compute_first_cdi(FW_L0);

    std::printf("  [UDS 파괴 확인]\n");
    std::printf("  %-20s: %s\n", "engine.uds_available",
                engine.uds_available ? "true (접근 가능)" : "false (접근 차단)");
    std::printf("  %-20s: %s\n", "engine.uds_bytes",
                is_all_zero(engine.uds_bytes, 32) ? "전부 0 (제로화 완료)" : "잔존!");

    // CDI 이동 → 원본 파괴 확인
    dice::SimpleCert did_cert, alias_cert0;
    dice::LayerResult r0 = dice::DiceLayer::process_layer0(
        std::move(cdi0), FW_L0, FW_L1, did_cert, alias_cert0);

    std::printf("\n  [CDI_L0 파괴 확인 (std::move 후)]\n");
    std::printf("  %-20s: %s\n", "cdi0.valid",
                cdi0.valid ? "true" : "false (무효)");
    std::printf("  %-20s: %s\n", "cdi0.buf",
                is_all_zero(cdi0.buf, 32) ? "전부 0 (제로화 완료)" : "잔존!");

    // Layer 1 처리 → CDI_L1 파괴 확인
    dice::SimpleCert alias_cert1;
    dice::LayerResult r1 = dice::DiceLayer::process_layer_n(
        std::move(r0.next_cdi), FW_L1,
        r0.alias_sk, r0.alias_pk,
        alias_cert1, FW_L2);

    std::printf("\n  [CDI_L1 파괴 확인 (std::move 후)]\n");
    std::printf("  %-20s: %s\n", "r0.next_cdi.valid",
                r0.next_cdi.valid ? "true" : "false (무효)");
    std::printf("  %-20s: %s\n", "r0.next_cdi.buf",
                is_all_zero(r0.next_cdi.buf, 32)
                    ? "전부 0 (제로화 완료)" : "잔존!");

    std::printf("\n  * 실제 하드웨어에서는:\n");
    std::printf("    - UDS: fuse 잠금으로 물리적 접근 차단\n");
    std::printf("    - CDI: MPU/MMU로 메모리 영역 접근 제한\n");
    std::printf("    - 이 시뮬레이터: sodium_memzero + move semantics로 모사\n");
}

// ═══════════════════════════════════════════════════════════════
// 메인 함수
// ═══════════════════════════════════════════════════════════════
int main()
{
    // libsodium 초기화 (모든 암호 연산 전에 반드시 호출)
    if (sodium_init() < 0) {
        std::fprintf(stderr, "오류: libsodium 초기화 실패\n");
        return 1;
    }

    std::printf("\n");
    std::printf("================================================================\n");
    std::printf("     DICE TCB 레이어 시뮬레이터 데모\n");
    std::printf("     UDS -> CDI -> 키 유도 -> 인증서 체인 -> 검증\n");
    std::printf("================================================================\n");

    // ── 정상 부트 시뮬레이션 (1~4단계) ──
    std::vector<dice::SimpleCert> normal_certs;
    BootSnapshot normal_snap;
    run_boot(FW_L0, FW_L1, FW_L2,
             normal_certs, normal_snap, true);

    // ── 인증서 체인 검증 (5단계) ──
    verify_and_print(normal_certs, FW_L0, FW_L1, FW_L2);

    // ── 변조 탐지 시뮬레이션 (6단계) ──
    run_tamper_demo(normal_snap);

    // ── 비밀값 파괴 검증 (7단계) ──
    verify_secret_destruction();

    std::printf("\n================================================================\n");
    std::printf("  데모 완료\n");
    std::printf("================================================================\n\n");

    return 0;
}
