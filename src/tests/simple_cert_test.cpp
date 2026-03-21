#include <gtest/gtest.h>
#include <cstring>
#include "simple_cert.hpp"

// 인증서를 생성하고 서명한 뒤, 같은 issuer_pk로 검증이 통과하는지 확인
TEST(SimpleCert, SignAndVerify)
{
    // 임의의 키 쌍 생성
    sodium_crypto::ed25519 issuer;
    sodium_crypto::ed25519 subject;

    // 인증서 필드 설정
    dice::SimpleCert cert;
    std::memcpy(cert.subject_pk, subject.pk, 32);
    std::memcpy(cert.issuer_pk,  issuer.pk,  32);
    // 테스트용 FWID (실제로는 SHA-256 해시)
    std::memset(cert.fwid, 0xab, 32);

    // 서명 생성 및 검증
    cert.sign(issuer.sk);
    EXPECT_TRUE(cert.verify());
}

// subject_pk가 변조되면 TBS가 달라져 서명 검증이 실패하는지 확인
// 공격자가 인증서의 공개키를 자기 키로 교체하는 시나리오
TEST(SimpleCert, TamperedSubjectPKFails)
{
    sodium_crypto::ed25519 issuer;
    sodium_crypto::ed25519 subject;

    dice::SimpleCert cert;
    std::memcpy(cert.subject_pk, subject.pk, 32);
    std::memcpy(cert.issuer_pk,  issuer.pk,  32);
    std::memset(cert.fwid, 0xcd, 32);
    cert.sign(issuer.sk);

    // subject_pk 1바이트 변조
    cert.subject_pk[0] ^= 0xff;

    // TBS가 달라졌으므로 서명 검증 실패
    EXPECT_FALSE(cert.verify());
}

// FWID가 변조되면 검증이 실패하는지 확인
// 공격자가 펌웨어를 교체한 뒤 인증서의 FWID를 조작하는 시나리오
TEST(SimpleCert, TamperedFWIDFails)
{
    sodium_crypto::ed25519 issuer;
    sodium_crypto::ed25519 subject;

    dice::SimpleCert cert;
    std::memcpy(cert.subject_pk, subject.pk, 32);
    std::memcpy(cert.issuer_pk,  issuer.pk,  32);
    std::memset(cert.fwid, 0xef, 32);
    cert.sign(issuer.sk);

    // FWID 1바이트 변조
    cert.fwid[15] ^= 0x01;

    EXPECT_FALSE(cert.verify());
}

// 발행자가 아닌 다른 키로 서명한 인증서는 검증에 실패해야 함
// issuer_pk에는 A의 공개키가 기록되어 있지만, 실제 서명은 B의 비밀키로 한 경우
TEST(SimpleCert, WrongIssuerKeyFails)
{
    sodium_crypto::ed25519 real_issuer;
    sodium_crypto::ed25519 fake_issuer;
    sodium_crypto::ed25519 subject;

    dice::SimpleCert cert;
    std::memcpy(cert.subject_pk, subject.pk, 32);
    std::memcpy(cert.issuer_pk,  real_issuer.pk, 32);  // 기록은 real_issuer
    std::memset(cert.fwid, 0x11, 32);

    // 실제 서명은 fake_issuer로 수행 (위조 시도)
    cert.sign(fake_issuer.sk);

    // issuer_pk(real)와 실제 서명자(fake)가 다르므로 검증 실패
    EXPECT_FALSE(cert.verify());
}

// 자체 서명 인증서 (DeviceID Cert) 생성 및 검증
// subject_pk == issuer_pk이고, 자기 자신의 SK로 서명
TEST(SimpleCert, SelfSignedCert)
{
    sodium_crypto::ed25519 device_id;

    dice::SimpleCert cert;
    std::memcpy(cert.subject_pk, device_id.pk, 32);
    std::memcpy(cert.issuer_pk,  device_id.pk, 32);  // 자체 서명
    std::memset(cert.fwid, 0x00, 32);

    cert.sign(device_id.sk);

    EXPECT_TRUE(cert.verify());
    EXPECT_TRUE(cert.is_self_signed());
}
