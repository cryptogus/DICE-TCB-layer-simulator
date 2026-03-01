# DICE 시뮬레이터 — 구현 순서 & 핵심 개념

## DICE가 하는 일 (한 줄 요약)

디바이스 고유 비밀(UDS)과 펌웨어 이미지를 결합해서, 각 부트 레이어마다 고유한 신원(키 + 인증서)을 만들어내는 것.

---

## 핵심 개념

### UDS (Unique Device Secret)
- 디바이스마다 다른 32바이트 비밀값
- 실제로는 제조 시 하드웨어에 fuse로 기록됨
- DICE 엔진만 읽을 수 있고, 첫 번째 CDI를 유도한 뒤 즉시 접근 차단됨
- 시뮬레이터에서는 `randombytes_buf`로 생성하고, 사용 후 `sodium_memzero`

### CDI (Compound Device Identifier)
- 각 레이어의 고유 비밀값
- **이전 비밀 + 현재 펌웨어 해시**를 HMAC으로 결합하여 유도
- 같은 UDS + 같은 펌웨어 → 항상 같은 CDI (결정론적)
- 펌웨어 1바이트만 바뀌어도 CDI가 완전히 달라짐

```
CDI_L0 = HMAC(UDS,    SHA256(fw_layer0))
CDI_L1 = HMAC(CDI_L0, SHA256(fw_layer1))
CDI_L2 = HMAC(CDI_L1, SHA256(fw_layer2))
```

### FWID (Firmware Identifier)
- 각 레이어 펌웨어 이미지의 SHA-256 해시
- 인증서에 포함되어 "이 레이어에서 어떤 펌웨어가 돌아가는지" 증명
- 검증자가 기대하는 FWID와 비교하여 변조 여부 판단

### DeviceID Key
- CDI로부터 HKDF로 유도한 장기 키 쌍 (Ed25519)
- 디바이스의 고유 신원을 대표
- 보통 Layer 0에서만 생성

### Alias Key
- CDI로부터 HKDF로 유도한 단기 키 쌍
- 다음 레이어를 인증(서명)하는 데 사용
- 펌웨어가 바뀌면 CDI가 바뀌고 → Alias Key도 바뀜
- 각 레이어마다 하나씩 생성

### 인증서 체인
```
DeviceID Cert  ← 자체 서명 (또는 제조사 Root CA 서명)
  └─ Alias L0 Cert  ← DeviceID SK로 서명, FWID_L0 포함
       └─ Alias L1 Cert  ← Alias L0 SK로 서명, FWID_L1 포함
            └─ ...
```
- 검증자는 루트부터 순서대로 서명을 검증
- 각 인증서의 FWID가 기대값과 일치하는지 확인
- 하나라도 불일치 → 변조 탐지

### 레이어 격리
- 각 레이어는 CDI를 사용한 뒤 이전 레이어의 비밀을 파괴
- 실제 HW: MPU/MMU로 접근 차단
- 시뮬레이터: `sodium_memzero`로 제거 + move semantics로 소유권 이전

---

## 구현 순서

### 1단계: 크립토 래퍼 클래스
- libsodium API를 감싸는 template 클래스
- `HashAlgo`, `SignAlgo` 등을 template parameter로 받도록 설계
- 당장은 SHA256 + Ed25519 하나만 구현하되, 구조만 교체 가능하게

### 2단계: UDS → CDI 유도
- UDS 생성 (randombytes_buf)
- 가짜 펌웨어 파일 또는 문자열을 SHA-256 해싱
- `CDI = HMAC(UDS, Hash(fw))` 계산
- UDS 제로화
- 테스트: 같은 입력 → 같은 CDI, 다른 입력 → 다른 CDI

### 3단계: 멀티 레이어 체이닝
- 3~4개 레이어로 CDI 체이닝
- 각 레이어에서 이전 CDI 제로화
- DiceLayer 클래스로 추상화: 입력(이전 CDI + fw) → 출력(현재 CDI)

### 4단계: CDI → 키 유도
- HKDF-Extract(salt=zero, ikm=CDI) → PRK
- HKDF-Expand(PRK, "DEVICEID_KEY") → DeviceID seed → keypair
- HKDF-Expand(PRK, "ALIAS_KEY_LN") → Alias seed → keypair
- seed 사용 후 즉시 제로화

### 5단계: 인증서 체인 생성
- 간이 인증서 구조체 정의 (X.509 전체 구현 불필요)
  - subject_pk (32B)
  - issuer_pk (32B)
  - fwid (32B)
  - signature (64B)
- DeviceID Cert: 자체 서명
- Alias LN Cert: 이전 레이어 SK로 서명, 해당 레이어 FWID 포함

### 6단계: 체인 검증
- 루트(DeviceID Cert)부터 순서대로 서명 검증
- 각 인증서의 FWID가 기대하는 펌웨어 해시와 일치하는지 확인
- 전부 통과 → 인증 성공

### 7단계: 변조 탐지 테스트
- 특정 레이어 펌웨어를 변경
- CDI가 달라지고 → 키가 달라지고 → 인증서 체인 검증 실패
- 어느 레이어에서 실패하는지 출력

---

## 클래스 구조 (참고)

```
DiceEngine
  - UDS 보유
  - computeFirstCDI(fw_image) → CDI
  - 호출 후 UDS 파괴

DiceLayer
  - CDI 입력 → DeviceID/Alias 키 유도
  - 인증서 생성 (이전 레이어 SK로 서명)
  - 다음 레이어 CDI 계산
  - 호출 후 현재 CDI 파괴

SimpleCert
  - subject_pk, issuer_pk, fwid, signature
  - sign(issuer_sk) / verify(issuer_pk) 메서드

ChainVerifier
  - 인증서 배열 + 기대 FWID 배열 입력
  - 루트부터 순서대로 검증
  - 실패 시 어느 레이어에서 실패했는지 반환
```

---

## 키 포인트 체크리스트

- [ ] 같은 UDS + 같은 FW → 항상 같은 CDI/키 (결정론적 유도)
- [ ] FW 1바이트 변경 → 해당 레이어 이후 CDI 전부 변경
- [ ] 이전 레이어 비밀은 다음 레이어 진입 시 반드시 파괴
- [ ] 인증서 체인: 루트 → 리프 순서로 서명 검증 가능
- [ ] 변조 시나리오에서 체인 검증이 실패하는지 확인
