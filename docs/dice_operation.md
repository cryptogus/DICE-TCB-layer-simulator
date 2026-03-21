# DICE (Device Identifier Composition Engine) 동작 원리

TCG (Trusted Computing Group) DICE 아키텍처 기반의 디바이스 신뢰 부팅 메커니즘을 설명한다.

---

## 1. DICE란?

DICE는 **디바이스가 자신의 신원과 실행 중인 소프트웨어의 무결성을 암호학적으로 증명**하는 메커니즘이다.

핵심 아이디어: 하드웨어에 내장된 비밀(UDS)과 각 부트 레이어의 펌웨어 해시를 **단방향으로 결합**하여, 레이어마다 고유한 비밀(CDI)과 키 쌍을 유도한다. 이를 통해:

- 디바이스 고유 신원 증명 (Device Identity)
- 펌웨어 무결성 증명 (Firmware Attestation)
- 레이어 간 비밀 격리 (Secret Isolation)

를 동시에 달성한다.

### 1.1 TCG DICE 표준 문서

| 문서 | 내용 |
|------|------|
| **DICE Layering Architecture** | 레이어 구조, CDI 유도, 키 유도 규격 |
| **DICE Certificate Profiles** | X.509/CBOR 인증서 포맷 정의 |
| **DICE Attestation Architecture** | 원격 증명(Remote Attestation) 절차 |
| **DICE Protection Environment** | UDS 보호, 하드웨어 격리 요구사항 |

이 시뮬레이터는 **DICE Layering Architecture**의 핵심 흐름을 구현한다.

---

## 2. 전체 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    Hardware (제조 시)                         │
│  ┌─────────┐                                                │
│  │   UDS   │  Unique Device Secret (32B, fuse에 기록)       │
│  │  (fuse) │  디바이스마다 고유, 제조 후 변경 불가            │
│  └────┬────┘                                                │
│       │ (최초 1회만 읽기 가능)                                │
├───────┼─────────────────────────────────────────────────────┤
│       ▼                                                     │
│  ┌─────────────┐                                            │
│  │ DICE Engine  │  ROM 코드 (불변)                           │
│  │ (Layer -1)   │  UDS → CDI_L0 유도 후 UDS 영구 잠금        │
│  └──────┬──────┘                                            │
│         │ CDI_L0                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │  Layer 0    │  1차 부트로더                                │
│  │ (FBL)       │  DeviceID + Alias_L0 키 유도               │
│  └──────┬──────┘                                            │
│         │ CDI_L1                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │  Layer 1    │  2차 부트로더 / OS 커널                     │
│  │             │  Alias_L1 키 유도                           │
│  └──────┬──────┘                                            │
│         │ CDI_L2                                            │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │  Layer 2    │  애플리케이션                                │
│  │             │  Alias_L2 키 유도                           │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 핵심 개념 상세

### 3.1 UDS (Unique Device Secret)

```
크기: 32바이트 (256비트)
생성: 제조 시 하드웨어 fuse에 기록
보호: DICE Engine만 접근 가능, CDI 계산 후 하드웨어적 잠금
```

UDS는 DICE 신뢰 체인의 **신뢰 루트(Root of Trust)**이다.

- 디바이스마다 고유한 값 (공장에서 TRNG으로 생성)
- 제조 후 변경 불가 (one-time programmable fuse)
- DICE ROM 이외의 소프트웨어는 절대 접근 불가
- CDI 유도 후 하드웨어 래치(latch)로 영구 잠금

**시뮬레이터 구현:**
```
생성: libsodium randombytes_buf() (CSPRNG)
잠금: sodium_memzero() + uds_available 플래그
→ DiceEngine::compute_first_cdi() 호출 후 UDS 메모리 제로화
```

### 3.2 CDI (Compound Device Identifier)

```
크기: 32바이트
유도: CDI = HMAC-SHA256(key=이전비밀, msg=SHA256(현재펌웨어))
특성: 결정론적 — 같은 입력이면 항상 같은 CDI
```

CDI는 **이전 비밀과 현재 펌웨어의 결합**이다. "compound"라는 이름은 두 요소가 합성(composition)되었다는 의미.

```
CDI_L0 = HMAC-SHA256(UDS,    SHA256(fw_layer0))    ← UDS + Layer0 펌웨어
CDI_L1 = HMAC-SHA256(CDI_L0, SHA256(fw_layer1))    ← CDI_L0 + Layer1 펌웨어
CDI_L2 = HMAC-SHA256(CDI_L1, SHA256(fw_layer2))    ← CDI_L1 + Layer2 펌웨어
```

**핵심 속성:**
- **결정론적**: 같은 UDS + 같은 펌웨어 체인 → 항상 같은 CDI
- **눈사태 효과**: 펌웨어 1바이트만 변경 → 해당 CDI 이후 전부 변경
- **단방향**: CDI에서 UDS를 역산할 수 없음 (HMAC의 일방향성)
- **누적적**: CDI_L2는 Layer 0, 1, 2 펌웨어가 **모두** 올바를 때만 정상값

### 3.3 FWID (Firmware Identifier)

```
크기: 32바이트
계산: FWID = SHA-256(firmware_image)
용도: 인증서에 포함되어 펌웨어 무결성 증명
```

FWID는 특정 펌웨어 바이너리의 **디지털 지문**이다.

- 검증자는 "Layer 1에서 실행되어야 할 펌웨어의 FWID"를 알고 있음
- 인증서에 기록된 FWID와 비교하여 예상 펌웨어가 실행 중인지 확인
- 1비트만 달라도 FWID가 완전히 달라짐 (SHA-256 충돌 저항성)

---

## 4. 키 유도 과정 (HKDF)

CDI에서 서명 키를 유도할 때 **HKDF (HMAC-based Key Derivation Function, RFC 5869)**를 사용한다.

### 4.1 HKDF 2단계 구조

```
┌────────────────────────────────────────────────────┐
│  Stage 1: Extract (추출)                            │
│                                                    │
│  PRK = HMAC-SHA256(salt=0x00...00, ikm=CDI)        │
│                                                    │
│  - salt이 없으면 32바이트 0을 사용 (RFC 5869)        │
│  - CDI의 엔트로피를 균일하게 분산시키는 역할          │
│  - 출력: PRK (Pseudo-Random Key, 32바이트)           │
└───────────────────────┬────────────────────────────┘
                        │ PRK
                        ▼
┌────────────────────────────────────────────────────┐
│  Stage 2: Expand (확장)                             │
│                                                    │
│  seed = HKDF-Expand(PRK, info="DEVICEID_KEY", 32)  │
│  seed = HKDF-Expand(PRK, info="ALIAS_KEY", 32)     │
│                                                    │
│  - info 문자열이 다르면 독립적인 키가 나옴            │
│  - 같은 PRK에서 여러 용도의 키를 안전하게 파생        │
│  - 출력: 32바이트 시드 → Ed25519 키 쌍 생성에 사용    │
└────────────────────────────────────────────────────┘
```

### 4.2 Layer 0 키 유도 (DeviceID + Alias)

Layer 0만의 특징: **DeviceID 키**를 추가로 유도한다.

```
CDI_L0
  │
  ├──Extract──→ PRK
  │               │
  │               ├──Expand("DEVICEID_KEY")──→ seed ──→ Ed25519 키 쌍
  │               │                                      ├─ DeviceID SK (64B)
  │               │                                      └─ DeviceID PK (32B)
  │               │
  │               └──Expand("ALIAS_KEY")────→ seed ──→ Ed25519 키 쌍
  │                                                    ├─ Alias_L0 SK (64B)
  │                                                    └─ Alias_L0 PK (32B)
  │
  └──HMAC(CDI_L0, SHA256(fw_L1))──→ CDI_L1 (다음 레이어에 전달)
```

- **DeviceID**: 디바이스의 장기(long-term) 신원. UDS가 같으면 항상 같은 키.
- **Alias**: 레이어별 단기(ephemeral) 키. 펌웨어가 바뀌면 키도 바뀜.
- info 문자열만 다르고 같은 PRK를 사용하지만, HKDF의 설계에 의해 완전히 독립적인 키가 생성됨.

### 4.3 Layer N (N≥1) 키 유도 (Alias만)

```
CDI_Ln
  │
  ├──Extract──→ PRK
  │               │
  │               └──Expand("ALIAS_KEY")──→ seed ──→ Ed25519 키 쌍
  │                                                  ├─ Alias_Ln SK
  │                                                  └─ Alias_Ln PK
  │
  └──HMAC(CDI_Ln, SHA256(fw_Ln+1))──→ CDI_Ln+1 (다음 레이어에 전달)
      (마지막 레이어이면 생략)
```

Layer 1 이후에는 DeviceID 키를 생성하지 않는다. DeviceID는 디바이스 전체의 신원이므로 Layer 0에서 한 번만 생성.

---

## 5. 인증서 체인

### 5.1 인증서 구조 (SimpleCert)

```
┌─────────────────────────────────────────────┐
│              SimpleCert (160B)               │
├────────────────┬────────────────────────────┤
│  subject_pk    │  32B  주체의 Ed25519 PK     │
│  issuer_pk     │  32B  발행자의 Ed25519 PK   │
│  fwid          │  32B  펌웨어 SHA-256 해시    │
│  signature     │  64B  Ed25519 서명           │
├────────────────┴────────────────────────────┤
│  TBS (서명 대상) = subject_pk ‖ issuer_pk ‖ fwid  (96B)  │
│  signature = Ed25519_Sign(issuer_sk, TBS)               │
└─────────────────────────────────────────────┘
```

실제 DICE 표준에서는 X.509 또는 CBOR 기반 인증서를 사용하지만, 이 시뮬레이터에서는 핵심 필드만 포함한 간이 구조를 사용.

### 5.2 인증서 체인 구성

3-레이어 부트 체인의 인증서 4장:

```
┌──────────────────────────────────────────────────────────────────┐
│  [0] DeviceID Cert (자체 서명, 신뢰 루트)                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  subject_pk = DeviceID PK                                  │  │
│  │  issuer_pk  = DeviceID PK    ← 자기 자신 (self-signed)     │  │
│  │  fwid       = 0x00...00      ← 특정 레이어 아닌 장치 신원   │  │
│  │  signature  = Sign(DeviceID SK, TBS)                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         │  DeviceID SK로 서명                                     │
│         ▼                                                        │
│  [1] Alias L0 Cert                                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  subject_pk = Alias_L0 PK                                  │  │
│  │  issuer_pk  = DeviceID PK    ← DeviceID가 발행             │  │
│  │  fwid       = SHA256(fw_L0)  ← Layer 0 펌웨어 해시          │  │
│  │  signature  = Sign(DeviceID SK, TBS)                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         │  Alias_L0 SK로 서명                                     │
│         ▼                                                        │
│  [2] Alias L1 Cert                                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  subject_pk = Alias_L1 PK                                  │  │
│  │  issuer_pk  = Alias_L0 PK    ← Alias L0가 발행             │  │
│  │  fwid       = SHA256(fw_L1)  ← Layer 1 펌웨어 해시          │  │
│  │  signature  = Sign(Alias_L0 SK, TBS)                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│         │                                                        │
│         │  Alias_L1 SK로 서명                                     │
│         ▼                                                        │
│  [3] Alias L2 Cert                                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  subject_pk = Alias_L2 PK                                  │  │
│  │  issuer_pk  = Alias_L1 PK    ← Alias L1이 발행             │  │
│  │  fwid       = SHA256(fw_L2)  ← Layer 2 펌웨어 해시          │  │
│  │  signature  = Sign(Alias_L1 SK, TBS)                       │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.3 체인 연결 규칙

인증서 `certs[i]`와 `certs[i-1]` 사이의 관계:

```
certs[i].issuer_pk == certs[i-1].subject_pk
```

즉, **"나를 발행한 자의 공개키"가 "이전 인증서의 주체 공개키"와 일치**해야 한다.
이 연결이 끊어지면 체인이 변조된 것이다.

---

## 6. 부트 시 전체 동작 흐름

### 6.1 Phase 1: DICE Engine (UDS → CDI_L0)

```
입력: UDS (fuse), fw_L0 (Layer 0 펌웨어 이미지)
출력: CDI_L0

처리:
  ① FWID_L0 = SHA-256(fw_L0)
  ② CDI_L0  = HMAC-SHA256(key=UDS, msg=FWID_L0)
  ③ UDS 영구 잠금 (fuse latch / sodium_memzero)
```

이 단계 이후 UDS는 **어떤 소프트웨어도 접근할 수 없다.**

### 6.2 Phase 2: Layer 0 처리

```
입력: CDI_L0 (소유권 이전), fw_L0, fw_L1
출력: DeviceID Cert, Alias_L0 Cert, CDI_L1, Alias_L0 키

처리:
  ① CDI_L1 = HMAC(CDI_L0, SHA256(fw_L1))   ← CDI 파괴 전에 먼저!
  ② PRK = HKDF-Extract(salt=zeros, ikm=CDI_L0)
  ③ DeviceID seed = HKDF-Expand(PRK, "DEVICEID_KEY")
     → Ed25519 키 쌍 생성
  ④ Alias seed = HKDF-Expand(PRK, "ALIAS_KEY")
     → Ed25519 키 쌍 생성
  ⑤ DeviceID Cert 생성 (self-signed)
  ⑥ Alias_L0 Cert 생성 (DeviceID SK로 서명, FWID_L0 포함)
  ⑦ CDI_L0, PRK, 모든 seed 제로화
```

**중요**: ①에서 CDI_L1을 먼저 계산한 후 CDI_L0를 키 유도에 사용한다. CDI_L0가 파괴되면 다음 CDI를 계산할 수 없기 때문.

### 6.3 Phase 3: Layer 1 처리

```
입력: CDI_L1 (소유권 이전), fw_L1, Alias_L0 SK/PK, fw_L2
출력: Alias_L1 Cert, CDI_L2, Alias_L1 키

처리:
  ① CDI_L2 = HMAC(CDI_L1, SHA256(fw_L2))
  ② PRK = HKDF-Extract(salt=zeros, ikm=CDI_L1)
  ③ Alias_L1 seed = HKDF-Expand(PRK, "ALIAS_KEY")
     → Ed25519 키 쌍 생성
  ④ Alias_L1 Cert 생성 (Alias_L0 SK로 서명, FWID_L1 포함)
  ⑤ CDI_L1, PRK, seed 제로화
```

### 6.4 Phase 4: Layer 2 처리 (마지막 레이어)

```
입력: CDI_L2 (소유권 이전), fw_L2, Alias_L1 SK/PK
출력: Alias_L2 Cert, Alias_L2 키

처리:
  ① (다음 펌웨어 없음 → CDI_L3 계산 안 함)
  ② PRK = HKDF-Extract(salt=zeros, ikm=CDI_L2)
  ③ Alias_L2 seed = HKDF-Expand(PRK, "ALIAS_KEY")
     → Ed25519 키 쌍 생성
  ④ Alias_L2 Cert 생성 (Alias_L1 SK로 서명, FWID_L2 포함)
  ⑤ CDI_L2, PRK, seed 제로화
```

마지막 레이어의 Alias 키는 **외부 통신**(TLS 핸드셰이크, 원격 증명 등)에 사용될 수 있다.

---

## 7. 인증서 체인 검증

원격 검증자(Verifier)가 디바이스의 신뢰성을 확인하는 과정.

### 7.1 검증 흐름

```
검증자가 알고 있는 정보:
  - DeviceID PK (제조사로부터 사전 등록)
  - 각 레이어의 기대 FWID (펌웨어 빌드 시 공개된 해시)

검증 단계:
  [1] certs[0] (DeviceID Cert)
      ✓ self-signed인가? (subject_pk == issuer_pk)
      ✓ 서명이 유효한가? (DeviceID PK로 검증)

  [2] certs[1] (Alias L0 Cert)
      ✓ issuer_pk == certs[0].subject_pk 인가? (체인 연결)
      ✓ 서명이 유효한가?
      ✓ fwid == expected_fwid[0] 인가? (펌웨어 무결성)

  [3] certs[2] (Alias L1 Cert)
      ✓ issuer_pk == certs[1].subject_pk 인가?
      ✓ 서명이 유효한가?
      ✓ fwid == expected_fwid[1] 인가?

  [4] certs[3] (Alias L2 Cert)
      ✓ issuer_pk == certs[2].subject_pk 인가?
      ✓ 서명이 유효한가?
      ✓ fwid == expected_fwid[2] 인가?

  모두 통과 → 디바이스 신뢰 확인 ✓
```

### 7.2 검증 실패 케이스

| 실패 원인 | 탐지 위치 | 탐지 방법 |
|-----------|----------|----------|
| Layer 1 펌웨어 변조 | certs[2] | FWID 불일치 |
| 인증서 위조 | 해당 cert | 서명 검증 실패 |
| 체인 중간 인증서 삭제 | 해당 cert | issuer_pk 체인 단절 |
| 루트 인증서 교체 | certs[0] | DeviceID PK 불일치 (사전 등록값과 다름) |

---

## 8. 보안 속성

### 8.1 결정론적 유도 (Deterministic Derivation)

```
같은 UDS + 같은 fw_L0 + 같은 fw_L1 + 같은 fw_L2
= 항상 같은 CDI_L0, CDI_L1, CDI_L2
= 항상 같은 DeviceID, Alias_L0, Alias_L1, Alias_L2
= 항상 같은 인증서 체인
```

이 속성 덕분에 **키를 별도 저장할 필요 없이** 매 부팅마다 동일한 키를 재생성할 수 있다. 비휘발성 저장소에 비밀키를 저장하지 않으므로 물리적 공격 표면이 줄어든다.

### 8.2 눈사태 효과 (Avalanche Effect)

```
fw_L1이 1바이트 변경되면:

Layer 0: CDI_L0 동일, DeviceID 동일, Alias_L0 동일  ← 영향 없음
Layer 1: CDI_L1 변경 → Alias_L1 변경                ← 여기서부터 변경
Layer 2: CDI_L2 변경 → Alias_L2 변경                ← 전파
```

변경된 레이어 **이후**의 모든 CDI와 키가 완전히 달라진다.
변경된 레이어 **이전**은 영향을 받지 않는다.

### 8.3 레이어 격리 (Layer Isolation)

DICE의 핵심 보안 원칙: **상위 레이어는 하위 레이어의 비밀에 접근할 수 없다.**

```
Layer 0 실행 중:  UDS ✗ (잠금),  CDI_L0 ○ (소유)
Layer 1 실행 중:  UDS ✗,         CDI_L0 ✗ (파괴됨),  CDI_L1 ○
Layer 2 실행 중:  UDS ✗,         CDI_L0 ✗,           CDI_L1 ✗,  CDI_L2 ○
```

이를 통해:
- Layer 2에서 악성코드가 실행되더라도 Layer 0의 CDI/키를 알 수 없음
- 공격자가 상위 레이어를 장악해도 DeviceID를 위조할 수 없음

**시뮬레이터 구현:**
```
하드웨어 잠금 → SecureBuf 이동 의미론 + sodium_memzero
CDI를 std::move로 다음 레이어에 전달 → 원본 자동 제로화
```

### 8.4 단방향 신뢰 체인 (Unidirectional Trust)

```
DeviceID ──서명──→ Alias_L0 ──서명──→ Alias_L1 ──서명──→ Alias_L2
  (루트)                                                   (리프)
```

- 각 레이어는 **자신의 키로 다음 레이어를 인증**
- 역방향 인증은 불가: Layer 2가 Layer 0을 인증할 수 없음
- 루트 인증서의 신뢰는 **제조사 PKI** 또는 **DeviceID PK 사전 등록**에 의존

---

## 9. 사용되는 암호 알고리즘

| 알고리즘 | 용도 | 입력 | 출력 |
|---------|------|------|------|
| **SHA-256** | 펌웨어 해싱 (FWID 계산) | 가변 길이 데이터 | 32바이트 해시 |
| **HMAC-SHA256** | CDI 유도 (비밀 + 해시 결합) | key 32B + msg 32B | 32바이트 MAC |
| **HKDF-SHA256** | 키 유도 (CDI → 서명키 시드) | Extract + Expand | 32바이트 시드 |
| **Ed25519** | 디지털 서명 (인증서 서명/검증) | SK 64B, PK 32B | 서명 64B |

### 왜 이 조합인가?

- **HMAC-SHA256**: CDI 유도에 적합. 키가 있는 해시이므로 UDS 없이 CDI를 역산할 수 없음
- **HKDF**: 하나의 비밀(CDI)에서 여러 독립적인 키를 안전하게 파생. RFC 5869로 표준화
- **Ed25519**: 서명/검증이 빠르고, 키 크기가 작아 임베디드에 적합. 32바이트 시드에서 결정론적으로 키 쌍 생성 가능

---

## 10. 실제 하드웨어 vs 시뮬레이터

| 기능 | 실제 하드웨어 | 시뮬레이터 |
|------|-------------|-----------|
| UDS 저장 | OTP Fuse | `uint8_t[32]` 배열 |
| UDS 잠금 | 하드웨어 래치 (물리적 차단) | `sodium_memzero` + `uds_available` 플래그 |
| CDI 격리 | MPU/MMU 메모리 보호 | `SecureBuf` 이동 의미론 + 소멸자 제로화 |
| 키 유도 | 하드웨어 가속기 (선택) | libsodium 소프트웨어 구현 |
| 인증서 | X.509 / CBOR | `SimpleCert` (96B TBS + 64B 서명) |
| TRNG | 하드웨어 난수 생성기 | libsodium CSPRNG (`randombytes_buf`) |

---

## 11. 변조 탐지 시나리오

### 시나리오: Layer 1 펌웨어가 변조된 경우

```
정상 부팅:
  fw_L0 (정상) → CDI_L0 = A
  fw_L1 (정상) → CDI_L1 = B → Alias_L1 PK = X
  fw_L2 (정상) → CDI_L2 = C → Alias_L2 PK = Y

변조 부팅 (fw_L1'로 변경):
  fw_L0 (정상)  → CDI_L0 = A       ← 동일
  fw_L1'(변조)  → CDI_L1 = B'  ≠ B → Alias_L1 PK = X' ≠ X
  fw_L2 (정상)  → CDI_L2 = C'  ≠ C → Alias_L2 PK = Y' ≠ Y

검증자가 정상 인증서 체인의 FWID와 비교:
  certs[1].fwid == SHA256(fw_L0) ✓   (Layer 0은 변경 없음)
  certs[2].fwid == SHA256(fw_L1) ✗   (Layer 1 FWID 불일치!)
  → "인증서 2: FWID 불일치 (펌웨어 변조 의심)" 반환
```

Layer 1의 변조가 Layer 2 이후에 전파되지만, **검증은 최초 불일치 지점에서 실패**한다.

---

## 12. 용어 정리

| 용어 | 영문 | 설명 |
|------|------|------|
| UDS | Unique Device Secret | 디바이스 고유 비밀, 신뢰 루트 |
| CDI | Compound Device Identifier | 이전 비밀 + 현재 펌웨어의 합성 식별자 |
| FWID | Firmware Identifier | 펌웨어 이미지의 SHA-256 해시 |
| TCB | Trusted Computing Base | 신뢰할 수 있는 컴퓨팅 기반 (검증 대상) |
| TBS | To-Be-Signed | 서명의 대상이 되는 데이터 |
| PRK | Pseudo-Random Key | HKDF Extract의 출력, Expand의 입력 |
| DeviceID | Device Identity Key | 디바이스 장기 신원 키 (Layer 0에서만 유도) |
| Alias Key | - | 레이어별 단기 인증 키 |
| HKDF | HMAC-based KDF | RFC 5869, 키 유도 함수 |
| OTP Fuse | One-Time Programmable | 1회만 쓸 수 있는 하드웨어 퓨즈 |
