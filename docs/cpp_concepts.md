# C++ 핵심 개념 정리

DICE 시뮬레이터 구현 과정에서 다룬 C++ 개념들을 정리한 문서.

---

## 1. std::span (C++20)

배열이나 벡터 등 **연속된 메모리 영역을 가리키는 비소유(non-owning) 뷰**.

```cpp
#include <span>

void print_bytes(std::span<const uint8_t> data) {
    for (auto b : data) std::cout << (int)b << " ";
}

uint8_t arr[4] = {1, 2, 3, 4};
std::vector<uint8_t> vec = {5, 6, 7};

print_bytes(arr);   // C 배열 OK
print_bytes(vec);   // std::vector OK
```

### 특징
- 데이터를 **복사하지 않음** (포인터 + 길이만 저장)
- C 배열, `std::array`, `std::vector` 등을 하나의 타입으로 받을 수 있음
- `data()`로 포인터, `size()`로 길이 접근

### 고정 크기 배열 참조와의 비교

```cpp
// 고정 크기: 배열 참조가 적합
void use_key(const uint8_t (&key)[32]);

// 가변 크기: std::span이 적합
void use_data(std::span<const uint8_t> data);
```

고정 크기 배열 참조(`uint8_t (&key)[32]`)는 정확히 32바이트만 받으므로 컴파일 타임에 크기를 보장한다. 가변 길이 데이터에는 `std::span`을 사용한다.

---

## 2. lvalue와 rvalue

| | lvalue | rvalue |
|---|--------|--------|
| 뜻 | **이름이 있는** 값 | **이름이 없는** 임시 값 |
| 주소 | `&a` 가능 | 불가능 |
| 수명 | 스코프 끝까지 유지 | 그 줄이 끝나면 사라짐 |

```cpp
SecureBuf a;          // a는 lvalue (이름 있음)
SecureBuf();          // rvalue (이름 없는 임시 객체)
```

이름의 유래는 대입문 기준:

```cpp
a = b + c;
// a     → left value  (= 왼쪽, 결과를 저장할 곳)
// b + c → right value (= 오른쪽, 임시 계산 결과)
```

---

## 3. 참조: `&` vs `&&`

### lvalue reference (`&`)

```cpp
void foo(SecureBuf& other);   // 이름 있는 객체만 받음
```

- 기존 객체를 **빌려 쓰는** 것
- 원본을 훼손하면 안 된다는 암묵적 약속

### rvalue reference (`&&`)

```cpp
void foo(SecureBuf&& other);  // 임시 객체 또는 std::move()된 객체만 받음
```

- 원본을 **훼손해도 된다는 약속**이 있는 참조
- 실제 메모리 수준에서는 `&`와 동일 (둘 다 내부적으로 주소 전달)

### 핵심 차이

`&`와 `&&` 모두 참조(별명)이다. 런타임에 차이는 없다. 차이는 **컴파일 타임에 어떤 오버로드를 선택하느냐**:

```cpp
SecureBuf(SecureBuf& other);    // 복사 생성자
SecureBuf(SecureBuf&& other);   // 이동 생성자

SecureBuf a;
SecureBuf b(a);              // & 매칭 → 복사 생성자
SecureBuf c(std::move(a));   // && 매칭 → 이동 생성자
```

---

## 4. std::move

**실제로 아무것도 이동시키지 않는다.** lvalue를 rvalue로 캐스팅할 뿐이다.

```cpp
SecureBuf a(some_data);
SecureBuf b(a);              // ❌ 컴파일 에러 (&&에 바인딩 안 됨)
SecureBuf b(std::move(a));   // ✅ a를 rvalue로 캐스팅 → && 매칭
```

### 왜 필요한가

`std::move` 없이 `&`로 받아서 원본을 파괴할 수도 있다. 하지만:

```cpp
// & 버전: 호출부에서 파괴 여부가 안 보임
SecureBuf b(a);     // a가 파괴되는지? 안 되는지? 모름

// && 버전: std::move가 경고 표지판 역할
SecureBuf b(std::move(a));  // "a를 여기서 포기한다"는 의도 명시
```

`&&`는 프로그래머 실수를 **컴파일 타임에 방지**하는 안전장치. `std::move`는 그 안전장치를 **의도적으로 해제**하는 명시적 표현이다.

단, `std::move` 후에도 원본을 사용하는 것은 컴파일러가 막지 못한다. 100% 방지는 아니지만, `&`만 쓰는 것(0% 방지)보다 훨씬 안전하다.

---

## 5. 이동 생성자 vs 이동 대입 연산자

둘 다 `&&`를 사용하지만, 호출되는 시점이 다르다.

### 이동 생성자 (Move Constructor)

**새 객체를 생성할 때** 호출:

```cpp
SecureBuf(SecureBuf&& other) noexcept : valid(other.valid) {
    std::memcpy(buf, other.buf, N);
    sodium_memzero(other.buf, N);
    other.valid = false;
}

// 호출 예시
SecureBuf b(std::move(a));       // 이동 생성자
SecureBuf c = std::move(a);      // 이것도 이동 생성자 (새 객체 생성)
```

### 이동 대입 연산자 (Move Assignment)

**이미 존재하는 객체에 대입할 때** 호출:

```cpp
SecureBuf& operator=(SecureBuf&& other) noexcept {
    if (this != &other) {
        sodium_memzero(buf, N);       // 기존 데이터 먼저 정리
        std::memcpy(buf, other.buf, N);
        valid = other.valid;
        sodium_memzero(other.buf, N);
        other.valid = false;
    }
    return *this;
}

// 호출 예시
SecureBuf b;
b = std::move(a);                // 이동 대입 (b는 이미 존재)
```

핵심 차이: 이동 대입은 **기존 데이터를 먼저 정리**해야 한다.

---

## 6. DICE 코드에서의 활용

`SecureBuf`(= `Cdi`)가 이 개념들을 모두 활용하는 대표적 예시:

```cpp
// 1. 복사 금지 — 비밀 키가 여러 곳에 존재하면 위험
SecureBuf(const SecureBuf&) = delete;

// 2. 이동만 허용 — 소유권이 한 곳에만 존재
SecureBuf(SecureBuf&& other) noexcept;

// 3. 이동 후 원본 제로화 — 이전 레이어가 비밀을 유지하면 안 됨
sodium_memzero(other.buf, N);

// 4. 소멸자에서도 제로화 — 스코프를 벗어나면 자동 정리
~SecureBuf() { sodium_memzero(buf, N); }
```

DICE 부트 체인에서 CDI의 흐름:

```cpp
Cdi cdi0 = engine.compute_first_cdi(FW_L0);  // Engine → cdi0
LayerResult r0 = process_layer0(std::move(cdi0), ...);
// cdi0.buf은 제로화됨 — Layer 0이 CDI를 소유
// r0.next_cdi에 다음 레이어용 CDI가 들어있음

LayerResult r1 = process_layer_n(std::move(r0.next_cdi), ...);
// r0.next_cdi도 제로화됨 — Layer 1이 CDI를 소유
```

각 레이어가 CDI를 받아 사용한 후 파괴하므로, **이전 레이어는 절대 다음 레이어의 비밀에 접근할 수 없다.** 이것이 DICE의 핵심 보안 속성이며, C++의 이동 의미론이 이를 자연스럽게 표현한다.
