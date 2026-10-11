# PoP Diagnoser (Proof of Possession 게이트웨이 401/403/400 오프라인 진단기)

[![CI](https://github.com/altdmfk/pop-diagnoser/actions/workflows/test.yml/badge.svg)](https://github.com/altdmfk/pop-diagnoser/actions/workflows/test.yml)

> **한 줄 요약 (KR):** FIDO2 Proof-of-Possession(PoP) 게이트웨이가 `401`/`403`/`400`을 반환할 때, 외부 네트워크 통신이나 비밀키 입력 없이 어느 검증 단계에서 어떤 정규화·인코딩 실수로 실패했는지 찾는 오프라인 진단 도구입니다.  
> **Summary (EN):** An offline browser/CLI diagnostic tool that identifies the failed verification stage and canonicalization/encoding mistake when a FIDO2 Proof-of-Possession gateway rejects requests with `401`/`403`/`400`.

---

## 1. 문제 정의

보안 게이트웨이는 공격자에게 단서를 주지 않기 위해 서명 검증에 실패해도 `401 Unauthorized`, `403 Forbidden`, `400 Bad Request`만 반환합니다.  
그래서 연동 과정에서 다음과 같은 차이가 생기면 어디서 문제가 발생했는지 확인하기가 쉽지 않습니다.

- 쿼리 파라미터(`?c=3&a=1&b=2`)를 서명 전에 알파벳순으로 정렬했는가, 원본 순서를 유지했는가?
- HTTP 메서드를 소문자(`post`)로 서명했거나, 프록시가 `Host` 헤더의 `:443` 포트를 제거했는가?
- ECDSA P-256 서명을 IEEE P1363(64바이트 Raw `r || s`) 대신 ASN.1 DER 형식이나 표준 Base64(`+`, `/`, `=`)로 인코딩했는가?
- 본문(Body) 해시 계산 시 줄바꿈이 `CRLF(\r\n)`로 바뀌었거나 대문자 Hex / Base64url을 사용했는가?

**PoP Diagnoser**는 게이트웨이의 1~5단계 검증 과정을 브라우저와 CLI에서 동일하게 재현합니다. 검증에 실패하면 14개 항목의 가설 카탈로그를 너비 우선 탐색(BFS)으로 조합해, 클라이언트가 실제로 서명한 문자열과 게이트웨이가 기대한 정규화 문자열의 차이를 비교해 보여줍니다.

---

## 2. 데모 및 실행 방법

- **라이브 데모 (GitHub Pages):** [https://altdmfk.github.io/pop-diagnoser/](https://altdmfk.github.io/pop-diagnoser/)
- **관련 게이트웨이 및 논문 프로젝트:** [FIDO2 PoP Gateway Project (`https://altdmfk.github.io/fido2-pop-gateway/`)](https://altdmfk.github.io/fido2-pop-gateway/)

### 로컬 실행 (`file://` 지원)
1. 저장소를 클론하거나 ZIP으로 내려받습니다.
2. 별도의 패키지 설치나 로컬 웹 서버 없이 [`index.html`](index.html) 파일을 브라우저(`file://`)에서 바로 엽니다.
3. 브라우저 개발자 도구(F12)의 **Network** 탭을 열어두면 외부 네트워크 요청이 발생하지 않는 것을 확인할 수 있습니다.

---

## 3. 주요 기능

- **5단계 오프라인 검증 파이프라인**: 필수 헤더 확인(1단계) → 타임스탬프 허용 오차 60초(2단계) → Nonce 존재 여부(3단계) → ECDSA P-256 서명 검증(4단계) → 본문 SHA-256 다이제스트 대조(5단계) 순서로 진단합니다.
- **최소 일치 집합(Minimal Matching Set) 가설 탐색 및 Diff 표시**: 4단계 서명 검증 실패 시 최대 3개 복합 실수(`maxComboDepth: 3`)까지 BFS로 탐색하고, 불필요한 상위 집합을 제외한 최소 원인 조합과 줄 단위 Canonical Payload Diff(`- 클라이언트 서명값` / `+ 게이트웨이 기대값`)를 출력합니다.
- **cURL / Raw HTTP 붙여넣기 파서 및 샘플 명령어**: 브라우저 개발자 도구의 `Copy as cURL (bash)` 명령어나 Raw HTTP 요청 원문을 붙여넣어 메서드, URL, 본문(원본 줄바꿈·공백 보존), PoP 헤더 4종을 한 번에 채울 수 있습니다. 바로 시험해 볼 수 있도록 `샘플: 정상 cURL`, `샘플: 실패 cURL (DER 서명)`, `샘플: Raw HTTP` 버튼 3종을 제공하며, 기존 입력값이 있을 때는 덮어쓰기 전에 확인 바를 띄웁니다.
- **서명 · 공개키 구조 인스펙터**: 서명의 인코딩(`base64url` / 표준 `base64` / `hex`), 바이트 길이, 형식(`raw-rs(64B)` / `der`), `r`·`s` 32B Hex, `s > n/2` (High-S) 여부를 분석합니다. 공개키는 SPKI OID(`ecPublicKey` / `P-256`), 비압축 좌표(`0x04 || X || Y`), P-256 타원곡선 방정식(\(y^2 \equiv x^3 - 3x + b \pmod p\)) 충족 여부, SHA-256 Fingerprint를 확인하며, 실수로 개인키(`PRIVATE KEY`) PEM을 입력하면 파싱하지 않고 경고를 표시합니다.
- **내장 테스트 서명 생성기**: 브라우저 WebCrypto API(`crypto.subtle`)를 사용해 현재 입력된 요청에 대한 임시 ECDSA P-256 키 쌍, `X-Body-Digest`, 전자서명을 생성합니다.
- **JSON 문법 오류 위치 표시**: 요청 본문(Body)이 잘못된 JSON일 때 오류 줄·칸 번호를 계산하고, 한글·전각 문자 폭(2칸)과 탭을 보정해 오류 위치 아래에 화살표(`▲`)를 표시합니다.
- **4개 탭 레이아웃 · 키보드 접근성 · 5개 슬롯 저장소**: 입력과 보조 도구를 `HTTP 요청` / `서명 헤더` / `검증 설정` / `cURL · 임시저장소` 4개 탭으로 나누고, 좌우 방향키·`Home`·`End` 키 이동과 ARIA 속성을 지원합니다. `localStorage` 기반 슬롯 5개에 전체 입력 상태를 저장하고 불러올 수 있습니다.

---

## 4. 설계 원칙

1. **외부 네트워크 요청 0건**
   - `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, 외부 폰트·스크립트를 사용하지 않으며, CSP `connect-src 'none'`으로 외부 연결을 막았습니다.
2. **비밀키 비요구**
   - 진단기는 공개키(SPKI PEM/Base64)와 서명 결과값만 입력받습니다. 클라이언트의 비밀키를 입력받거나 다루지 않습니다.
3. **CSP 준수 및 DOM 기반 렌더링**
   - `default-src 'none'; script-src 'self' file:; style-src 'self' file:;` 정책을 적용합니다.
   - 코드 전체에서 `innerHTML`, `outerHTML`, `eval`, `new Function`, 인라인 이벤트 핸들러(`onclick=`), 인라인 스타일 조작(`el.style.*`)을 사용하지 않습니다. 코어 모듈은 데이터 객체만 반환하고, UI 모듈은 `createElement`와 `textContent`로만 화면을 그립니다.
4. **무빌드 UMD 모듈 구조**
   - `file://` 환경에서는 브라우저 CORS 정책 때문에 ES 모듈(`<script type="module">`)이 동작하지 않습니다. 모든 스크립트를 UMD 패턴으로 작성해 빌드 도구 없이 브라우저(`window.PopCore`, `window.PopUI`)와 Node.js(`require()`) 양쪽에서 그대로 실행됩니다.

---

## 5. 아키텍처

### 5.1 모듈 구조도 (`core` / `profile` / `ui` / `test`)

```mermaid
flowchart TD
    subgraph Browser_or_Node["Core Engine (DOM-Independent UMD, 8 Modules)"]
        Profile["js/core/profiles/paper.js<br/>(PaperProfile: 60s, 64B, Headers, Stages 1-5)"]
        Encoding["js/core/encoding.js<br/>(Base64url / Std Base64 / SHA-256)"]
        ECDSA["js/core/ecdsa.js<br/>(SPKI Import / derToRaw / P-256 Verify)"]
        Inspect["js/core/inspect.js<br/>(Sig & SPKI Curve/OID Inspector)"]
        CurlParser["js/core/curlParser.js<br/>(cURL & Raw HTTP Tokenizer)"]
        Canonical["js/core/canonical.js<br/>(Canonical Payload Builder)"]
        Hypotheses["js/core/hypotheses.js<br/>(Unified 14-Item Catalog)"]
        Diagnose["js/core/diagnose.js<br/>(diagnose & generateTestSignature)"]

        Profile --> Diagnose
        Profile --> CurlParser
        Encoding --> ECDSA
        Encoding --> Inspect
        ECDSA --> Inspect
        Encoding --> Hypotheses
        ECDSA --> Hypotheses
        Encoding --> Diagnose
        ECDSA --> Diagnose
        Inspect --> Diagnose
        CurlParser --> Diagnose
        Canonical --> Diagnose
        Hypotheses --> Diagnose
    end

    subgraph UI_Layer["UI Layer (DOM Builders, 7 Modules)"]
        JsonError["js/ui/jsonError.js<br/>(Line/Col & CJK Width Pointer)"]
        Render["js/ui/render.js<br/>(textContent DOM Renderer)"]
        InspectorUI["js/ui/inspector.js<br/>(Details Panel & Debounced Inspector)"]
        ImporterUI["js/ui/importer.js<br/>(cURL/HTTP Importer & Sample Buttons)"]
        Slots["js/ui/slots.js<br/>(LocalStorage 5 Slots)"]
        Tabs["js/ui/tabs.js<br/>(4-Tab & Keyboard Controller)"]
        App["js/app.js<br/>(DOMContentLoaded Bootstrap)"]

        JsonError --> Diagnose
        Inspect --> InspectorUI
        CurlParser --> ImporterUI
        Render --> Slots
        Render --> App
        InspectorUI --> App
        ImporterUI --> App
        Slots --> App
        Tabs --> App
        Diagnose --> App
    end

    subgraph Test_Suite["Test & Verification"]
        Fixtures["test/fixtures/fixtures.js"]
        TestJS["test/test.js (59 Tests)"]
        Fixtures --> TestJS
        Diagnose --> TestJS
        Inspect --> TestJS
        CurlParser --> TestJS
        Render --> TestJS
        InspectorUI --> TestJS
        ImporterUI --> TestJS
        Slots --> TestJS
        Tabs --> TestJS
    end
```

### 5.2 진단 5단계 및 가설 탐색 흐름도

```mermaid
flowchart LR
    Input["요청 입력<br/>(Method, URL, Body, Headers, PEM)"] --> S1["1단계: 필수 헤더 확인"]
    S1 -- "누락" --> Out1["1단계 실패 반환"]
    S1 -- "통과" --> Parse["입력 형식 검사<br/>(JSON, URL, PEM, Base64, Timestamp)"]
    Parse -- "형식 오류" --> Err["입력 오류 반환<br/>(JSON 줄/칸 화살표 스니펫)"]
    Parse -- "정상" --> S2["2단계: Timestamp 오차 (≤60s)"]
    S2 --> S3["3단계: Nonce 존재 확인"]
    S3 --> S4["4단계: ECDSA P-256 서명 검증"]
    S4 --> S5["5단계: SHA-256 본문 다이제스트 대조"]
    S5 -- "4·5단계 모두 통과" --> Pass["검증 성공 (Skipped)"]
    S5 -- "4단계 통과 + 5단계 실패" --> H5["5단계 다이제스트 가설 탐색<br/>(Base64url, 대문자 Hex, CRLF, BOM 등)"]
    S5 -- "4단계 실패" --> H4["4단계 서명 가설 BFS 탐색<br/>(최대 3개 조합, 최소 일치 집합 필터링)"]
    H5 --> Diff["원인 가설 + Canonical Diff 출력"]
    H4 --> Diff
```

---

## 6. 가설 카탈로그

4단계(서명 검증) 또는 5단계(다이제스트 대조) 실패 시 탐색하는 가설 목록입니다. 모든 가설은 [`js/core/hypotheses.js`](js/core/hypotheses.js)에 단일 스키마(`{ id, label, tag, stage, apply }`)로 정의되어 있으며 [`test/test.js`](test/test.js)에서 각 항목을 테스트합니다.

| # | 가설 ID (`id`) | 출처 태그 | 적용 단계 | 진단하는 실수 내용 | 테스트 검증 위치 |
| :-: | :--- | :--- | :-: | :--- | :--- |
| 1 | `query-sorted` | `[흔한 실수]` | 4단계 | 쿼리 파라미터를 알파벳순으로 정렬하여 서명함 | [`fixtures.js`](test/fixtures/fixtures.js) (`query-sorted`, `combo-2`) |
| 2 | `query-reverse` | `[흔한 실수]` | 4단계 | 쿼리 파라미터 순서를 역순으로 뒤집어 서명함 | [`test/test.js`](test/test.js) (`hyp-query-reverse`) |
| 3 | `method-lowercase` | `[흔한 실수]` | 4단계 | HTTP 메서드를 소문자(`post`, `get` 등)로 서명함 | [`fixtures.js`](test/fixtures/fixtures.js) (`method-lowercase`, `combo-2`) |
| 4 | `path-trailing-slash-add` | `[흔한 실수]` | 4단계 | URL Path 끝에 슬래시(`/`)를 추가하여 서명함 | [`fixtures.js`](test/fixtures/fixtures.js) (`path-trailing-slash-add`) |
| 5 | `path-trailing-slash-remove` | `[흔한 실수]` | 4단계 | URL Path 끝의 슬래시(`/`)를 제거하고 서명함 | [`test/test.js`](test/test.js) (`hyp-path-trailing-slash-remove`) |
| 6 | `host-rewritten` | `[흔한 실수]` | 4단계 | `Host`의 기본 포트(`:443`)를 누락하거나 추가하여 서명함 | [`fixtures.js`](test/fixtures/fixtures.js) (`host-rewritten`, `both-fail`) |
| 7 | `sig-der` | `[인코딩]` | 4단계 | 서명을 64B Raw(P1363) 대신 ASN.1 DER 형식으로 인코딩함 | [`fixtures.js`](test/fixtures/fixtures.js) (`sig-der`), [`test/test.js`](test/test.js) (`hyp-sig-der-short-under-70b`) |
| 8 | `sig-base64url` | `[인코딩]` | 4단계 | 서명을 Base64url 대신 표준 Base64(`+`, `/`, `=`)로 인코딩함 | [`test/test.js`](test/test.js) (`hyp-sig-base64url`) |
| 9 | `newline-crlf` | `[논문 규칙]` | 4·5단계 겸용 | Canonical 구분자(4단계) 또는 본문 줄바꿈(5단계)을 `CRLF(\r\n)`로 사용함 | [`test/test.js`](test/test.js) (`hyp-newline-crlf-stage4`), [`fixtures.js`](test/fixtures/fixtures.js) (`newline-crlf`) |
| 10 | `newline-trailing` | `[논문 규칙]` | 4·5단계 겸용 | Canonical 문자열(4단계) 또는 본문(5단계) 끝에 줄바꿈(`\n`)을 추가함 | [`test/test.js`](test/test.js) (`hyp-newline-trailing-stage4`, `hyp-newline-trailing-stage5`) |
| 11 | `digest-base64url` | `[인코딩]` | 5단계 | 본문 SHA-256 해시를 소문자 Hex 대신 Base64url로 인코딩함 | [`fixtures.js`](test/fixtures/fixtures.js) (`digest-base64url`) |
| 12 | `digest-hex` | `[인코딩]` | 5단계 | 본문 SHA-256 해시를 대문자(또는 대소문자 혼합) Hex로 인코딩함 | [`test/test.js`](test/test.js) (`hyp-digest-hex`) |
| 13 | `body-bom-added` | `[흔한 실수]` | 5단계 | 본문 앞에 UTF-8 BOM(`\uFEFF`)이 추가된 상태로 해시를 계산함 | [`test/test.js`](test/test.js) (`hyp-body-bom-added`) |
| 14 | `body-reserialized-nospace` | `[흔한 실수]` | 5단계 | 원본 본문 대신 `JSON.stringify()`로 공백을 제거한 문자열을 해시함 | [`test/test.js`](test/test.js) (`hyp-body-reserialized-nospace`) |

---

## 7. 테스트, 검증 도구 및 배포 안내

### 단위·회귀 테스트 실행
Node.js(v20 이상 권장) 환경에서 외부 패키지 설치 없이 실행됩니다.
```bash
# 루트 진입점 또는 테스트 파일 실행 (총 59개 테스트)
node test.js
node test/test.js

# 인코딩 검사 (UTF-8, BOM 미포함, U+FFFD 깨진 문자 여부 확인)
python tools/check_encoding.py
```
브라우저에서 확인하려면 [`test.html`](test.html) 파일을 열어 동일한 테스트를 실행할 수 있습니다.

### 픽스처 생성 및 게이트웨이 차분 테스트 (선택)
로컬에 참조 게이트웨이 저장소(`../fido2-pop-gateway-main`)가 있는 경우, FastAPI 게이트웨이의 실제 응답과 진단기의 판정 단계를 비교할 수 있습니다.
```bash
python tools/generate_fixtures.py    # test/fixtures/fixtures.js 갱신
python tools/differential_check.py   # 게이트웨이 vs 진단기 14개 시나리오 비교 검증
node tools/golden_pass.js            # 골든 패스 픽스처 검증
```

### GitHub Pages 정적 배포 안내
루트 [`index.html`](index.html)과 상대 경로 리소스만으로 구성되어 있어 별도 빌드 과정 없이 GitHub Pages로 배포할 수 있습니다.
1. GitHub 저장소의 **Settings → Pages** 메뉴로 이동합니다.
2. **Build and deployment**의 **Source**를 `Deploy from a branch`로 선택합니다.
3. **Branch**를 `main`, 폴더를 `/ (root)`로 선택한 뒤 **Save**를 누릅니다.
4. 배포가 끝나면 `https://<OWNER>.github.io/<REPO>/`에서 사용할 수 있습니다.

---

## 8. 알려진 한계

- **카탈로그 밖 변형 및 복합 오류 상한**: 브라우저 응답 지연을 막기 위해 가설 탐색은 최대 3개 조합(`maxComboDepth: 3`), 최대 2,000개 노드(`maxSearchNodes: 2000`)까지만 수행합니다. 카탈로그에 없는 변형이나 4개 이상의 복합 실수는 `"원인 파악 실패 (일치하는 실수 패턴 없음)"`으로 표시됩니다.
- **`host-rewritten` 가설의 범위**: `host-rewritten` 가설은 HTTPS 기본 포트(`:443`)의 누락·추가만 확인합니다. `:80` 포트, 커스텀 포트(예: `:8443`), 또는 브라우저 `new URL()` 파서가 자동으로 소문자로 바꾸는 `Host` 대소문자 차이는 탐지하지 않습니다.
- **프록시·중간 계층의 요청 변형**: 리버스 프록시, CDN, WAF 등이 전송 도중 URL이나 본문을 수정한 경우, 클라이언트가 서명한 원본 값을 찾으려면 변형 전후의 요청을 함께 비교해야 합니다.
- **서버 상태 의존 항목 제외**: 게이트웨이 DB의 Nonce 재사용(Replay) 여부 조회와 `Authorization` 헤더의 JWT 클레임(`cnf.kid`) 바인딩 검증은 서버 상태가 필요하므로 오프라인 진단 범위에서 제외됩니다.

---

## 9. 논문과의 관계 및 케이스 스터디

- **기반 논문 및 게이트웨이**: 이 도구는 [**"Design and Performance Analysis of a FIDO2 Hardware-Isolated Key-Based Proof-of-Possession Reverse Proxy Gateway"**](https://altdmfk.github.io/fido2-pop-gateway/)의 정규화 규격(`PaperProfile`)을 따릅니다.
- **논문 순서 vs 실제 게이트웨이 구현 순서**: 논문 개념도는 4단계 다이제스트 대조 후 5단계 서명 검증을 설명하지만, 실제 게이트웨이 코드는 대용량 본문 해시 연산을 이용한 서비스 거부(DoS) 공격을 막기 위해 **헤더 기반의 ECDSA 서명 검증(4단계)을 먼저 수행한 뒤 본문 스트리밍 다이제스트 대조(5단계)**를 수행합니다. 진단기는 실제 게이트웨이 코드의 실행 순서를 따릅니다.
- **코드 감사 및 리팩토링 기록**: 코드 감사 과정에서 찾아 수정한 도달 불가 가설, DOM XSS, DER 파서 경계 버그와 추가 기능 설계 내용은 [**`docs/case-study.md`**](docs/case-study.md)에 정리되어 있습니다.
