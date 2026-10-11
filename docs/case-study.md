# 내 코드를 직접 감사하며 찾은 버그들

본 문서는 [FIDO2 PoP 게이트웨이 프로젝트](https://altdmfk.github.io/fido2-pop-gateway/)의 오프라인 진단기(**PoP Diagnoser**)를 자체 코드 감사(Self-Audit) 및 리팩토링하면서 발견하고 수정한 주요 결함들을 기록한 기술 케이스 스터디입니다.

모든 항목은 **발견(증상) → 원인(기존 파일:줄 근거) → 수정 → 회귀 테스트 → 배운 점** 순서로 정리되어 있습니다.

---

## 1. 도달 불가 가설 (README에는 있으나 실제로는 절대 매칭되지 않던 가설들)

- **발견 (증상)**
  - `README.md`의 가설 카탈로그에 명시된 11개 가설 중 `query-unsorted`, `sig-base64url`, `digest-hex`가 어떤 입력을 넣어도 진단 결과로 채택되지 않았고, `newline-crlf`와 `newline-trailing`은 4단계(Canonical 구분자 실수)에서 동작하지 않았습니다.
  - 또한 5단계(다이제스트 불일치) 가설이 매칭되더라도 브라우저 UI에서는 원인 설명과 Diff가 렌더링되지 않고 빈 녹색 상자만 표시되었습니다.
- **원인 (기존 파일:줄 근거)**
  1. **`query-unsorted` (기존 `diagnose-core.js:230-235`)**: 게이트웨이의 기본 규격 자체가 URL 쿼리를 정렬하지 않고 원본 순서 그대로(`baseReq.query = url.search.substring(1)`) 사용하는데, `query-unsorted`의 `apply`가 `req => ({ ...req, query: req.rawQuery })`로 정의되어 있어 `baseReq`와 항상 동일한 문자열을 반환했습니다. BFS 탐색 루프(`diagnose-core.js:575`)는 `nextCanonical === canonical`이면 `continue`로 건너뛰므로 절대 매칭될 수 없는 항등(no-op) 가설이었습니다.
  2. **`sig-base64url` (기존 `diagnose-core.js:285-303`, `421-426`)**: 표준 Base64(`+`, `/`, `=`)로 인코딩된 서명이 들어오면 4단계 가설 탐색에 도달하기 전인 입력 파싱 단계(`base64UrlDecode(signature)`)에서 정규식 검사에 걸려 즉시 `result.error`를 반환하고 종료되었습니다.
  3. **`digest-hex` (기존 `diagnose-core.js:305-311`, `525`)**: 5단계 본문 해시 비교가 `cleanReqDigest.toLowerCase() === bodyHashHex`로 대소문자를 무시하고 있어, 대문자 Hex 다이제스트가 5단계를 그대로 통과해버렸고, `HYPOTHESES`의 `digest-hex`는 4단계 전용 배열에만 들어 있어 5단계에서는 호출조차 되지 않았습니다.
  4. **4·5단계 가설 테이블 이원화 및 반환 스키마 불일치 (기존 `diagnose-core.js:542-562`, `app.js:353`)**: 4단계는 `{ type: 'found', sets: [...] }`를 반환한 반면, 5단계는 하드코딩된 별도 배열에서 `{ type: 'match', idStr, history }`를 반환했습니다. 그러나 `app.js`의 `renderResult()`는 `hRes.type === 'found'`와 `no-match`만 분기 처리하고 있어 5단계 매칭 결과가 화면에 그려지지 않았습니다.
- **수정**
  - [`js/core/hypotheses.js`](../js/core/hypotheses.js)에서 4단계와 5단계 가설을 단일 테이블(`HYPOTHESES`, `{ id, label, tag, stage, apply }`)로 통합하고, 5단계 매칭 반환 구조도 `{ type: 'found', sets: [...], reduced: false }`로 통일했습니다.
  - 5단계 다이제스트 비교를 대소문자 구분 비교(`cleanReqDigest === bodyHashHex`)로 변경해 대문자 Hex가 `digest-hex` 가설로 잡히도록 수정했습니다.
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 `decodeSignatureWithFallback()`에서 Base64url 디코딩 실패 시 표준 Base64 디코딩 결과가 64바이트 이상이면 `stdBase64Signature` 후보로 보존하여 4단계 `sig-base64url` 가설이 검증할 수 있게 했습니다.
  - `newline-crlf`와 `newline-trailing`을 `stage: 'both'`(4·5단계 겸용)로 확장하고, 의미 없는 항등 변형이던 `query-unsorted`는 제거했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `dynamicCases`에 `hyp-sig-base64url`, `hyp-digest-hex`, `hyp-newline-crlf-stage4`, `hyp-newline-trailing-stage4`, `hyp-newline-trailing-stage5` 등을 추가하고, 모든 5단계 픽스처에서도 `expected.idStr`까지 대조하도록 검증을 강화했습니다.
- **배운 점**
  - 선언적 카탈로그(테이블)를 설계할 때 앞단 파서(Early Return)의 전제 조건과 뒷단 가설 탐색의 입력 조건이 충돌하면, 코드는 존재하지만 실행 경로상 도달 불가능한(Unreachable) 죽은 기능이 만들어집니다. 모든 카탈로그 항목은 반드시 1:1로 대응하는 실패 재현 테스트를 가져야 합니다.

---

## 2. 에러 및 경고 경로의 DOM XSS 취약점

- **발견 (증상)**
  - 정상 진단 결과 경로는 `textContent`를 사용하고 있었으나, JSON 문법 오류나 소문자 HTTP 메서드 경고 등 **예외/경고 경로 3곳**에서 사용자 입력이 가공 없이 `innerHTML`로 삽입되고 있었습니다.
- **원인 (기존 파일:줄 근거)**
  1. 기존 `diagnose-core.js:401`, `706`에서 `getJsonErrorSnippet(e, bodyStr)`(사용자가 입력한 JSON 문제 행 `problemLine` 원본 포함)을 `<div class="error-detail-box">...</div>` HTML 문자열과 결합해 반환했고, `app.js:235`, `308`에서 이를 `panel.innerHTML` / `errDiv.innerHTML`에 그대로 대입했습니다.
  2. 기존 `diagnose-core.js:465`에서 사용자 입력 `method`를 경고 문자열에 포함시켰고, `app.js:275-278`에서 `result.warnings.forEach(w => { html += \`<li>${w}</li>\`; }); wDiv.innerHTML = html;`로 렌더링했습니다.
- **수정**
  - 코어 엔진([`js/core/diagnose.js`](../js/core/diagnose.js))에서 모든 HTML 태그 문자열을 제거하고 `{ message, detail, hint, hintExample }` 형태의 순수 데이터 객체만 반환하도록 분리했습니다.
  - UI 렌더러([`js/ui/render.js`](../js/ui/render.js))의 모든 `innerHTML` 호출을 제거(코드베이스 전체 `innerHTML` 0건)하고 `document.createElement`, `textContent`, `document.createTextNode`로만 DOM을 조립하도록 교체했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)에 `bodyStr: '{"xss": "<img src=x onerror=alert(1)>", broken}'` 및 `method: "<script>alert(1)</script>"`를 주입하는 XSS 회귀 테스트 5건을 추가했습니다. 특히 Mock DOM의 `set innerHTML` 스파이를 통해 렌더링 중 `innerHTML` 대입이 0회이며 페이로드가 `textContent`에만 존재함을 자동 검증합니다.
- **배운 점**
  - "정상 경로(Happy Path)"에서 `textContent`를 썼더라도, 에러 메시지 포매팅(줄바꿈 `<br>`, 강조 `<strong>` 등)을 편하게 하려고 코어가 HTML 조각을 반환하기 시작하면 곧바로 XSS 싱크가 열립니다. 코어는 순수 데이터만 반환하고 마크업 조립은 전적으로 UI 렌더러가 담당해야 합니다.

---

## 3. Node.js와 브라우저 간 Base64url 디코딩 불일치 및 에러 핸들러 복붙 버그

- **발견 (증상)**
  - 길이 나머지가 1인 잘못된 Base64url 문자열(예: `"abcde"`)을 넣었을 때 브라우저(`window.atob`)에서는 즉시 예외가 발생한 반면, Node.js(`Buffer.from(str, 'base64')`)에서는 예외 없이 관대하게 무시되어 1단계 입력 에러 대신 4단계 검증 실패로 넘어가는 환경 간 불일치가 있었습니다.
  - 또한 잘못된 URL을 입력했을 때 URL 에러 상세 상자에 URL 에러가 아니라 엉뚱한 `getJsonErrorSnippet(e, bodyStr)` 결과가 출력되거나, `bodyStr`이 `undefined`이면 `TypeError`로 크래시가 발생했습니다.
- **원인 (기존 파일:줄 근거)**
  - 기존 `diagnose-core.js:55-68`의 `base64UrlDecode()`가 패딩 제거 후 `base64.length % 4 === 1`(Base64 규격상 불가능한 길이)을 검사하지 않고 Node의 `Buffer.from(..., 'base64')`에 그대로 전달했습니다.
  - 기존 `diagnose-core.js:413`의 URL 파싱 `catch (e)` 블록에서 복사-붙여넣기 실수로 `${e.message}` 대신 `${getJsonErrorSnippet(e, bodyStr)}`를 호출하고 있었습니다.
- **수정**
  - [`js/core/encoding.js`](../js/core/encoding.js)의 `base64UrlDecode()` 및 `base64StandardDecode()`에서 허용 문자 정규식과 `length % 4 === 1` 여부를 명시적으로 검증하도록 수정해 브라우저와 Node.js의 동작을 일치시켰습니다.
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 URL `catch (e)` 블록에서 `detail: e.message`를 반환하도록 수정했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `bad-signature-length` (`signature: "abcde"`) 및 `bad-url` 케이스로 검증했습니다.
- **배운 점**
  - 브라우저(`atob`)와 Node.js(`Buffer.from`)를 겸용하는 UMD 모듈에서는 런타임 내장 디코더의 암묵적 관대함에 의존하지 말고, 입력 형식 불변 조건(정규식 및 길이 모듈로)을 직접 검증해야 합니다.

---

## 4. 거짓 통과(False Positive)하던 테스트 러너와 `undefined.trim()` 크래시

- **발견 (증상)**
  - 초기 상태에서 `node test.js`를 실행하면 `bad-url` 케이스에서 `TypeError: Cannot read properties of undefined (reading 'trim')`가 발생하며 테스트가 중단되었습니다.
  - 또한 `test.js`의 `inputTests` 검증 로직에 결함이 있어, 에러가 나지 않아야 할 케이스(`expectError: false`)에서 에러가 발생해도 테스트가 통과(`passed++`)로 집계되고 있었습니다.
- **원인 (기존 파일:줄 근거)**
  - 기존 `diagnose-core.js:397`에서 `if (bodyStr.trim())`을 호출할 때 `inputs.bodyStr`이 생략(`undefined`)된 경우를 방어하지 않았습니다.
  - 기존 `test.js:61-65`에서 `if (t.expectError && !result.error) { ok = false; }`만 검사하고, `else if (!t.expectError && result.error)` 분기가 누락되어 있었습니다.
  - 또한 `test.js:30-35`의 픽스처 검증 루프에서 `expected.idStr`가 지정되어 있어도 `result.hypothesisResult.type === 'found'`일 때만 비교하고 5단계가 반환하던 `type === 'match'`일 때는 `idStr` 비교를 건너뛰고 있었습니다.
- **수정**
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 `normalizeInputs()`에서 모든 문자열 입력을 `String(safe.field ?? "")`로 정규화하고, `evalTime`이 `NaN`/미입력일 때도 현재 시각으로 안전하게 폴백하도록 방어했습니다.
  - [`test/test.js`](../test/test.js)에서 `!t.expectError && result.error`일 때 즉시 실패 처리하도록 수정하고, 4·5단계 모든 매칭 케이스의 `idStr`를 엄격히 대조하도록 보강했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `inputTests` 9종(`empty-inputs`, `bad-url`, `missing-nonce`, `long-input` 등) 전체 통과로 확인했습니다.
- **배운 점**
  - 테스트 코드 자체가 조건문 누락으로 거짓 양성(False Positive)을 내고 있으면 코어의 버그가 가려집니다. 단언문(Assertion)은 긍정 조건과 부정 조건 양쪽을 모두 닫아야 합니다.

---

## 5. `localStorage` 예외로 인한 앱 전체 먹통

- **발견 (증상)**
  - 브라우저 설정에서 쿠키/사이트 데이터를 차단했거나 `file://` 로컬 스토리지 접근이 제한된 환경, 혹은 `popDiagnoserSlots` 키에 손상된 JSON이 들어간 경우 페이지 로드 직후 앱 전체가 먹통이 되어 `진단 시작` 및 데모 버튼조차 동작하지 않았습니다.
- **원인 (기존 파일:줄 근거)**
  - 기존 `app.js:36`의 `DOMContentLoaded` 핸들러 최상단에서 `JSON.parse(localStorage.getItem('popDiagnoserSlots') || '{}')`를 `try/catch` 없이 즉시 실행했습니다. 여기서 `SecurityError`나 `SyntaxError`가 던져지면 같은 핸들러 아래쪽(`app.js:134-291`)에 있던 모든 버튼 이벤트 리스너 등록 코드가 실행되지 못한 채 중단되었습니다.
- **수정**
  - [`js/ui/slots.js`](../js/ui/slots.js)에서 `readMemorySlots()`와 `writeMemorySlots()` 래퍼 함수를 만들어 모든 `localStorage.getItem`, `setItem`, `JSON.parse`를 `try/catch` 및 타입 검사로 감쌌습니다.
  - 저장소 접근 실패 시 예외를 던지는 대신 `{ ok: false, reason, data: {} }`를 반환하여 앱 초기화와 이벤트 바인딩이 정상 완료되도록 하고, 사용자가 슬롯 저장/불러오기를 시도할 때만 토스트 메시지로 원인을 안내하도록 개선했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `storage-resilience` 테스트에서 `SecurityError`, `QuotaExceededError`, 손상된 JSON(`"{broken-json"`)을 주입해 예외 전파 없이 `{ ok: false }`가 반환됨을 검증했습니다.
- **배운 점**
  - 부수적 편의 기능(임시저장 슬롯)의 초기화 실패가 핵심 기능(서명 진단)의 이벤트 바인딩까지 중단시키는 단일 장애점(SPOF)이 되어서는 안 됩니다. 특히 `file://` 환경에서는 `localStorage` 접근이 언제든 거부될 수 있음을 전제해야 합니다.

---

## 6. ASN.1 DER → Raw(P1363) 변환(`derToRaw`) 경계 조건 버그

- **발견 (증상)**
  - 유효한 ECDSA P-256 ASN.1 DER 서명 중 길이가 68~69바이트인 서명이 `sig-der` 가설로 진단되지 않고 실패했으며, 비정상적인 DER 바이트 배열이 입력될 경우 `Uint8Array.prototype.set()`에서 `RangeError: offset is out of bounds`가 발생할 수 있었습니다.
- **원인 (기존 파일:줄 근거)**
  1. 기존 `diagnose-core.js:146`에서 `if (view.length < 70) return null;`로 하드코딩되어 있었습니다. P-256의 `r`, `s` 정수는 최상위 비트가 `0`이거나 상위 바이트가 `0x00`일 때 패딩 바이트 없이 31~32바이트로 인코딩되므로, 68~69바이트인 유효한 DER 서명이 자주 생성됩니다.
  2. 기존 `diagnose-core.js:154`에서 ASN.1 long-form 길이(`seqLen > 0x80`)를 파싱할 때 `offset = 2 + numLenBytes + 1`로 `+ 1`을 잘못 더해 `r`의 `0x02`(INTEGER) 태그 위치를 1바이트 건너뛰는 오프셋 계산 버그가 있었습니다.
  3. `rLen` 또는 `sLen`이 선행 `0x00` 1바이트를 제거한 뒤에도 32바이트를 초과할 때 검사 없이 `raw.set(r, 32 - rLen)`을 호출하여 음수 오프셋 `RangeError`가 발생할 수 있었습니다.
- **수정**
  - [`js/core/ecdsa.js`](../js/core/ecdsa.js)의 `derToRaw()`에서 최소 길이를 `MIN_DER_BYTES = 8`로 낮추고, long-form 오프셋을 `offset = 2 + numLenBytes`로 수정했습니다.
  - 전체 시퀀스 길이(`offset + seqLen === view.length`), `s` 끝 오프셋(`sStart + sLen === view.length`), 선행 패딩 제거 후 `1 <= len <= 32` 및 이중 `0x00` 패딩 거부 조건을 엄격히 검사하도록 수정했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)에 실제 70바이트 미만 DER 서명을 생성해 진단하는 `hyp-sig-der-short-under-70b`와 `derToRaw` 직접 단위 테스트 3건(`derToRaw-68b`, `derToRaw-long-form`, `derToRaw-invalid-33b`)을 추가했습니다.
- **배운 점**
  - 암호학 포맷 파서(ASN.1 DER)를 직접 구현할 때는 "가장 흔한 길이(70~72B)"만 가정해서는 안 되며, RFC/ITU-T X.690 규격에 따른 최소/최대 바이트 경계와 버퍼 길이 일치 여부를 빠짐없이 검증해야 합니다.

---

## 7. README ↔ 코드 불일치를 발견한 방법

- **발견 및 분석 방법**
  - 리팩토링 착수 전(Phase 0), `README.md`의 모든 문장을 기능 주장(Claim) 단위로 분해한 뒤 실제 코드의 심볼·줄 번호와 1:1 매핑표를 작성하는 **정적 교차 대조(Static Cross-Checking)**를 수행했습니다.
  - 그 결과:
    1. `README.md`에는 적혀 있으나 매칭 테스트가 없던 가설 4종(`query-unsorted`, `sig-base64url`, `digest-hex`, `newline-trailing`)이 실제로는 죽은 코드였음을 발견했습니다.
    2. 반대로 코드(`HYPOTHESES`)에는 구현되어 있으나 `README.md`에 누락되어 있던 가설 3종(`query-reverse`, `host-rewritten`, `body-bom-added`)을 식별해 문서와 테스트에 반영했습니다.
- **배운 점**
  - 문서와 코드의 괴리를 막으려면 문서의 카탈로그 표가 테스트 스위트의 케이스 목록과 1:1로 대응하도록 유지해야 합니다.

---

## 8. 리팩토링 전·후 정량 지표 비교

아래 수치는 실제 저장소 파일 및 `node test.js` 실행 결과에서 측정된 값입니다.

| 지표 항목 | 리팩토링 전 (Phase 0 Baseline) | 리팩토링 후 (최종) | 비고 |
| :--- | :--- | :--- | :--- |
| **`node test.js` 결과** | **16 통과 / 1 실패 / 실행 중 크래시 중단** | **45 통과 / 0 실패 (완주)** | `node test.js` 및 `node test/test.js`, `test.html` 동일 |
| **가설 카탈로그 동작률** | README 11개 중 **7개만 동작** (3개 불능, 1개 5단계 전용) + 미문서화 3개 | **13개 가설(14개 항목) 100% 동작 및 전수 테스트** | 무의미한 항등 가설 `query-unsorted` 제거 및 문서 동기화 |
| **5단계 가설 UI 렌더링** | 매칭되어도 화면 미출력 (`type: 'match'` 불일치) | **4·5단계 모두 원인 설명 + Diff 정상 출력** | 반환 스키마 `{ type: 'found', sets }` 통일 |
| **소스 파일 구조** | 루트 단일 파일 위주 (`diagnose-core.js` 782줄, `app.js` 465줄, `style.css` 479줄) | **역할별 11개 UMD 모듈 + `css/style.css` 분리** | `js/core/`(6개), `js/ui/`(4개), `js/app.js`(1개) |
| **최대 함수 길이** | `diagnose()` **311줄**, `renderResult()` **146줄** | `diagnose()` **50줄**, `renderResult()` **21줄** | 모든 하위 함수를 단일 책임(12~50줄)으로 분해 |
| **`innerHTML` 사용 건수** | **10건** (이 중 사용자 입력 삽입 XSS 싱크 3건) | **0건** | 전체 `createElement` / `textContent` 전환 |
| **`el.style.*` / `!important`** | `el.style.*` **27건**, CSS `!important` **12건** | **각 0건** | CSS 클래스 토글(`.hidden`, `.toast-visible` 등)로 일원화 |
