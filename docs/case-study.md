# 코드 감사 및 리팩토링 기록

이 문서는 [FIDO2 PoP 게이트웨이 프로젝트](https://altdmfk.github.io/fido2-pop-gateway/)의 오프라인 진단기(**PoP Diagnoser**)를 직접 점검하고 리팩토링하면서 수정한 주요 결함과 기능 개선 사항을 정리한 기록입니다.

각 버그 항목은 **발견(증상) → 원인(기존 파일:줄 근거) → 수정 → 회귀 테스트 → 정리** 순서로 작성했습니다.

---

## 1. 도달 불가 가설 (`README.md`에는 있었으나 실제로는 매칭되지 않던 가설들)

- **발견 (증상)**
  - 초기 `README.md`의 가설 카탈로그에 적힌 11개 가설 중 `query-unsorted`, `sig-base64url`, `digest-hex`는 어떤 입력을 넣어도 진단 결과로 선택되지 않았고, `newline-crlf`와 `newline-trailing`은 4단계(Canonical 구분자 실수)에서 동작하지 않았습니다.
  - 5단계(다이제스트 불일치) 가설이 매칭되더라도 브라우저 화면에는 원인 설명과 Diff가 나오지 않고 빈 상자만 표시되었습니다.
- **원인 (기존 파일:줄 근거)**
  1. **`query-unsorted` (기존 `diagnose-core.js:230-235`)**: 게이트웨이 기본 규격 자체가 URL 쿼리를 정렬하지 않고 원본 순서 그대로(`baseReq.query = url.search.substring(1)`) 사용하는데, `query-unsorted`의 `apply`가 `req => ({ ...req, query: req.rawQuery })`로 작성되어 있어 `baseReq`와 항상 같은 문자열을 반환했습니다. BFS 탐색 루프(`diagnose-core.js:575`)는 `nextCanonical === canonical`이면 `continue`로 건너뛰므로 매칭될 수 없는 가설이었습니다.
  2. **`sig-base64url` (기존 `diagnose-core.js:285-303`, `421-426`)**: 표준 Base64(`+`, `/`, `=`)로 인코딩된 서명이 들어오면 4단계 가설 탐색에 들어가기 전인 입력 파싱 단계(`base64UrlDecode(signature)`)에서 정규식 검사에 걸려 곧바로 `result.error`를 반환하고 끝났습니다.
  3. **`digest-hex` (기존 `diagnose-core.js:305-311`, `525`)**: 5단계 본문 해시 비교가 `cleanReqDigest.toLowerCase() === bodyHashHex`로 대소문자를 구분하지 않아 대문자 Hex 다이제스트가 5단계를 그대로 통과했고, `HYPOTHESES`의 `digest-hex`는 4단계 전용 배열에만 들어 있어 5단계에서는 호출되지 않았습니다.
  4. **4·5단계 가설 테이블 분리 및 반환 형식 불일치 (기존 `diagnose-core.js:542-562`, `app.js:353`)**: 4단계는 `{ type: 'found', sets: [...] }`를 반환한 반면, 5단계는 별도 배열에서 `{ type: 'match', idStr, history }`를 반환했습니다. 하지만 `app.js`의 `renderResult()`는 `hRes.type === 'found'`와 `no-match`만 처리하고 있어 5단계 매칭 결과가 화면에 표시되지 않았습니다.
- **수정**
  - [`js/core/hypotheses.js`](../js/core/hypotheses.js)에서 4단계와 5단계 가설을 하나의 테이블(`HYPOTHESES`, `{ id, label, tag, stage, apply }`)로 합치고, 5단계 매칭 반환 구조도 `{ type: 'found', sets: [...], reduced: false }`로 통일했습니다.
  - 5단계 다이제스트 비교를 대소문자 구분 비교(`cleanReqDigest === bodyHashHex`)로 바꾸어 대문자 Hex가 `digest-hex` 가설로 잡히도록 수정했습니다.
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 `decodeSignatureWithFallback()`에서 Base64url 디코딩이 실패하더라도 표준 Base64 디코딩 결과가 64바이트 이상이면 `stdBase64Signature` 후보로 남겨 4단계 `sig-base64url` 가설에서 검증할 수 있게 했습니다.
  - `newline-crlf`와 `newline-trailing`을 `stage: 'both'`(4·5단계 겸용)로 넓히고, 원본과 차이가 없던 `query-unsorted`는 제거했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `dynamicCases`에 `hyp-sig-base64url`, `hyp-digest-hex`, `hyp-newline-crlf-stage4`, `hyp-newline-trailing-stage4`, `hyp-newline-trailing-stage5`를 추가하고, 5단계 픽스처에서도 `expected.idStr`까지 확인하도록 보강했습니다.
- **정리**
  - 앞단 파서의 조기 종료 조건과 뒷단 가설 탐색의 입력 조건이 어긋나면 코드는 있어도 실행되지 않는 항목이 생깁니다. 가설 카탈로그의 각 항목에는 대응하는 실패 재현 테스트를 1:1로 두어야 합니다.

---

## 2. 에러 및 경고 출력 경로의 DOM XSS

- **발견 (증상)**
  - 정상 진단 결과는 `textContent`로 출력하고 있었으나, JSON 문법 오류나 소문자 HTTP 메서드 경고 등 예외·경고 경로 3곳에서 사용자 입력이 이스케이프 없이 `innerHTML`에 들어가고 있었습니다.
- **원인 (기존 파일:줄 근거)**
  1. 기존 `diagnose-core.js:401`, `706`에서 `getJsonErrorSnippet(e, bodyStr)`(사용자가 입력한 JSON 문제 행 원본 포함)을 `<div class="error-detail-box">...</div>` 문자열과 합쳐 반환했고, `app.js:235`, `308`에서 이를 `panel.innerHTML` / `errDiv.innerHTML`에 그대로 넣었습니다.
  2. 기존 `diagnose-core.js:465`에서 사용자 입력 `method`를 경고 문자열에 넣었고, `app.js:275-278`에서 `<li>${w}</li>` 문자열을 만들어 `wDiv.innerHTML`에 대입했습니다.
- **수정**
  - 코어 엔진([`js/core/diagnose.js`](../js/core/diagnose.js))에서 HTML 태그 문자열을 모두 빼고 `{ message, detail, hint, hintExample }` 형태의 데이터 객체만 반환하도록 바꿨습니다.
  - UI 렌더러([`js/ui/render.js`](../js/ui/render.js))에서 `innerHTML`을 모두 제거하고 `document.createElement`, `textContent`, `document.createTextNode`로만 DOM을 구성하도록 변경했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)에 `bodyStr: '{"xss": "<img src=x onerror=alert(1)>", broken}'` 및 `method: "<script>alert(1)</script>"`를 넣는 XSS 회귀 테스트를 추가하고, Mock DOM의 `set innerHTML` 감시를 통해 렌더링 중 `innerHTML` 호출이 0회인지 확인합니다.
- **정리**
  - 에러 메시지 줄바꿈이나 강조 표시를 편하게 하려고 코어 함수가 HTML 조각을 반환하기 시작하면 XSS 취약점이 생기기 쉽습니다. 코어는 데이터만 반환하고 태그 조립은 UI 계층에서만 처리하는 편이 안전합니다.

---

## 3. Node.js와 브라우저 간 Base64url 디코딩 차이 및 URL 에러 처리 실수

- **발견 (증상)**
  - 길이를 4로 나눈 나머지가 1인 잘못된 Base64url 문자열(예: `"abcde"`)을 넣었을 때 브라우저(`window.atob`)에서는 바로 예외가 났지만, Node.js(`Buffer.from(str, 'base64')`)에서는 예외 없이 넘어간 뒤 4단계 검증 실패로 처리되는 차이가 있었습니다.
  - 잘못된 URL을 입력했을 때 URL 에러 상세 상자에 URL 오류 메시지가 아니라 `getJsonErrorSnippet(e, bodyStr)` 결과가 출력되거나, `bodyStr`이 `undefined`일 때 `TypeError`가 발생했습니다.
- **원인 (기존 파일:줄 근거)**
  - 기존 `diagnose-core.js:55-68`의 `base64UrlDecode()`가 패딩 제거 후 `base64.length % 4 === 1` 여부를 확인하지 않고 Node.js의 `Buffer.from(..., 'base64')`에 그대로 넘겼습니다.
  - 기존 `diagnose-core.js:413`의 URL 파싱 `catch (e)` 블록에서 복사·붙여넣기 실수로 `${e.message}` 대신 `${getJsonErrorSnippet(e, bodyStr)}`를 호출하고 있었습니다.
- **수정**
  - [`js/core/encoding.js`](../js/core/encoding.js)의 `base64UrlDecode()`와 `base64StandardDecode()`에서 허용 문자 정규식과 `length % 4 === 1` 조건을 먼저 검사하도록 수정해 브라우저와 Node.js의 동작을 맞췄습니다.
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 URL `catch (e)` 블록에서 `detail: e.message`를 반환하도록 고쳤습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `bad-signature-length` (`signature: "abcde"`) 및 `bad-url` 케이스로 확인했습니다.
- **정리**
  - 브라우저(`atob`)와 Node.js(`Buffer.from`)에서 함께 쓰는 모듈은 런타임 내장 디코더의 예외 처리 방식에 의존하지 않고 입력 형식을 직접 검사해야 일관된 결과를 얻을 수 있습니다.

---

## 4. 잘못 통과하던 테스트 조건문과 `undefined.trim()` 오류

- **발견 (증상)**
  - 초기 상태에서 `node test.js`를 실행하면 `bad-url` 케이스에서 `TypeError: Cannot read properties of undefined (reading 'trim')`가 나며 테스트가 멈췄습니다.
  - 또한 `test.js`의 `inputTests` 검증 코드에 누락된 분기가 있어, 에러가 나지 않아야 할 케이스(`expectError: false`)에서 에러가 나도 통과(`passed++`)로 집계되고 있었습니다.
- **원인 (기존 파일:줄 근거)**
  - 기존 `diagnose-core.js:397`에서 `if (bodyStr.trim())`을 호출할 때 `inputs.bodyStr`이 생략(`undefined`)된 경우를 처리하지 않았습니다.
  - 기존 `test.js:61-65`에서 `if (t.expectError && !result.error) { ok = false; }`만 확인하고, `else if (!t.expectError && result.error)` 조건을 빠뜨렸습니다.
  - `test.js:30-35`의 픽스처 검증 루프에서도 `result.hypothesisResult.type === 'found'`일 때만 `expected.idStr`를 비교하고 5단계가 반환하던 `type === 'match'`일 때는 `idStr` 비교를 건너뛰고 있었습니다.
- **수정**
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 `normalizeInputs()`에서 모든 문자열 필드를 `String(safe.field ?? "")`로 정규화하고, `evalTime`이 비어 있거나 `NaN`일 때도 현재 시각으로 대체하도록 처리했습니다.
  - [`test/test.js`](../test/test.js)에서 `!t.expectError && result.error`일 때 실패로 기록하도록 고치고, 4·5단계 모든 매칭 케이스의 `idStr`를 비교하도록 수정했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `inputTests` 9종(`empty-inputs`, `bad-url`, `missing-nonce`, `long-input` 등) 통과로 확인했습니다.
- **정리**
  - 테스트 코드에서 반대 조건 분기가 빠져 있으면 실제 버그가 있어도 통과로 표시됩니다. 단언문은 성공 조건과 실패 조건 양쪽을 모두 확인해야 합니다.

---

## 5. `localStorage` 예외로 인한 초기화 중단

- **발견 (증상)**
  - 브라우저 설정에서 사이트 데이터 저장을 막았거나 `file://` 환경에서 `localStorage` 접근이 거부된 경우, 또는 `popDiagnoserSlots`에 깨진 JSON이 들어 있는 경우 페이지 로드 직후 초기화가 멈춰 `진단 시작`과 데모 버튼이 동작하지 않았습니다.
- **원인 (기존 파일:줄 근거)**
  - 기존 `app.js:36`의 `DOMContentLoaded` 핸들러 맨 위에서 `JSON.parse(localStorage.getItem('popDiagnoserSlots') || '{}')`를 `try/catch` 없이 실행했습니다. 여기서 `SecurityError`나 `SyntaxError`가 발생하면 같은 핸들러 아래쪽(`app.js:134-291`)의 버튼 이벤트 등록 코드까지 실행되지 않았습니다.
- **수정**
  - [`js/ui/slots.js`](../js/ui/slots.js)에 `readMemorySlots()`와 `writeMemorySlots()`를 두어 `localStorage` 접근과 `JSON.parse`를 모두 `try/catch`로 감쌌습니다.
  - 저장소 접근에 실패하면 예외를 던지지 않고 `{ ok: false, reason, data: {} }`를 반환해 버튼 이벤트 연결이 정상 진행되도록 했고, 사용자가 슬롯 저장·불러오기를 눌렀을 때만 토스트 메시지로 알리도록 바꿨습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)의 `storage-resilience` 테스트에서 `SecurityError`, `QuotaExceededError`, 깨진 JSON(`"{broken-json"`)을 주입해 예외가 밖으로 전파되지 않는지 확인했습니다.
- **정리**
  - 부가 기능(임시저장 슬롯)의 오류가 핵심 기능(서명 진단) 초기화까지 막아서는 안 됩니다. 특히 `file://` 환경에서는 `localStorage` 접근이 제한될 수 있다는 점을 고려해야 합니다.

---

## 6. ASN.1 DER → Raw(P1363) 변환(`derToRaw`) 경계 조건 버그

- **발견 (증상)**
  - 유효한 ECDSA P-256 ASN.1 DER 서명 중 길이가 68~69바이트인 서명이 `sig-der` 가설로 잡히지 않았고, 잘못된 DER 바이트 배열이 들어오면 `Uint8Array.prototype.set()`에서 `RangeError: offset is out of bounds`가 발생할 수 있었습니다.
- **원인 (기존 파일:줄 근거)**
  1. 기존 `diagnose-core.js:146`에서 `if (view.length < 70) return null;`로 고정되어 있었습니다. P-256의 `r`, `s` 정수는 최상위 비트가 `0`이거나 상위 바이트가 `0x00`일 때 패딩 바이트 없이 31~32바이트로 인코딩되므로 68~69바이트 길이의 유효한 DER 서명이 생성될 수 있습니다.
  2. 기존 `diagnose-core.js:154`에서 ASN.1 long-form 길이(`seqLen > 0x80`)를 읽을 때 `offset = 2 + numLenBytes + 1`로 `+ 1`을 잘못 더해 `r`의 `0x02`(INTEGER) 태그 위치를 1바이트 건너뛰는 오프셋 계산 실수가 있었습니다.
  3. `rLen` 또는 `sLen`이 선행 `0x00` 1바이트를 뺀 뒤에도 32바이트보다 클 때 길이 확인 없이 `raw.set(r, 32 - rLen)`을 호출해 음수 오프셋 `RangeError`가 날 수 있었습니다.
- **수정**
  - [`js/core/ecdsa.js`](../js/core/ecdsa.js)의 `derToRaw()`에서 최소 길이를 `MIN_DER_BYTES = 8`로 낮추고, long-form 오프셋을 `offset = 2 + numLenBytes`로 고쳤습니다.
  - 전체 시퀀스 길이(`offset + seqLen === view.length`), `s` 끝 오프셋(`sStart + sLen === view.length`), 선행 패딩 제거 후 `1 <= len <= 32` 여부와 불필요한 이중 `0x00` 패딩 여부를 확인하도록 수정했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)에 70바이트 미만 DER 서명을 생성해 진단하는 `hyp-sig-der-short-under-70b`와 `derToRaw` 단위 테스트 3건(`derToRaw-68b`, `derToRaw-long-form`, `derToRaw-invalid-33b`)을 추가했습니다.
- **정리**
  - 바이너리 포맷 파서(ASN.1 DER)를 작성할 때는 흔히 나오는 길이(70~72B)만 가정하지 않고 규격상 가능한 최소·최대 길이와 오프셋 경계를 함께 확인해야 합니다.

---

## 7. 문서 ↔ 코드 불일치를 확인한 방법과 추가 도구 구현

- **문서·코드 교차 확인**
  - 리팩토링 전에 `README.md`에 적힌 기능 설명을 항목별로 나누고, 실제 코드의 함수·줄 번호와 1:1로 대조했습니다.
  - 이 과정에서 `README.md`에는 적혀 있으나 매칭되지 않던 가설 4종(`query-unsorted`, `sig-base64url`, `digest-hex`, `newline-trailing`)과, 반대로 코드(`HYPOTHESES`)에는 있었으나 문서에 빠져 있던 가설 3종(`query-reverse`, `host-rewritten`, `body-bom-added`)을 찾아 문서와 테스트를 맞췄습니다.
- **진단 보조 기능 추가**
  - **서명 · 공개키 인스펙터 ([`js/core/inspect.js`](../js/core/inspect.js), [`js/ui/inspector.js`](../js/ui/inspector.js))**: 서명의 인코딩(`base64url` / 표준 `base64` / `hex`), `raw-rs(64B)` vs `der` 구조, `r`·`s` 값과 High-S 여부, 공개키의 SPKI OID(`ecPublicKey`, `P-256`), 타원곡선 위 좌표 검증(\(y^2 \equiv x^3 - 3x + b \pmod p\)), SHA-256 Fingerprint를 별도 패널에서 확인할 수 있게 추가했습니다.
  - **cURL / Raw HTTP 붙여넣기 파서 및 샘플 버튼 ([`js/core/curlParser.js`](../js/core/curlParser.js), [`js/ui/importer.js`](../js/ui/importer.js))**: `eval` 없이 동작하는 상태 기계 토크나이저로 브라우저 DevTools의 `Copy as cURL (bash)` 명령어와 Raw HTTP 요청을 파싱해 입력칸에 채우는 기능을 추가했습니다. 로컬 파일 참조(`-d @file`)나 셸 치환(`$(...)`) 등은 실행하지 않고 거부 사유를 안내하며, 바로 시험해 볼 수 있는 샘플 명령어 버튼 3종을 함께 구성했습니다.
  - **키보드 접근성 및 모바일 대응 ([`js/ui/tabs.js`](../js/ui/tabs.js), [`css/style.css`](../css/style.css))**: 탭 목록에 `role="tablist"`와 방향키·`Home`·`End` 키 이동(Roving `tabindex`)을 적용하고, 모든 `<label for>` 연결 여부를 [`test/test.js`](../test/test.js)에서 정적 검사하도록 추가했습니다.

---

## 8. 리팩토링 전·후 정량 지표 비교

아래 수치는 저장소 파일과 `node test.js` 실행 결과를 기준으로 집계한 값입니다.

| 지표 항목 | 리팩토링 전 (Phase 0 Baseline) | 현재 | 비고 |
| :--- | :--- | :--- | :--- |
| **`node test.js` 결과** | **16 통과 / 1 실패 / 실행 중 오류 중단** | **59 통과 / 0 실패** | `node test.js`, `node test/test.js`, `test.html` 동일 |
| **가설 카탈로그 동작 여부** | README 11개 중 **7개만 동작** (3개 불능, 1개 5단계 전용) + 미문서화 3개 | **13개 가설(14개 항목) 동작 및 개별 테스트 보유** | 항등 가설 `query-unsorted` 제거 및 문서 동기화 |
| **5단계 가설 UI 표시** | 매칭되어도 화면 미출력 (`type: 'match'` 불일치) | **4·5단계 모두 원인 설명 + Diff 출력** | 반환 스키마 `{ type: 'found', sets }` 통일 |
| **소스 파일 구성** | 루트 단일 파일 위주 (`diagnose-core.js` 782줄, `app.js` 465줄, `style.css` 479줄) | **역할별 15개 UMD 모듈 + `css/style.css` 분리** | `js/core/`(8개), `js/ui/`(6개), `js/app.js`(1개) |
| **진단 보조 기능** | 데모 시나리오 5종 및 테스트 서명 생성기 | **+ 서명·공개키 인스펙터, cURL/Raw HTTP 파서(샘플 3종), 키보드 탭 접근성** | 기존 진단 파이프라인 결과 불변 유지 |
| **`innerHTML` 사용 건수** | **10건** (이 중 사용자 입력 삽입 XSS 3건) | **0건** | 전체 `createElement` / `textContent` 사용 |
| **`el.style.*` / `!important`** | `el.style.*` **27건**, CSS `!important` **12건** | **각 0건** | CSS 클래스 토글(`.hidden`, `.toast-visible` 등)로 통일 |
