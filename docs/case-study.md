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
  - [`js/core/hypotheses.js`](../js/core/hypotheses.js)에서 4단계와 5단계 가설을 하나의 테이블(`HYPOTHESES`, `{ id, label, tag, stage, cause, solution, apply }`)로 합치고, 5단계 매칭 반환 구조도 `{ type: 'found', sets: [...], reduced: false }`로 통일했습니다.
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
  - [`js/core/ecdsa.js`](../js/core/ecdsa.js)의 `parseDerSignature()`(및 이를 호출하는 `derToRaw()`)에서 최소 길이를 `MIN_DER_BYTES = 8`로 낮추고, long-form 오프셋을 `offset = 2 + numLenBytes`로 고쳤습니다.
  - 전체 시퀀스 길이(`offset + seqLen === view.length`), `s` 끝 오프셋(`sStart + sLen === view.length`), 선행 패딩 제거 후 `1 <= len <= 32` 여부와 불필요한 이중 `0x00` 패딩 여부를 확인하도록 수정했습니다.
- **회귀 테스트**
  - [`test/test.js`](../test/test.js)에 70바이트 미만 DER 서명을 생성해 진단하는 `hyp-sig-der-short-under-70b`와 `derToRaw` 단위 테스트 3건(`derToRaw-68b`, `derToRaw-long-form`, `derToRaw-invalid-33b`)을 추가했습니다.
- **정리**
  - 바이너리 포맷 파서(ASN.1 DER)를 작성할 때는 흔히 나오는 길이(70~72B)만 가정하지 않고 규격상 가능한 최소·최대 길이와 오프셋 경계를 함께 확인해야 합니다.

---

## 7. 비-JSON 본문 진단 차단 및 1단계 실행 순서 역전

- **문제**
  - `diagnose()`가 1단계(필수 헤더·입력 유무 확인)보다 먼저 `validateJsonBody()`를 실행하고, `bodyStr`이 비어 있지 않으면 `JSON.parse`를 통과해야만 진단을 진행했습니다.
  - 게이트웨이는 본문을 바이트 스트림으로 SHA-256 해시할 뿐 JSON만 허용하지 않는데도, 평문(`"hello"`, `"Plain text log [OK]"`)이나 `form-urlencoded` 본문이 들어오면 `golden_pass.js`와 1~5단계 진단 및 `generateTestSignature()`가 중단되었습니다.
- **원인**
  - [`js/core/diagnose.js`](../js/core/diagnose.js)에서 JSON 문법 보조 검사를 치명적 입력 오류(`result.error` 및 `throw`)로 취급하고 1단계 필수 항목 점검보다 앞단에 배치했습니다.
- **수정**
  - `diagnose()` 실행 순서를 `1단계(필수 입력 확인) → 입력 형식 검사(URL·공개키·서명·타임스탬프) → 2~5단계 검증`으로 바로잡았습니다.
  - `looksLikeJson(bodyStr, contentType)`을 정교화해 `Content-Type`이 비-JSON 계열이면 즉시 제외하고, `Content-Type`이 없을 때는 `{`/`[`로 시작하거나 `}`로 끝나면서 `"키":` 패턴이 있는 경우, 또는 `]`로 끝나면서 따옴표·숫자·`{`·`[`로 시작하는 경우에만 `validateJsonBody()`를 수행하도록 했습니다. 문법 오류 시 `diagnose()`는 `result.warnings`(`WARNING_CODES.INVALID_JSON`, `'ERR_INVALID_JSON'`)로, `generateTestSignature()`는 반환 객체의 `warning` 필드로 비차단 안내를 기록합니다.
- **교훈**
  - 사용자 편의를 위한 휴리스틱 검사(JSON 문법 힌트)가 프로토콜의 본질적 검증(바이트 스트림 해시 및 서명 생성·검증)을 가로막아서는 안 됩니다.

---

## 8. 메인 진단기와 인스펙터 간 파서·판별기 이원화 및 비밀키 추출 가능 설정

- **문제**
  1. 128자리 Hex 서명을 넣으면 인스펙터는 `hex (64B)`로 판정하는 반면 메인 진단기는 `base64url (96B)`로 디코딩해 길이 오류를 냈고, `=` 패딩이 붙은 표준 Base64 서명(우연히 `+`, `/` 미포함)이 `base64UrlDecode()`를 그대로 통과했습니다.
  2. `importPublicKey()`와 `inspectPublicKey()`, `derToRaw()`와 `inspectDerStructure()`가 각각 따로 구현되어 있어 비최소 DER 정수(`02 02 00 05`), 역순 PEM 헤더, `PRIVATE KEY` 입력에 대해 서로 다른 판정을 내렸습니다.
  3. `generateKeyPairAndSign()`이 `extractable: true`로 키쌍을 생성해 비밀키가 메모리에서 내보내기 가능한 상태였습니다.
- **원인**
  - 인스펙터 기능을 추가할 때 기존 코어 파서를 재사용하지 않고 별도 정규식·바이트 파서를 중복 작성하면서 경계 조건이 갈라졌습니다.
- **수정**
  - [`js/core/inspect.js`](../js/core/inspect.js)의 `detectAndDecodeSignature()`(내부적으로 [`js/core/encoding.js`](../js/core/encoding.js)의 패딩 없는 `base64UrlDecode()` 및 `base64StandardDecode()` 사용, 메인 진단기의 `decodeSignatureWithFallback()`과 인스펙터의 `inspectSignature()`가 공유)와 [`js/core/ecdsa.js`](../js/core/ecdsa.js)의 `parseDerSignature()`(`derToRaw()`와 `inspectDerStructure()`가 공유), `extractPublicKeySpkiBytes()` 및 `containsPrivateKeyMarker()`(`importPublicKey()`와 `inspectPublicKey()`가 공유)로 파서를 단일화해 메인 진단기와 인스펙터가 동일한 판정을 내리도록 통합했습니다.
  - `PRIVATE KEY` PEM 입력 시 즉시 `PRIVATE_KEY_REJECTED`로 거부하고, `generateKeyPairAndSign()`의 `generateKey` 호출을 `extractable: false`로 고정했습니다.
- **교훈**
  - 같은 입력 포맷(Base64url/Hex, ASN.1 DER, SPKI PEM)을 다루는 진단 로직과 시각화 인스펙터는 반드시 단일 파서 함수를 공유해야 판정 모순을 막을 수 있습니다.

---

## 9. BFS 가설 탐색의 순열·상태 중복 검증 및 4·5단계 복합 탐색 누락

- **문제**
  - 깊이 3 BFS에서 가설 집합 `{A, B, C}`가 6가지 순서로 중복 탐색되어 `WebCrypto.subtle.verify`(`verifySig`)가 불필요하게 반복 호출되었고, `path-trailing-slash-add` 뒤 `path-trailing-slash-remove`처럼 원래 상태로 되돌아가는 역연산 조합도 재검증되었습니다.
  - 5단계는 깊이 1 단일 가설만 순회해 `body-bom-added + digest-hex` 같은 복합 원인을 찾지 못했고, 4·5단계 동시 실패(`both-fail`) 시 4단계만 탐색해 5단계 원인이 누락되었습니다.
- **원인**
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 BFS 큐가 조합 인덱스 순서나 `(canonical, signature)` 상태 중복을 관리하지 않았고, 5단계 탐색이 단순 1중 루프로 작성되어 있었습니다.
- **수정**
  - `searchStage4Hypotheses()`와 `searchStage5Hypotheses()`에서 별도의 역연산 배제 테이블을 두는 대신, 조합 인덱스 오름차순(`startIdx`)과 상태 캐시(`stateCache`: 4단계 `${nextCanonical}|${nextSigHex}`, 5단계 `${nextReq.rawBody}|${nextReq.bodyHash}`)를 결합해 중복을 제거했습니다. 루트 상태를 깊이 0으로 `stateCache`에 미리 등록하고 더 얕은 깊이에서 이미 방문한 상태(`cached.depth < nextDepth`)는 건너뛰므로, 역연산 쌍 적용으로 이전 상태(깊이 0 등)로 되돌아가는 경로가 자동으로 가지치기됩니다. 또한 같은 깊이(`cached.depth === nextDepth`)에서 동일 상태로 수렴하는 경우에는 캐시된 검증 결과(`cached.verified`)를 재사용해 동일 상태에 대한 `verifySig()` 재호출을 0회로 줄이면서 구분 불가(`indistinguishable`) 후보 경로는 보존했습니다(일반 최악 입력 시 탐색 루프 내 63회·4단계 초기 검증 포함 총 64회 호출, `outside-catalog` 입력 시 총 26회 호출).
  - `STAGE4_HYPOTHESIS_PRIORITY`를 통해 `sig-base64url`을 `sig-der`보다 앞에 배치해 순서 의존 쌍이 정상 동작하도록 보장하고, 5단계에도 깊이 1~3 BFS 조합 탐색(`STAGE5_HYPOTHESIS_PRIORITY`)을 도입했으며, 4·5단계 동시 실패 시 두 단계의 탐색 결과를 모두 반환·렌더링(`mergeStage4AndStage5Sets()`)하도록 개선했습니다.
- **교훈**
  - 탐색 공간이 작더라도 조합 인덱스(`startIdx`)와 상태 캐시(`stateCache`)로 순열 중복과 회귀(역연산)·항등 전이를 제거해야 상한(`maxSearchNodes: 100`, `maxComboDepth: 3`)이 의미를 가지며, 순서에 의존하는 전이 쌍은 카탈로그 우선순위와 테스트로 명시해야 합니다.

---

## 10. WHATWG `new URL()`의 기본 포트(`:443`) 제거와 `host-rewritten` 오작동

- **문제**
  - `https://api.example.com:443/v1/tx`를 입력해도 `new URL()`이 기본 포트 `:443`을 자동 제거해 `baseReq.host`에서 `:443`이 사라졌고, 반대로 커스텀 포트(`:8443`)나 IPv6 호스트(`[::1]`)는 `newHost.split(':')[0]` 때문에 포트가 잘리거나 호스트 문자열이 깨졌습니다.
- **원인**
  - WHATWG URL 파서의 기본 포트 정규화 동작을 고려하지 않고 `urlObj.host`를 그대로 썼으며, `host-rewritten` 가설이 단순 `split(':')`으로 작성되어 있었습니다.
- **수정**
  - [`js/core/diagnose.js`](../js/core/diagnose.js)의 `extractEffectiveHost()`로 원문 URL에 `:443`이 명시되었는지 보존(`diagnose()` 및 `generateTestSignature()` 모두 적용)하고, [`js/core/hypotheses.js`](../js/core/hypotheses.js)의 `host-rewritten`은 IPv6 브래킷과 커스텀 포트를 보존한 채 기본 포트 `:443`의 유무만 양방향 토글하도록 수정했습니다.
- **교훈**
  - 표준 URL 파서는 프로토콜 기본 포트를 정규화하므로, 원문 문자열 자체가 서명 대상이 되는 프로토콜에서는 파서 정규화 전 원문 토큰을 별도로 추출해야 합니다.

---

## 11. 줄바꿈(`CRLF` ↔ `LF`) 단방향 가설 및 브라우저 `<textarea>` 개행 정규화

- **문제**
  - 5단계 `newline-crlf` 가설이 `\n → \r\n` 단방향 변환만 수행해, 본문이 `\r\n`이고 클라이언트가 `\n`으로 해시한 반대 경우를 탐지하지 못했습니다.
  - 또한 HTML 표준상 `<textarea>`는 값을 읽을 때 `\r\n`을 `\n`으로 정규화하고 `app.js`도 `.replace(/\r\n/g, '\n')`을 수행해, cURL/Raw HTTP 파서가 보존한 `\r\n`이 브라우저에서 유실되었습니다.
- **원인**
  - 5단계 가설이 입력 본문을 항상 LF라고 가정했고, 브라우저 DOM `<textarea>`의 개행 정규화 명세를 고려하지 않았습니다.
- **수정**
  - 5단계 `newline-crlf`를 양방향 토글(`\r\n` 포함 시 `\n`으로, 미포함 시 `\r\n`으로 변환)로 수정했습니다.
  - [`js/ui/importer.js`](../js/ui/importer.js)에 `setRawTextareaValue()` / `readRequestBody()` 헬퍼를 두고 [`js/ui/slots.js`](../js/ui/slots.js)의 슬롯 저장·불러오기에서도 `_rawBody`를 함께 보존해, 파서·샘플·슬롯이 주입한 원본 본문(`\r\n` 포함)을 사용자가 직접 편집하기 전까지 진단기에 그대로 전달하며 `<textarea>`의 LF 정규화 한계를 UI 배너와 `README.md`에 명시했습니다.
- **교훈**
  - 바이트 단위 해시를 진단하는 웹 도구에서는 HTML 폼 요소(`<textarea>`)의 자동 정규화 동작과 메모리 원본 값을 분리해 다루어야 합니다.

---

## 12. 코어 → UI 역의존, UI 다중 가설 렌더링 누락 및 파이썬 검증 도구 결함

- **문제**
  1. `core/diagnose.js`가 `../ui/jsonError.js` 및 `root.PopUI`를 참조하는 역방향 의존성이 있었고, `index.html`이 테스트 픽스처(`test/fixtures/fixtures.js`)를 운영 스크립트로 직접 로드했습니다.
  2. [`js/ui/render.js`](../js/ui/render.js)가 `hRes.sets[0]`만 렌더링하고 `sets[1..n]`을 버렸으며, `indistinguishable`일 때 첫 후보의 해결 가이드만 표시하고, Diff 뷰의 `actual`/`expected` CSS 클래스가 반대로 붙어 있었습니다.
  3. [`tools/generate_fixtures.py`](../tools/generate_fixtures.py)의 `wrong-key` 픽스처가 DER 서명(~71B)과 리터럴 `\\n`을 사용해 키 불일치가 아닌 서명 길이 오류로 실패했고, [`tools/check_encoding.py`](../tools/check_encoding.py)는 인코딩 이상 발견 시에도 종료 코드 `0`을 반환했습니다.
- **원인**
  - 모듈 분리 시 데이터 추출(`extractJsonErrorLocation`)과 시각 포맷팅(`formatJsonErrorSnippet`)의 경계를 나누지 않았고, UI 렌더러가 단일 매칭 케이스만 가정해 배열의 첫 원소(`[0]`)만 참조했습니다.
- **수정**
  - JSON 오류 위치·원인 데이터 추출은 [`js/core/jsonError.js`](../js/core/jsonError.js)로, 전각 폭 보정 포인터(`▲`) 문자열 조립은 [`js/ui/jsonError.js`](../js/ui/jsonError.js)로 분리하고, 운영용 데모 데이터는 [`js/ui/samples.js`](../js/ui/samples.js)로 독립시켰습니다.
  - `renderHypothesisSection()`이 모든 `sets`와 4·5단계 동시 실패 결과를 렌더링하고, `indistinguishable` 후보 전체의 가이드를 중복 없이 표시하며, Diff 행의 `actual`(`-` 빨강) / `expected`(`+` 초록) 클래스를 일치시켰습니다.
  - `generate_fixtures.py`의 `wrong-key`가 `make_fixture(..., signer=sim2)`를 재사용하도록 고쳐 14개 픽스처를 재생성하고, `differential_check.py`는 단일 `node` 호출 + `tempfile` 정리 방식으로 개선했으며, `check_encoding.py`는 이상 발견 시 `sys.exit(1)`을 반환하도록 수정하고 CI 워크플로우에 추가했습니다.
- **교훈**
  - 코어/UI 계층 분리, 테스트 픽스처의 실제 실패 코드 검증, 정적 검사 스크립트의 종료 코드(`exit 1`)는 자동화 테스트로 고정해 두어야 회귀를 막을 수 있습니다.

---

## 13. 문서 ↔ 코드 교차 확인 및 진단 보조 도구 요약

- **문서·코드 교차 확인**
  - `README.md`에 적힌 기능·수치·흐름도를 실제 코드의 함수와 1:1로 대조해 불일치 항목(실행 순서, 5단계 BFS 조합 탐색, 4·5단계 동시 실패 처리, `maxSearchNodes: 100`, 모듈 개수, `:443` 토글 범위, `<textarea>` 줄바꿈 한계 등)을 모두 동기화했습니다.
- **진단 보조 기능**
  - **서명 · 공개키 인스펙터 ([`js/core/inspect.js`](../js/core/inspect.js), [`js/ui/inspector.js`](../js/ui/inspector.js))**: 서명의 인코딩(`base64url` / 표준 `base64` / `hex`), `raw-rs(64B)` vs `der` 구조, `r`·`s` 값과 High-S 여부, 공개키의 SPKI OID(`ecPublicKey`, `P-256`), 타원곡선 위 좌표 검증(\(y^2 \equiv x^3 - 3x + b \pmod p\)), SHA-256 Fingerprint를 별도 패널에서 확인합니다.
  - **cURL / Raw HTTP 붙여넣기 파서 및 샘플 버튼 ([`js/core/curlParser.js`](../js/core/curlParser.js), [`js/ui/importer.js`](../js/ui/importer.js))**: `eval` 없이 동작하는 상태 기계 토크나이저(`tokenizeShellCommand()`, `parseCurl()`, `parseRawHttp()`)로 브라우저 DevTools의 `Copy as cURL (bash)` 명령어와 Raw HTTP 요청(`Content-Type` 포함)을 파싱해 입력칸에 채웁니다.
  - **키보드 접근성 및 모바일 대응 ([`js/ui/tabs.js`](../js/ui/tabs.js), [`css/style.css`](../css/style.css))**: 탭 목록에 `role="tablist"`와 방향키·`Home`·`End` 키 이동(Roving `tabindex`)을 적용하고, 모든 `<label for>` 연결 여부를 [`test/test.js`](../test/test.js)에서 정적 검사합니다.

---

## 14. 리팩토링 전·후 정량 지표 비교

아래 수치는 저장소 파일과 `node test.js` 실행 결과를 기준으로 집계한 값입니다.

| 지표 항목 | 리팩토링 전 | 현재 | 비고 |
| :--- | :--- | :--- | :--- |
| **`node test.js` 결과** | **16 통과 / 1 실패 / 실행 중 오류 중단** | **82 통과 / 0 실패 / 0 건너뜀** | 브라우저(`test.html`)는 Node `fs` 전용 1건 제외 **81 통과 / 1 건너뜀 (총 82건)** |
| **가설 카탈로그 동작 여부** | README 11개 중 **7개만 동작** (3개 불능, 1개 5단계 전용) + 미문서화 3개 | **14개 가설(4단계 10개 · 5단계 6개, 겸용 2개 포함) 동작 및 고정 벡터 테스트 보유** | 항등 가설 `query-unsorted` 제거, 4·5단계 최대 깊이 3 BFS 조합 탐색 |
| **4·5단계 가설 UI 표시** | 5단계 매칭 미출력, `sets[0]`만 출력, Diff 색상 반대 | **4·5단계 동시 표시, 모든 `sets` 및 후보 가이드 출력, Diff 색상 일치** | 반환 스키마 `{ type: 'found', sets }` 통일 |
| **소스 파일 구성** | 루트 단일 파일 위주 (`diagnose-core.js` 782줄, `app.js` 465줄, `style.css` 479줄) | **역할별 17개 스크립트 모듈 + `css/style.css` 분리** | `js/core/`(9개), `js/ui/`(7개), `js/app.js`(1개), 코어→UI 역의존 0건 |
| **진단 보조 기능** | 데모 시나리오 5종 및 테스트 서명 생성기 | **데모 7종 + 서명·공개키 인스펙터 + cURL/Raw HTTP 파서 + 키보드 접근성** | 기존 진단 파이프라인 결과 불변 유지 |
| **`innerHTML` 사용 건수** | **10건** (이 중 사용자 입력 삽입 XSS 3건) | **0건** | 전체 `createElement` / `textContent` 사용 |
| **`el.style.*` / `!important`** | `el.style.*` **27건**, CSS `!important` **12건** | **각 0건** | CSS 클래스 토글(`.hidden`, `.toast-visible` 등)로 통일 |
