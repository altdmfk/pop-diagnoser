# PoP Diagnoser (Proof of Possession Gateway 401 진단기)

## 개요
API가 `401 Unauthorized` 또는 `403 Forbidden`을 반환할 때, 서명(Proof of Possession) 검증 과정 중 어느 단계에서 실패했는지 오프라인에서 진단하는 도구입니다.

### 이 앱이 하는 일
- 서명 문자열(Canonical Payload)을 재구성하여 서명 수학(ECDSA Math) 검증 수행
- 실패 시 다양한 가설(실수 패턴)을 탐색하여 일치하는 가설(최소 일치 집합) 제시
- 타임스탬프, Nonce, 본문 해시 등 각 단계별 독립적인 검증 상태 안내

### 이 앱이 하지 않는 일
- 외부 서버나 API로 데이터를 전송하지 않음 (네트워크 요청 0건)
- Nonce의 실제 소비(사용) 여부 판단 (서버 상태가 필요하므로 판단 불가 처리)
- 비밀키 입력 요구 (이 도구는 **공개키**와 **서명된 결과값**만 사용합니다)

## 범위 한정
📌 이 도구는 논문 **"Design and Performance Analysis of a FIDO2 Hardware-Isolated Key-Based Proof-of-Possession Reverse Proxy Gateway"** 형식으로 서명된 요청 전용입니다. 다른 포맷이나 규칙을 사용하는 게이트웨이 요청에는 적합하지 않을 수 있습니다.

## 실행 방법
1. 로컬 환경에서 `index.html` 파일을 더블클릭하여 웹 브라우저로 엽니다. (빌드 과정이나 웹 서버가 필요하지 않습니다. `file://` 프로토콜로 동작합니다.)
2. **Network 탭을 열고 붙여넣어도 요청이 0건인지 확인**: 브라우저 개발자 도구(F12)의 Network 탭을 열어둔 상태로 진단 버튼을 눌러보세요. 어떠한 외부 통신도 발생하지 않음을 직접 확인할 수 있습니다.

## 가설 카탈로그와 출처 태그
서명이 실패했을 때 앱이 탐색하는 가설 목록입니다:
- `[흔한 실수]` 쿼리를 정렬하지 않음 (`query-unsorted`)
- `[흔한 실수]` 쿼리를 알파벳순 정렬 (`query-sorted`)
- `[흔한 실수]` HTTP 메서드 소문자 사용 (`method-lowercase`)
- `[흔한 실수]` Path 끝에 슬래시(/) 추가/제거 (`path-trailing-slash-add`, `path-trailing-slash-remove`)
- `[흔한 실수]` JSON 공백 제거 후 해시 (`body-reserialized-nospace`)
- `[인코딩]` 본문 해시를 Base64url로 인코딩 (`digest-base64url`)
- `[인코딩]` 본문 해시를 Hex로 인코딩 (`digest-hex`)
- `[인코딩]` 서명이 DER 형식으로 인코딩됨 (`sig-der`)
- `[인코딩]` 서명 디코딩 변형 (Base64url) (`sig-base64url`)
- `[논문 규칙]` 항목 구분을 CRLF(\r\n)로 사용 (`newline-crlf`)
- `[논문 규칙]` 마지막에 줄바꿈 추가 (`newline-trailing`)

## 테스트 실행법
Node.js(v20 이상)가 설치된 환경에서 다음 명령어로 독립적인 테스트 픽스처를 실행할 수 있습니다.
```bash
python generate_fixtures.py  # (선택) 픽스처 데이터 갱신
node test.js                 # 테스트 러너 실행
```

## 알려진 한계
- **카탈로그 밖 실수**: 카탈로그에 없는 실수나 3개 이상의 오류가 복합된 경우 "일치 없음"으로 표시될 수 있습니다.
- **중간 계층 변형**: 프록시, CDN, 또는 웹 프레임워크가 전달 과정에서 URL이나 본문을 은연중에 변형한 경우, 클라이언트가 서명한 원본을 파악하기 어려울 수 있습니다.


- **범위 밖**: 게이트웨이가 검사하는 Authorization 헤더의 JWT 디코딩 및 바인딩 검증은 서버 상태가 필요하므로 제외됩니다.

- **논문 vs 구현 차이**: 논문은 4단계 다이제스트 대조, 5단계 서명 검증을 제안하나, 실제 게이트웨이 코드는 자원 고갈 공격을 막기 위해 서명 검증(4) 후 다이제스트 스트리밍(5) 순으로 실행하며 본 앱은 실제 코드를 따릅니다.
