(function (root, factory) {
    const profileMod = (typeof module !== 'undefined' && module.exports)
        ? require('./profiles/paper.js')
        : root.PopCore;
    const encoding = (typeof module !== 'undefined' && module.exports)
        ? require('./encoding.js')
        : root.PopCore;
    const ecdsa = (typeof module !== 'undefined' && module.exports)
        ? require('./ecdsa.js')
        : root.PopCore;
    const mod = factory(profileMod, encoding, ecdsa);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (profileMod, encoding, ecdsa) {
    const STAGE_IDS = (profileMod && profileMod.STAGE_IDS) || { SIGNATURE: 4, DIGEST: 5 };
    const { hashString, hashStringToBase64Url } = encoding;
    const { derToRaw } = ecdsa;

    const HYPOTHESES = [
        {
            id: 'query-sorted',
            label: '쿼리를 알파벳순 정렬',
            tag: 'common-mistake',
            stage: STAGE_IDS.SIGNATURE,
            cause: "요청 URL의 쿼리 파라미터를 알파벳순(c=3&a=1&b=2 ➔ a=1&b=2&c=3)으로 정렬하여 서명했습니다.",
            solution: "FIDO2 PoP 게이트웨이는 쿼리를 정렬하지 않습니다. 클라이언트에서 쿼리 정렬 로직을 제거하고 요청 URL에 표기된 순서 그대로 서명 대상 문자열에 포함하세요.",
            apply: async (req) => {
                if (!req.query) return req;
                const sorted = req.query.split('&').sort().join('&');
                return { ...req, query: sorted };
            }
        },
        {
            id: 'query-reverse',
            label: '쿼리를 역순으로 뒤집음',
            tag: 'common-mistake',
            stage: STAGE_IDS.SIGNATURE,
            cause: "요청 URL의 쿼리 파라미터 순서가 역순으로 뒤집혀 서명되었습니다.",
            solution: "쿼리 파라미터를 임의로 뒤집지 말고 실제 전송되는 URL의 파라미터 순서 그대로 서명하세요.",
            apply: async (req) => {
                if (!req.query) return req;
                return { ...req, query: req.query.split('&').reverse().join('&') };
            }
        },
        {
            id: 'method-lowercase',
            label: 'HTTP 메서드를 소문자로 사용',
            tag: 'common-mistake',
            stage: STAGE_IDS.SIGNATURE,
            cause: "HTTP 메서드가 소문자(예: 'post', 'get')로 서명되었습니다.",
            solution: "FIDO2 PoP 규격은 HTTP 메서드를 반드시 대문자(예: 'POST', 'GET')로 요구합니다. 서명 대상 문자열의 첫 줄을 대문자 메서드로 변경하세요.",
            apply: async (req) => ({ ...req, method: req.method.toLowerCase() })
        },
        {
            id: 'path-trailing-slash-add',
            label: 'Path 끝에 슬래시(/) 추가',
            tag: 'common-mistake',
            stage: STAGE_IDS.SIGNATURE,
            cause: "URL 경로 끝에 요청과 달리 슬래시('/')가 추가된 채 서명되었습니다 (예: '/v1/tx/').",
            solution: "실제 요청 URL 경로와 서명 대상 경로가 정확히 일치해야 합니다. 서명 대상 경로 끝의 불필요한 슬래시('/')를 제거하세요.",
            apply: async (req) => ({ ...req, path: req.path.endsWith('/') ? req.path : req.path + '/' })
        },
        {
            id: 'path-trailing-slash-remove',
            label: 'Path 끝에 슬래시(/) 제거',
            tag: 'common-mistake',
            stage: STAGE_IDS.SIGNATURE,
            cause: "URL 경로 끝의 슬래시('/')가 누락된 채 서명되었습니다 (예: '/v1/tx').",
            solution: "실제 요청 URL 경로 끝에 슬래시('/')가 있다면 서명 대상 경로에도 슬래시를 동일하게 유지하세요.",
            apply: async (req) => ({ ...req, path: req.path.endsWith('/') && req.path.length > 1 ? req.path.slice(0, -1) : req.path })
        },
        {
            id: 'host-rewritten',
            label: 'Host 기본 포트(:443) 누락 또는 추가',
            tag: 'common-mistake',
            stage: STAGE_IDS.SIGNATURE,
            cause: "Host 헤더에 기본 HTTPS 포트 번호(':443')가 잘못 붙었거나 누락되어 서명되었습니다.",
            solution: "FIDO2 PoP 게이트웨이는 Host에 포트 번호(':443') 없이 도메인 이름만 사용합니다. 서명 대상 Host 값에서 ':443'을 제거하세요.",
            apply: async (req) => {
                const host = String(req.host || '');
                if (!host || host.startsWith('[') || host.includes(']')) {
                    return req;
                }
                const colonIdx = host.indexOf(':');
                if (colonIdx === -1) {
                    return { ...req, host: host + ':443' };
                }
                if (host.slice(colonIdx) === ':443') {
                    return { ...req, host: host.slice(0, colonIdx) };
                }
                return req;
            }
        },
        {
            id: 'sig-der',
            label: '서명이 DER 형식으로 인코딩됨',
            tag: 'encoding',
            stage: STAGE_IDS.SIGNATURE,
            cause: "서명값이 ECDSA 기본 ASN.1 DER 형식(약 70~72바이트)으로 전송되었습니다.",
            solution: "FIDO2 PoP 게이트웨이는 IEEE P1363 Raw(64바이트: r 32바이트 + s 32바이트) 형식을 요구합니다. 클라이언트 서명 라이브러리에서 DER 헤더를 제거하고 r과 s를 각각 32바이트 고정 길이로 추출해 이어 붙인 뒤(총 64바이트) Base64url 인코딩하세요.",
            apply: async (req) => {
                const raw = derToRaw(req.rawSignature);
                if (!raw) return req;
                return { ...req, parsedSignature: raw };
            }
        },
        {
            id: 'sig-base64url',
            label: '서명 디코딩 변형 (표준 Base64 사용)',
            tag: 'encoding',
            stage: STAGE_IDS.SIGNATURE,
            cause: "서명 문자열에 표준 Base64 문자('+', '/', '=')가 사용되었습니다.",
            solution: "FIDO2 PoP 규격은 Base64url(RFC 7515) 인코딩을 요구합니다. 서명 문자열에서 '+'를 '-'로, '/'를 '_'로 치환하고 끝의 패딩 문자('=')를 제거하세요.",
            apply: async (req) => {
                if (!req.stdBase64Signature) return req;
                return {
                    ...req,
                    rawSignature: req.stdBase64Signature,
                    parsedSignature: req.stdBase64Signature
                };
            }
        },
        {
            id: 'newline-crlf',
            label: '항목 구분 또는 본문 줄바꿈을 CRLF(\\r\\n)로 사용',
            tag: 'paper-rule',
            stage: 'both',
            cause: "항목 구분자 또는 본문에 윈도우 스타일 줄바꿈(CRLF, '\\r\\n')이 사용되었거나 본문 줄바꿈(LF ↔ CRLF)이 해시 계산 시점과 달라졌습니다.",
            solution: "FIDO2 PoP 게이트웨이는 Unix 스타일 줄바꿈(LF, '\\n')만을 허용합니다. 서명 대상 문자열 및 본문 해시 계산 전에 모든 '\\r\\n'을 '\\n'으로 정규화하세요.",
            apply: async (req, stage) => {
                if (stage === STAGE_IDS.DIGEST) {
                    const rawBody = String(req.rawBody ?? '');
                    const toggledBody = rawBody.includes('\r\n')
                        ? rawBody.replace(/\r\n/g, '\n')
                        : rawBody.replace(/\n/g, '\r\n');
                    if (toggledBody === rawBody) return req;
                    return { ...req, rawBody: toggledBody, bodyHash: await hashString(toggledBody) };
                }
                return { ...req, delimiter: '\r\n' };
            }
        },
        {
            id: 'newline-trailing',
            label: '마지막에 줄바꿈(\\n) 추가',
            tag: 'paper-rule',
            stage: 'both',
            cause: "서명 대상 문자열 맨 끝에 불필요한 줄바꿈('\\n')이 한 번 더 추가되었습니다.",
            solution: "서명 대상 문자열의 맨 마지막 줄 뒤에는 줄바꿈('\\n')을 추가하지 않아야 합니다. 마지막 항목(Body-Digest) 뒤의 줄바꿈을 제거하세요.",
            apply: async (req, stage) => {
                if (stage === STAGE_IDS.DIGEST) {
                    const trailingBody = req.rawBody + '\n';
                    return { ...req, rawBody: trailingBody, bodyHash: await hashString(trailingBody) };
                }
                return { ...req, trailingNewline: true };
            }
        },
        {
            id: 'digest-base64url',
            label: '본문 해시를 Base64url로 인코딩',
            tag: 'encoding',
            stage: STAGE_IDS.DIGEST,
            cause: "본문 해시(X-Body-Digest)가 Base64url로 인코딩되었습니다.",
            solution: "FIDO2 PoP 게이트웨이는 본문 해시를 'sha256=' 접두사와 64자리 소문자 16진수(Hex)로 요구합니다 (예: 'sha256=11abf1...'). Base64url 대신 소문자 Hex로 변환하세요.",
            apply: async (req) => ({
                ...req,
                bodyHash: await hashStringToBase64Url(req.rawBody)
            })
        },
        {
            id: 'digest-hex',
            label: '본문 해시를 대문자 Hex로 인코딩',
            tag: 'encoding',
            stage: STAGE_IDS.DIGEST,
            cause: "본문 해시(X-Body-Digest)가 대문자 Hex로 인코딩되었습니다.",
            solution: "본문 해시는 반드시 소문자 16진수(Hex, '0-9a-f')를 사용해야 합니다. 해시값을 소문자로 변환하세요.",
            apply: async (req) => {
                const lowerHex = await hashString(req.rawBody);
                if (req.targetDigest && req.targetDigest.toLowerCase() === lowerHex && req.targetDigest !== lowerHex) {
                    return { ...req, bodyHash: req.targetDigest };
                }
                return { ...req, bodyHash: lowerHex.toUpperCase() };
            }
        },
        {
            id: 'body-bom-added',
            label: '본문 앞에 UTF-8 BOM(\\uFEFF) 추가 후 해시',
            tag: 'common-mistake',
            stage: STAGE_IDS.DIGEST,
            cause: "본문 앞부분에 보이지 않는 UTF-8 BOM('\\uFEFF', 0xEF 0xBB 0xBF) 바이트가 포함된 채 해시되었습니다.",
            solution: "본문 앞에 BOM이 붙지 않도록 BOM 없는 UTF-8(UTF-8 without BOM)으로 저장 및 전송하세요.",
            apply: async (req) => {
                const bomBody = '\uFEFF' + req.rawBody;
                return {
                    ...req,
                    rawBody: bomBody,
                    bodyHash: await hashString(bomBody)
                };
            }
        },
        {
            id: 'body-reserialized-nospace',
            label: 'JSON 공백 제거 후 해시',
            tag: 'common-mistake',
            stage: STAGE_IDS.DIGEST,
            cause: "클라이언트가 JSON 본문의 공백을 모두 제거(JSON.stringify 축소)한 상태로 해시하여 전송된 원본 본문과 해시가 불일치합니다.",
            solution: "본문 해시(X-Body-Digest)는 가공된 JSON이 아니라 네트워크로 실제 전송되는 본문 바이트 원본 그대로 해시해야 합니다.",
            apply: async (req) => {
                try {
                    const compactBody = JSON.stringify(JSON.parse(req.rawBody));
                    if (compactBody === req.rawBody) return req;
                    return { ...req, rawBody: compactBody, bodyHash: await hashString(compactBody) };
                } catch (e) {
                    return req;
                }
            }
        }
    ];

    return { HYPOTHESES };
});
