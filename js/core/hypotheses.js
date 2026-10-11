(function (root, factory) {
    const encoding = (typeof module !== 'undefined' && module.exports)
        ? require('./encoding.js')
        : root.PopCore;
    const ecdsa = (typeof module !== 'undefined' && module.exports)
        ? require('./ecdsa.js')
        : root.PopCore;
    const mod = factory(encoding, ecdsa);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (encoding, ecdsa) {
    const { hashString, hashStringToBase64Url } = encoding;
    const { derToRaw } = ecdsa;

    const HYPOTHESES = [
        {
            id: 'query-sorted',
            label: '쿼리를 알파벳순 정렬',
            tag: 'common-mistake',
            stage: 4,
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
            stage: 4,
            apply: async (req) => {
                if (!req.query) return req;
                return { ...req, query: req.query.split('&').reverse().join('&') };
            }
        },
        {
            id: 'method-lowercase',
            label: 'HTTP 메서드를 소문자로 사용',
            tag: 'common-mistake',
            stage: 4,
            apply: async (req) => ({ ...req, method: req.method.toLowerCase() })
        },
        {
            id: 'path-trailing-slash-add',
            label: 'Path 끝에 슬래시(/) 추가',
            tag: 'common-mistake',
            stage: 4,
            apply: async (req) => ({ ...req, path: req.path.endsWith('/') ? req.path : req.path + '/' })
        },
        {
            id: 'path-trailing-slash-remove',
            label: 'Path 끝에 슬래시(/) 제거',
            tag: 'common-mistake',
            stage: 4,
            apply: async (req) => ({ ...req, path: req.path.endsWith('/') && req.path.length > 1 ? req.path.slice(0, -1) : req.path })
        },
        {
            id: 'host-rewritten',
            label: 'Host 기본 포트(:443) 누락 또는 추가',
            tag: 'common-mistake',
            stage: 4,
            apply: async (req) => {
                let newHost = req.host;
                if (newHost.includes(':')) {
                    newHost = newHost.split(':')[0];
                } else {
                    newHost = newHost + ':443';
                }
                return { ...req, host: newHost };
            }
        },
        {
            id: 'sig-der',
            label: '서명이 DER 형식으로 인코딩됨',
            tag: 'encoding',
            stage: 4,
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
            stage: 4,
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
            apply: async (req, stage) => {
                if (stage === 5) {
                    const crlfBody = req.rawBody.replace(/\r?\n/g, '\r\n');
                    return { ...req, bodyHash: await hashString(crlfBody) };
                }
                return { ...req, delimiter: '\r\n' };
            }
        },
        {
            id: 'newline-trailing',
            label: '마지막에 줄바꿈(\\n) 추가',
            tag: 'paper-rule',
            stage: 'both',
            apply: async (req, stage) => {
                if (stage === 5) {
                    const trailingBody = req.rawBody + '\n';
                    return { ...req, bodyHash: await hashString(trailingBody) };
                }
                return { ...req, trailingNewline: true };
            }
        },
        {
            id: 'digest-base64url',
            label: '본문 해시를 Base64url로 인코딩',
            tag: 'encoding',
            stage: 5,
            apply: async (req) => ({
                ...req,
                bodyHash: await hashStringToBase64Url(req.rawBody)
            })
        },
        {
            id: 'digest-hex',
            label: '본문 해시를 대문자 Hex로 인코딩',
            tag: 'encoding',
            stage: 5,
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
            stage: 5,
            apply: async (req) => ({
                ...req,
                bodyHash: await hashString('\uFEFF' + req.rawBody)
            })
        },
        {
            id: 'body-reserialized-nospace',
            label: 'JSON 공백 제거 후 해시',
            tag: 'common-mistake',
            stage: 5,
            apply: async (req) => {
                try {
                    const parsed = JSON.parse(req.rawBody);
                    return { ...req, bodyHash: await hashString(JSON.stringify(parsed)) };
                } catch (e) {
                    return req;
                }
            }
        }
    ];

    return { HYPOTHESES };
});
