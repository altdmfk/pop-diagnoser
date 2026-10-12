(function (root, factory) {
    const encoding = (typeof module !== 'undefined' && module.exports)
        ? require('./encoding.js')
        : root.PopCore;
    const mod = factory(encoding);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (encoding) {
    const { bytesToBinaryString, base64StandardDecode } = encoding;
    const _btoa = typeof btoa !== 'undefined' ? btoa : (str) => Buffer.from(str, 'binary').toString('base64');
    const _crypto = typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto;
    const RAW_SIGNATURE_BYTES = 64;
    const HALF_SIGNATURE_BYTES = 32;
    const MIN_DER_BYTES = 8;
    const PEM_PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    const PEM_PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";

    function containsPrivateKeyMarker(str) {
        if (typeof str !== 'string') return false;
        return /-----\s*(?:BEGIN|END)\s+[A-Z0-9 ]*PRIVATE KEY\s*-----/i.test(str) ||
            /\bPRIVATE\s+KEY\b/i.test(str);
    }

    function extractPublicKeySpkiBytes(pem) {
        const raw = String(pem ?? '').trim();
        if (containsPrivateKeyMarker(raw)) {
            return {
                ok: false,
                code: 'PRIVATE_KEY_REJECTED',
                message: `보안 경고: 비밀키(PRIVATE KEY)는 입력할 수 없습니다. 공개키(${PEM_PUBLIC_KEY_HEADER})만 입력해 주세요.`,
                warnings: [
                    {
                        code: 'PRIVATE_KEY_INPUT',
                        message: '비밀키(PRIVATE KEY)가 감지되어 파싱을 중단했습니다. 본 진단기는 비밀키를 요구하지 않으며 공개키(PUBLIC KEY)만 사용합니다.'
                    }
                ]
            };
        }

        if (!raw) {
            return {
                ok: false,
                code: 'EMPTY_PUBLIC_KEY',
                message: '공개키 입력값이 비어 있습니다.'
            };
        }

        if (/-----\s*BEGIN RSA PUBLIC KEY\s*-----/i.test(raw)) {
            return {
                ok: false,
                code: 'UNSUPPORTED_ALGORITHM_RSA',
                message: 'RSA 공개키(PKCS#1)는 지원하지 않습니다. FIDO2 PoP 게이트웨이는 ECDSA P-256 공개키(SPKI)만 지원합니다.'
            };
        }

        const hasHeader = raw.includes(PEM_PUBLIC_KEY_HEADER);
        const hasFooter = raw.includes(PEM_PUBLIC_KEY_FOOTER);
        let b64Body = '';

        if (hasHeader && hasFooter) {
            const startIdx = raw.indexOf(PEM_PUBLIC_KEY_HEADER) + PEM_PUBLIC_KEY_HEADER.length;
            const endIdx = raw.indexOf(PEM_PUBLIC_KEY_FOOTER);
            if (endIdx < startIdx) {
                return {
                    ok: false,
                    code: 'INVALID_PEM_FORMAT',
                    message: '공개키 PEM 헤더와 푸터의 순서가 올바르지 않습니다.'
                };
            }
            b64Body = raw.substring(startIdx, endIdx).replace(/\s/g, '');
        } else if (!hasHeader && !hasFooter && !/-----/.test(raw)) {
            b64Body = raw.replace(/\s/g, '');
        } else {
            const missing = !hasHeader ? `시작 태그(${PEM_PUBLIC_KEY_HEADER})` : `종료 태그(${PEM_PUBLIC_KEY_FOOTER})`;
            return {
                ok: false,
                code: 'INVALID_PEM_FORMAT',
                message: `공개키 형식이 올바르지 않습니다. ${missing}가 잘려나갔거나 손상되었습니다.\n아예 태그 없이 중간 값(Base64)만 넣으시거나, 양쪽 태그를 모두 포함해 주세요.`
            };
        }

        if (!b64Body) {
            return {
                ok: false,
                code: 'EMPTY_PUBLIC_KEY',
                message: '공개키 내부에 실제 키 데이터(Base64)가 비어 있습니다.'
            };
        }

        let spkiBytes;
        try {
            spkiBytes = new Uint8Array(base64StandardDecode(b64Body));
        } catch (e) {
            return {
                ok: false,
                code: 'INVALID_BASE64',
                message: '공개키 내부 데이터(Base64) 디코딩에 실패했습니다.\n공백 외의 잘못된 문자(한글, 특수기호 등)나 손상된 패딩이 있는지 확인하세요.'
            };
        }

        return { ok: true, spkiBytes };
    }

    async function importPublicKey(pem) {
        const extracted = extractPublicKeySpkiBytes(pem);
        if (!extracted.ok) {
            const err = new Error(extracted.message);
            err.code = extracted.code;
            throw err;
        }

        try {
            return await _crypto.subtle.importKey(
                "spki",
                extracted.spkiBytes.buffer,
                { name: "ECDSA", namedCurve: "P-256" },
                true,
                ["verify"]
            );
        } catch (e) {
            const err = new Error("공개키 데이터 분석(Import)에 실패했습니다. 키가 손상되었거나 유효한 ECDSA P-256 공개키가 아닐 수 있습니다. (상세 에러: " + e.message + ")");
            err.code = 'INVALID_SPKI_KEY';
            throw err;
        }
    }

    function parseDerSignature(derBytes) {
        if (!derBytes) {
            return { ok: false, message: 'DER 서명 바이트가 비어 있습니다.' };
        }
        const view = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
        if (view.length < MIN_DER_BYTES || view[0] !== 0x30) {
            return { ok: false, message: 'DER SEQUENCE 시작 태그(0x30)가 없거나 길이가 너무 짧습니다.' };
        }

        let offset = 2;
        let seqLen = view[1];
        if (seqLen === 0x80) {
            return { ok: false, message: 'DER Indefinite Length(0x80)는 허용되지 않습니다.' };
        }
        if (seqLen > 0x80) {
            const numLenBytes = seqLen & 0x7f;
            if (numLenBytes === 0 || numLenBytes > 2 || 2 + numLenBytes > view.length) {
                return { ok: false, message: 'DER SEQUENCE 길이 헤더가 손상되었습니다.' };
            }
            seqLen = 0;
            for (let i = 0; i < numLenBytes; i++) {
                seqLen = (seqLen << 8) | view[2 + i];
            }
            offset = 2 + numLenBytes;
        }
        if (offset + seqLen !== view.length) {
            return {
                ok: false,
                message: `DER SEQUENCE 선언 길이(${seqLen}B)와 실제 바이트 길이(${view.length - offset}B)가 일치하지 않습니다.`
            };
        }

        if (offset + 2 > view.length || view[offset] !== 0x02) {
            return { ok: false, message: 'DER r 성분의 INTEGER 태그(0x02)를 찾을 수 없습니다.' };
        }
        const rOrigLen = view[offset + 1];
        let rLen = rOrigLen;
        let rStart = offset + 2;
        if (rLen === 0 || rStart + rLen > view.length) {
            return { ok: false, message: 'DER r 성분의 길이가 0이거나 범위를 벗어났습니다.' };
        }
        const sOffset = rStart + rLen;
        let rLeadingZeroStripped = false;
        if (view[rStart] === 0x00 && rLen > 1) {
            if ((view[rStart + 1] & 0x80) === 0) {
                return { ok: false, message: 'DER r 성분에 불필요한 선행 0x00 바이트(비최소 인코딩)가 포함되어 있습니다.' };
            }
            rStart++;
            rLen--;
            rLeadingZeroStripped = true;
        }
        if (rLen === 0 || rLen > HALF_SIGNATURE_BYTES) {
            return { ok: false, message: `DER r 성분의 유효 길이(${rLen}B)가 P-256 최대 길이(32B)를 초과합니다.` };
        }
        const r = view.slice(rStart, rStart + rLen);

        offset = sOffset;
        if (offset + 2 > view.length || view[offset] !== 0x02) {
            return { ok: false, message: 'DER s 성분의 INTEGER 태그(0x02)를 찾을 수 없습니다.' };
        }
        const sOrigLen = view[offset + 1];
        let sLen = sOrigLen;
        let sStart = offset + 2;
        if (sLen === 0 || sStart + sLen !== view.length) {
            return { ok: false, message: 'DER s 성분의 길이가 올바르지 않거나 뒤에 잔여 바이트가 남아 있습니다.' };
        }
        let sLeadingZeroStripped = false;
        if (view[sStart] === 0x00 && sLen > 1) {
            if ((view[sStart + 1] & 0x80) === 0) {
                return { ok: false, message: 'DER s 성분에 불필요한 선행 0x00 바이트(비최소 인코딩)가 포함되어 있습니다.' };
            }
            sStart++;
            sLen--;
            sLeadingZeroStripped = true;
        }
        if (sLen === 0 || sLen > HALF_SIGNATURE_BYTES) {
            return { ok: false, message: `DER s 성분의 유효 길이(${sLen}B)가 P-256 최대 길이(32B)를 초과합니다.` };
        }
        const s = view.slice(sStart, sStart + sLen);

        const rawBytes = new Uint8Array(RAW_SIGNATURE_BYTES);
        rawBytes.set(r, HALF_SIGNATURE_BYTES - rLen);
        rawBytes.set(s, HALF_SIGNATURE_BYTES + (HALF_SIGNATURE_BYTES - sLen));

        return {
            ok: true,
            rawBytes,
            rIsZero: rLen === 1 && r[0] === 0x00,
            sIsZero: sLen === 1 && s[0] === 0x00,
            rLeadingZeroStripped,
            sLeadingZeroStripped,
            rDerLength: rOrigLen,
            sDerLength: sOrigLen
        };
    }

    function derToRaw(derBytes) {
        const parsed = parseDerSignature(derBytes);
        if (!parsed.ok || parsed.rIsZero || parsed.sIsZero) return null;
        return parsed.rawBytes.buffer;
    }

    async function verifySig(key, sigBytes, canonicalStr) {
        const encoder = new TextEncoder();
        const data = encoder.encode(canonicalStr);
        try {
            return await _crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, key, sigBytes, data);
        } catch (e) {
            return false;
        }
    }

    async function generateKeyPairAndSign(canonicalStr) {
        // 개인키(privateKey)는 외부로 추출(export)하지 않으므로 extractable: false로 생성한다.
        // WebCrypto 규격상 비대칭 키쌍에서 extractable: false는 개인키에만 적용되며 공개키(publicKey)는 SPKI로 정상 추출된다.
        const keyPair = await _crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["sign", "verify"]
        );
        const spki = await _crypto.subtle.exportKey("spki", keyPair.publicKey);
        const spkiBase64 = _btoa(bytesToBinaryString(spki));
        const pubkeyPem = `${PEM_PUBLIC_KEY_HEADER}\n${spkiBase64.match(/.{1,64}/g).join('\n')}\n${PEM_PUBLIC_KEY_FOOTER}`;

        const data = new TextEncoder().encode(canonicalStr);
        const signatureBytes = await _crypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            keyPair.privateKey,
            data
        );

        return { pubkeyPem, signatureBytes };
    }

    return {
        PEM_PUBLIC_KEY_HEADER,
        PEM_PUBLIC_KEY_FOOTER,
        containsPrivateKeyMarker,
        extractPublicKeySpkiBytes,
        parseDerSignature,
        importPublicKey,
        derToRaw,
        verifySig,
        generateKeyPairAndSign
    };
});
