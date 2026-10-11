(function (root, factory) {
    let deps;
    if (typeof module !== 'undefined' && module.exports) {
        deps = Object.assign(
            {},
            require('./encoding.js'),
            require('./ecdsa.js')
        );
    } else {
        deps = Object.assign({}, root.PopCore);
    }
    const mod = factory(deps);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (deps) {
    const {
        _atob,
        _crypto,
        base64UrlDecode,
        base64StandardDecode,
        bytesToHex,
        derToRaw
    } = deps;

    // NIST P-256 (secp256r1 / prime256v1) parameters
    const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
    const P256_A = P256_P - 3n;
    const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
    const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const P256_HALF_N = P256_N >> 1n;

    const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
    const OID_P256 = '1.2.840.10045.3.1.7';

    const KNOWN_ALGORITHMS = {
        '1.2.840.10045.2.1': 'id-ecPublicKey (ECDSA)',
        '1.2.840.113549.1.1.1': 'rsaEncryption (RSA)',
        '1.3.101.110': 'X25519',
        '1.3.101.112': 'Ed25519'
    };

    const KNOWN_CURVES = {
        '1.2.840.10045.3.1.7': 'P-256 (prime256v1 / secp256r1)',
        '1.3.132.0.34': 'P-384 (secp384r1)',
        '1.3.132.0.35': 'P-521 (secp521r1)',
        '1.3.132.0.10': 'secp256k1'
    };

    function containsPrivateKeyMarker(str) {
        if (typeof str !== 'string') return false;
        return /-----\s*(?:BEGIN|END)\s+[A-Z0-9 ]*PRIVATE KEY\s*-----/i.test(str) ||
            /\bPRIVATE\s+KEY\b/i.test(str);
    }

    function modP(val, p) {
        const r = val % p;
        return r >= 0n ? r : r + p;
    }

    function decodeHexBytes(hexStr) {
        const clean = hexStr.replace(/^0x/i, '');
        const out = new Uint8Array(clean.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    function detectAndDecodeSignature(sigStr) {
        const trimmed = String(sigStr ?? '').trim();
        if (!trimmed) {
            return {
                encoding: 'unknown',
                encodingReason: '입력값이 비어 있습니다.',
                bytes: null,
                error: { code: 'EMPTY_SIGNATURE', message: '서명 문자열이 비어 있습니다.' }
            };
        }

        const has0x = /^0x/i.test(trimmed);
        const hexCandidate = has0x ? trimmed.slice(2) : trimmed;
        const isHexChars = hexCandidate.length >= 2 &&
            hexCandidate.length % 2 === 0 &&
            /^[0-9a-fA-F]+$/.test(hexCandidate);

        // 86-char all-hex without 0x and not starting with 30 (e.g. 'A'.repeat(86)) is a 64B Base64url signature
        const isAmbiguous86Base64 = !has0x && hexCandidate.length === 86 && !/^30/i.test(hexCandidate);

        if (isHexChars && !isAmbiguous86Base64) {
            return {
                encoding: 'hex',
                encodingReason: has0x
                    ? '0x 접두사와 16진수(0-9, a-f) 문자만으로 구성된 짝수 길이 문자열입니다.'
                    : '16진수(0-9, a-f) 문자만으로 구성된 짝수 길이 문자열입니다.',
                bytes: decodeHexBytes(hexCandidate),
                error: null
            };
        }

        const hasStdChars = /[+/=]/.test(trimmed);
        const hasUrlChars = /[\-_]/.test(trimmed);

        if (hasStdChars && !hasUrlChars) {
            try {
                const buf = base64StandardDecode(trimmed);
                const foundChars = [];
                if (trimmed.includes('+')) foundChars.push('+');
                if (trimmed.includes('/')) foundChars.push('/');
                if (trimmed.includes('=')) foundChars.push('=');
                return {
                    encoding: 'base64(standard)',
                    encodingReason: `표준 Base64 전용 문자(${foundChars.join(', ')})가 포함되어 있습니다.`,
                    bytes: new Uint8Array(buf),
                    error: null
                };
            } catch (e) {
                return {
                    encoding: 'unknown',
                    encodingReason: '표준 Base64 문자가 포함되어 있으나 길이 또는 패딩 형식이 올바르지 않습니다.',
                    bytes: null,
                    error: { code: 'INVALID_ENCODING', message: '표준 Base64 디코딩에 실패했습니다. 패딩(=) 또는 문자열 길이를 확인하세요.' }
                };
            }
        }

        if (!hasStdChars) {
            try {
                const buf = base64UrlDecode(trimmed);
                return {
                    encoding: 'base64url',
                    encodingReason: hasUrlChars
                        ? 'Base64url 전용 문자(-, _)가 포함된 URL-safe 인코딩입니다.'
                        : '패딩(=)이 없는 URL-safe Base64(Base64url) 호환 문자열입니다.',
                    bytes: new Uint8Array(buf),
                    error: null
                };
            } catch (e) {
                // Fall through to unknown
            }
        }

        return {
            encoding: 'unknown',
            encodingReason: hasStdChars && hasUrlChars
                ? '표준 Base64 문자(+, /, =)와 Base64url 문자(-, _)가 혼용되어 있습니다.'
                : '유효한 Base64url, 표준 Base64 또는 Hex 인코딩 형식이 아닙니다.',
            bytes: null,
            error: {
                code: 'INVALID_ENCODING',
                message: '서명 문자열을 디코딩할 수 없습니다. 유효한 Base64url, 표준 Base64 또는 Hex 형식인지 확인하세요.'
            }
        };
    }

    function inspectDerStructure(view) {
        if (!view || view.length < 8 || view[0] !== 0x30) {
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

        // Parse r INTEGER
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
        if (rLen > 32) {
            return { ok: false, message: `DER r 성분의 유효 길이(${rLen}B)가 P-256 최대 길이(32B)를 초과합니다.` };
        }

        // Parse s INTEGER
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
        if (sLen > 32) {
            return { ok: false, message: `DER s 성분의 유효 길이(${sLen}B)가 P-256 최대 길이(32B)를 초과합니다.` };
        }

        // Use derToRaw when both r > 0 and s > 0; also support r=0 or s=0 (02 01 00) for inspection
        const rawFromCore = derToRaw(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
        let rawBytes;
        if (rawFromCore) {
            rawBytes = new Uint8Array(rawFromCore);
        } else {
            rawBytes = new Uint8Array(64);
            const rSlice = view.slice(rStart, rStart + rLen);
            const sSlice = view.slice(sStart, sStart + sLen);
            rawBytes.set(rSlice, 32 - rLen);
            rawBytes.set(sSlice, 32 + (32 - sLen));
        }

        return {
            ok: true,
            rawBytes,
            rLeadingZeroStripped,
            sLeadingZeroStripped,
            rDerLength: rOrigLen,
            sDerLength: sOrigLen
        };
    }

    function inspectSignature(sigStr) {
        if (containsPrivateKeyMarker(sigStr)) {
            return {
                ok: false,
                encoding: 'unknown',
                encodingReason: '비밀키(PRIVATE KEY) 헤더가 감지되었습니다.',
                byteLength: 0,
                format: 'invalid',
                r: null,
                s: null,
                rLeadingZeroStripped: false,
                sLeadingZeroStripped: false,
                isHighS: false,
                rOutOfRange: false,
                sOutOfRange: false,
                warnings: [
                    {
                        code: 'PRIVATE_KEY_INPUT',
                        message: '비밀키(PRIVATE KEY)가 감지되어 파싱을 중단했습니다. 본 진단기는 비밀키를 절대 요구하거나 처리하지 않습니다.'
                    }
                ],
                error: {
                    code: 'PRIVATE_KEY_REJECTED',
                    message: '보안 경고: 비밀키(PRIVATE KEY)는 입력할 수 없습니다.'
                }
            };
        }

        const decoded = detectAndDecodeSignature(sigStr);
        if (decoded.error || !decoded.bytes) {
            return {
                ok: false,
                encoding: decoded.encoding,
                encodingReason: decoded.encodingReason,
                byteLength: 0,
                format: 'invalid',
                r: null,
                s: null,
                rLeadingZeroStripped: false,
                sLeadingZeroStripped: false,
                isHighS: false,
                rOutOfRange: false,
                sOutOfRange: false,
                warnings: [],
                error: decoded.error
            };
        }

        const bytes = decoded.bytes;
        const byteLength = bytes.length;
        let format = 'invalid';
        let rBytes = null;
        let sBytes = null;
        let rLeadingZeroStripped = false;
        let sLeadingZeroStripped = false;
        let error = null;

        if (bytes[0] === 0x30) {
            const derRes = inspectDerStructure(bytes);
            if (derRes.ok) {
                format = 'der';
                rBytes = derRes.rawBytes.slice(0, 32);
                sBytes = derRes.rawBytes.slice(32, 64);
                rLeadingZeroStripped = derRes.rLeadingZeroStripped;
                sLeadingZeroStripped = derRes.sLeadingZeroStripped;
            } else if (byteLength === 64) {
                // 64B raw signature whose first byte of r happens to be 0x30
                format = 'raw-rs(64B)';
                rBytes = bytes.slice(0, 32);
                sBytes = bytes.slice(32, 64);
            } else {
                format = 'invalid';
                error = {
                    code: 'INVALID_DER',
                    message: derRes.message
                };
            }
        } else if (byteLength === 64) {
            format = 'raw-rs(64B)';
            rBytes = bytes.slice(0, 32);
            sBytes = bytes.slice(32, 64);
        } else {
            format = 'invalid';
            error = {
                code: 'INVALID_LENGTH',
                message: `서명 바이트 길이(${byteLength}B)가 올바르지 않습니다. Raw(P1363) 서명은 64바이트여야 하며, ASN.1 DER 서명은 0x30(SEQUENCE)으로 시작해야 합니다.`
            };
        }

        if (!rBytes || !sBytes) {
            return {
                ok: false,
                encoding: decoded.encoding,
                encodingReason: decoded.encodingReason,
                byteLength,
                format,
                r: null,
                s: null,
                rLeadingZeroStripped: false,
                sLeadingZeroStripped: false,
                isHighS: false,
                rOutOfRange: false,
                sOutOfRange: false,
                warnings: [],
                error
            };
        }

        const rHex = bytesToHex(rBytes);
        const sHex = bytesToHex(sBytes);
        const rBig = BigInt('0x' + rHex);
        const sBig = BigInt('0x' + sHex);

        const warnings = [];
        const rOutOfRange = rBig <= 0n || rBig >= P256_N;
        const sOutOfRange = sBig <= 0n || sBig >= P256_N;
        const isHighS = sBig > P256_HALF_N && sBig < P256_N;

        if (rBig === 0n) {
            warnings.push({
                code: 'R_ZERO',
                message: 'r 값이 0입니다. 유효한 ECDSA 서명에서 r은 1 이상 곡선 차수(n) 미만이어야 합니다.'
            });
        } else if (rBig >= P256_N) {
            warnings.push({
                code: 'R_GE_N',
                message: 'r 값이 P-256 곡선 차수(n) 이상입니다. 유효한 ECDSA 서명에서 r은 n 미만이어야 합니다.'
            });
        }

        if (sBig === 0n) {
            warnings.push({
                code: 'S_ZERO',
                message: 's 값이 0입니다. 유효한 ECDSA 서명에서 s는 1 이상 곡선 차수(n) 미만이어야 합니다.'
            });
        } else if (sBig >= P256_N) {
            warnings.push({
                code: 'S_GE_N',
                message: 's 값이 P-256 곡선 차수(n) 이상입니다. 유효한 ECDSA 서명에서 s는 n 미만이어야 합니다.'
            });
        }

        if (isHighS) {
            warnings.push({
                code: 'HIGH_S',
                message: 's > n/2 (High-S 서명): 표준 WebCrypto/ECDSA에서는 유효하지만, 서명 가변성(Malleability) 방지를 위해 Low-S만 강제하는 검증기에서는 거부될 수 있습니다.'
            });
        }

        return {
            ok: error === null,
            encoding: decoded.encoding,
            encodingReason: decoded.encodingReason,
            byteLength,
            format,
            r: rHex,
            s: sHex,
            rLeadingZeroStripped,
            sLeadingZeroStripped,
            isHighS,
            rOutOfRange,
            sOutOfRange,
            warnings,
            error
        };
    }

    function readDerTlv(bytes, offset) {
        if (!bytes || offset < 0 || offset + 2 > bytes.length) return null;
        const tag = bytes[offset];
        let lenByte = bytes[offset + 1];
        let headerLen = 2;
        let length = lenByte;

        if (lenByte === 0x80) return null; // indefinite length not allowed in DER
        if (lenByte > 0x80) {
            const numBytes = lenByte & 0x7f;
            if (numBytes === 0 || numBytes > 3 || offset + 2 + numBytes > bytes.length) return null;
            length = 0;
            for (let i = 0; i < numBytes; i++) {
                length = (length << 8) | bytes[offset + 2 + i];
            }
            headerLen = 2 + numBytes;
        }

        const valueStart = offset + headerLen;
        const valueEnd = valueStart + length;
        if (valueEnd > bytes.length) return null;

        return {
            tag,
            headerLen,
            length,
            valueStart,
            valueEnd,
            nextOffset: valueEnd
        };
    }

    function decodeOid(oidBytes) {
        if (!oidBytes || oidBytes.length === 0) return null;
        const firstByte = oidBytes[0];
        const first = firstByte >= 80 ? 2 : Math.floor(firstByte / 40);
        const second = firstByte >= 80 ? firstByte - 80 : firstByte % 40;
        const arcs = [first, second];

        let value = 0n;
        let inArc = false;
        for (let i = 1; i < oidBytes.length; i++) {
            const b = oidBytes[i];
            value = (value << 7n) | BigInt(b & 0x7f);
            inArc = true;
            if ((b & 0x80) === 0) {
                arcs.push(value.toString(10));
                value = 0n;
                inArc = false;
            }
        }
        if (inArc) return null; // truncated VLQ
        return arcs.join('.');
    }

    async function inspectPublicKey(pemStr) {
        const raw = String(pemStr ?? '').trim();
        if (containsPrivateKeyMarker(raw)) {
            return {
                ok: false,
                byteLength: 0,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint: null,
                warnings: [
                    {
                        code: 'PRIVATE_KEY_INPUT',
                        message: '비밀키(PRIVATE KEY)가 감지되어 파싱을 중단했습니다. 본 진단기는 비밀키를 요구하지 않으며 공개키(PUBLIC KEY)만 사용합니다.'
                    }
                ],
                error: {
                    code: 'PRIVATE_KEY_REJECTED',
                    message: '보안 경고: 비밀키(PRIVATE KEY)는 입력할 수 없습니다. 공개키(-----BEGIN PUBLIC KEY-----)만 입력해 주세요.'
                }
            };
        }

        if (!raw) {
            return {
                ok: false,
                byteLength: 0,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint: null,
                warnings: [],
                error: { code: 'EMPTY_PUBLIC_KEY', message: '공개키 입력값이 비어 있습니다.' }
            };
        }

        if (/-----\s*BEGIN RSA PUBLIC KEY\s*-----/i.test(raw)) {
            return {
                ok: false,
                byteLength: 0,
                algorithmOid: '1.2.840.113549.1.1.1',
                algorithmName: 'rsaEncryption (RSA PKCS#1)',
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint: null,
                warnings: [],
                error: {
                    code: 'UNSUPPORTED_ALGORITHM_RSA',
                    message: 'RSA 공개키(PKCS#1)는 지원하지 않습니다. FIDO2 PoP 게이트웨이는 ECDSA P-256 공개키(SPKI)만 지원합니다.'
                }
            };
        }

        const pemHeader = '-----BEGIN PUBLIC KEY-----';
        const pemFooter = '-----END PUBLIC KEY-----';
        const hasHeader = raw.includes(pemHeader);
        const hasFooter = raw.includes(pemFooter);
        let b64Body = '';

        if (hasHeader && hasFooter) {
            const startIdx = raw.indexOf(pemHeader) + pemHeader.length;
            const endIdx = raw.indexOf(pemFooter);
            if (endIdx < startIdx) {
                return {
                    ok: false,
                    byteLength: 0,
                    algorithmOid: null,
                    algorithmName: null,
                    curveOid: null,
                    curveName: null,
                    pointFormat: null,
                    x: null,
                    y: null,
                    onCurve: null,
                    fingerprint: null,
                    warnings: [],
                    error: { code: 'INVALID_PEM_FORMAT', message: '공개키 PEM 헤더와 푸터의 순서가 올바르지 않습니다.' }
                };
            }
            b64Body = raw.substring(startIdx, endIdx).replace(/\s/g, '');
        } else if (!hasHeader && !hasFooter && !/-----/.test(raw)) {
            b64Body = raw.replace(/\s/g, '');
        } else {
            return {
                ok: false,
                byteLength: 0,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint: null,
                warnings: [],
                error: {
                    code: 'INVALID_PEM_FORMAT',
                    message: '공개키 PEM 헤더(-----BEGIN PUBLIC KEY-----) 또는 푸터(-----END PUBLIC KEY-----)가 누락되었거나 손상되었습니다.'
                }
            };
        }

        if (!b64Body) {
            return {
                ok: false,
                byteLength: 0,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint: null,
                warnings: [],
                error: { code: 'EMPTY_PUBLIC_KEY', message: '공개키 PEM 내부의 Base64 데이터가 비어 있습니다.' }
            };
        }

        let spkiBytes;
        try {
            if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64Body)) {
                throw new Error('Invalid Base64 characters');
            }
            let padded = b64Body.replace(/=+$/, '');
            if (padded.length % 4 === 1) {
                throw new Error('Invalid Base64 length');
            }
            while (padded.length % 4) padded += '=';
            const binStr = _atob(padded);
            spkiBytes = new Uint8Array(binStr.length);
            for (let i = 0; i < binStr.length; i++) {
                spkiBytes[i] = binStr.charCodeAt(i);
            }
        } catch (e) {
            return {
                ok: false,
                byteLength: 0,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint: null,
                warnings: [],
                error: {
                    code: 'INVALID_BASE64',
                    message: '공개키 Base64 디코딩에 실패했습니다. 허용되지 않는 문자나 손상된 패딩이 있는지 확인하세요.'
                }
            };
        }

        const hashBuffer = await _crypto.subtle.digest('SHA-256', spkiBytes);
        const fingerprint = bytesToHex(hashBuffer);

        // Parse outer SubjectPublicKeyInfo SEQUENCE
        const outerSeq = readDerTlv(spkiBytes, 0);
        if (!outerSeq || outerSeq.tag !== 0x30 || outerSeq.nextOffset !== spkiBytes.length) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: { code: 'INVALID_SPKI_DER', message: '공개키 SPKI DER 외곽 SEQUENCE 구조가 손상되었습니다.' }
            };
        }

        // Parse AlgorithmIdentifier SEQUENCE
        const algSeq = readDerTlv(spkiBytes, outerSeq.valueStart);
        if (!algSeq || algSeq.tag !== 0x30 || algSeq.nextOffset > outerSeq.valueEnd) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: { code: 'INVALID_SPKI_DER', message: 'SPKI AlgorithmIdentifier SEQUENCE 구조가 손상되었습니다.' }
            };
        }

        const algOidTlv = readDerTlv(spkiBytes, algSeq.valueStart);
        if (!algOidTlv || algOidTlv.tag !== 0x06 || algOidTlv.nextOffset > algSeq.valueEnd) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid: null,
                algorithmName: null,
                curveOid: null,
                curveName: null,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: { code: 'INVALID_SPKI_DER', message: 'SPKI 알고리즘 OID(0x06)를 읽을 수 없습니다.' }
            };
        }

        const algorithmOid = decodeOid(spkiBytes.slice(algOidTlv.valueStart, algOidTlv.valueEnd));
        const algorithmName = KNOWN_ALGORITHMS[algorithmOid] || (algorithmOid ? `OID ${algorithmOid}` : null);

        let curveOid = null;
        let curveName = null;
        if (algOidTlv.nextOffset < algSeq.valueEnd) {
            const paramTlv = readDerTlv(spkiBytes, algOidTlv.nextOffset);
            if (!paramTlv || paramTlv.nextOffset !== algSeq.valueEnd) {
                return {
                    ok: false,
                    byteLength: spkiBytes.length,
                    algorithmOid,
                    algorithmName,
                    curveOid: null,
                    curveName: null,
                    pointFormat: null,
                    x: null,
                    y: null,
                    onCurve: null,
                    fingerprint,
                    warnings: [],
                    error: { code: 'INVALID_SPKI_DER', message: 'SPKI 알고리즘 파라미터 DER 구조가 손상되었습니다.' }
                };
            }
            if (paramTlv.tag === 0x06) {
                curveOid = decodeOid(spkiBytes.slice(paramTlv.valueStart, paramTlv.valueEnd));
                curveName = KNOWN_CURVES[curveOid] || (curveOid ? `OID ${curveOid}` : null);
            }
        }

        // Parse subjectPublicKey BIT STRING
        const bitStringTlv = readDerTlv(spkiBytes, algSeq.nextOffset);
        if (
            !bitStringTlv ||
            bitStringTlv.tag !== 0x03 ||
            bitStringTlv.nextOffset !== outerSeq.valueEnd ||
            bitStringTlv.length < 2 ||
            spkiBytes[bitStringTlv.valueStart] !== 0x00
        ) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid,
                algorithmName,
                curveOid,
                curveName,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: { code: 'INVALID_SPKI_DER', message: 'SPKI subjectPublicKey BIT STRING 구조가 손상되었습니다.' }
            };
        }

        if (algorithmOid !== OID_EC_PUBLIC_KEY) {
            const isRsa = algorithmOid === '1.2.840.113549.1.1.1';
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid,
                algorithmName,
                curveOid,
                curveName,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: {
                    code: isRsa ? 'UNSUPPORTED_ALGORITHM_RSA' : 'UNSUPPORTED_ALGORITHM',
                    message: isRsa
                        ? 'RSA 공개키(OID 1.2.840.113549.1.1.1)는 지원하지 않습니다. FIDO2 PoP 게이트웨이는 ECDSA P-256 공개키만 허용합니다.'
                        : `지원하지 않는 공개키 알고리즘(${algorithmName || algorithmOid})입니다. ECDSA(OID ${OID_EC_PUBLIC_KEY})만 지원합니다.`
                }
            };
        }

        if (curveOid !== OID_P256) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid,
                algorithmName,
                curveOid,
                curveName,
                pointFormat: null,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: {
                    code: 'UNSUPPORTED_CURVE',
                    message: `지원하지 않는 타원곡선(${curveName || curveOid || '미지정'})입니다. FIDO2 PoP 게이트웨이는 P-256(OID ${OID_P256})만 지원합니다.`
                }
            };
        }

        const pointBytes = spkiBytes.slice(bitStringTlv.valueStart + 1, bitStringTlv.valueEnd);
        const prefix = pointBytes[0];
        if (prefix !== 0x04) {
            const prefixHex = '0x' + prefix.toString(16).padStart(2, '0');
            const pointFormat = (prefix === 0x02 || prefix === 0x03)
                ? `compressed(${prefixHex})`
                : `invalid(${prefixHex})`;
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid,
                algorithmName,
                curveOid,
                curveName,
                pointFormat,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: {
                    code: 'INVALID_POINT_PREFIX',
                    message: `비압축 점 접두 바이트(0x04)가 아닙니다 (감지된 접두: ${prefixHex}). 65바이트 비압축 점(0x04 || X || Y)만 지원합니다.`
                }
            };
        }

        const pointFormat = 'uncompressed(0x04)';
        if (pointBytes.length !== 65) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid,
                algorithmName,
                curveOid,
                curveName,
                pointFormat,
                x: null,
                y: null,
                onCurve: null,
                fingerprint,
                warnings: [],
                error: {
                    code: 'INVALID_POINT_LENGTH',
                    message: `비압축 공개키 점의 바이트 길이(${pointBytes.length}B)가 올바르지 않습니다. 정확히 65바이트(0x04 + X 32B + Y 32B)여야 합니다.`
                }
            };
        }

        const xHex = bytesToHex(pointBytes.slice(1, 33));
        const yHex = bytesToHex(pointBytes.slice(33, 65));
        const xBig = BigInt('0x' + xHex);
        const yBig = BigInt('0x' + yHex);

        const inField = xBig >= 0n && xBig < P256_P && yBig >= 0n && yBig < P256_P;
        let onCurve = false;
        if (inField) {
            const lhs = modP(yBig * yBig, P256_P);
            const x2 = modP(xBig * xBig, P256_P);
            const x3 = modP(x2 * xBig, P256_P);
            const ax = modP(P256_A * xBig, P256_P);
            const rhs = modP(x3 + ax + P256_B, P256_P);
            onCurve = lhs === rhs;
        }

        if (!onCurve) {
            return {
                ok: false,
                byteLength: spkiBytes.length,
                algorithmOid,
                algorithmName,
                curveOid,
                curveName,
                pointFormat,
                x: xHex,
                y: yHex,
                onCurve: false,
                fingerprint,
                warnings: [],
                error: {
                    code: 'POINT_NOT_ON_CURVE',
                    message: '공개키 좌표 (X, Y)가 P-256 타원곡선 방정식(y² ≡ x³ - 3x + b mod p)을 만족하지 않습니다 (곡선 밖의 점).'
                }
            };
        }

        return {
            ok: true,
            byteLength: spkiBytes.length,
            algorithmOid,
            algorithmName,
            curveOid,
            curveName,
            pointFormat,
            x: xHex,
            y: yHex,
            onCurve: true,
            fingerprint,
            warnings: [],
            error: null
        };
    }

    return {
        P256_P,
        P256_A,
        P256_B,
        P256_N,
        P256_HALF_N,
        OID_EC_PUBLIC_KEY,
        OID_P256,
        inspectSignature,
        inspectPublicKey
    };
});
