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
        base64UrlDecode,
        base64StandardDecode,
        bytesToHex,
        containsPrivateKeyMarker,
        extractPublicKeySpkiBytes,
        parseDerSignature,
        PEM_PUBLIC_KEY_HEADER = '-----BEGIN PUBLIC KEY-----',
        PEM_PUBLIC_KEY_FOOTER = '-----END PUBLIC KEY-----'
    } = deps;
    const _crypto = typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto;

    // NIST P-256 (secp256r1 / prime256v1) parameters
    const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
    const P256_A = P256_P - 3n;
    const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
    const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const P256_HALF_N = P256_N >> 1n;

    const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
    const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    const OID_P256 = '1.2.840.10045.3.1.7';

    const KNOWN_ALGORITHMS = {
        [OID_EC_PUBLIC_KEY]: 'id-ecPublicKey (ECDSA)',
        [OID_RSA_ENCRYPTION]: 'rsaEncryption (RSA)',
        '1.3.101.110': 'X25519',
        '1.3.101.112': 'Ed25519'
    };

    const KNOWN_CURVES = {
        [OID_P256]: 'P-256 (prime256v1 / secp256r1)',
        '1.3.132.0.34': 'P-384 (secp384r1)',
        '1.3.132.0.35': 'P-521 (secp521r1)',
        '1.3.132.0.10': 'secp256k1'
    };

    function createSigFailReport(overrides) {
        return Object.assign({
            ok: false,
            encoding: 'unknown',
            encodingReason: '',
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
            error: null
        }, overrides);
    }

    function createPubKeyFailReport(overrides) {
        return Object.assign({
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
            error: null
        }, overrides);
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

        if (containsPrivateKeyMarker(trimmed)) {
            return {
                encoding: 'unknown',
                encodingReason: '비밀키(PRIVATE KEY) 헤더가 감지되었습니다.',
                bytes: null,
                error: { code: 'PRIVATE_KEY_REJECTED', message: '보안 경고: 비밀키(PRIVATE KEY)는 입력할 수 없습니다.' }
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
        return parseDerSignature(view);
    }

    function inspectSignature(sigStr) {
        if (containsPrivateKeyMarker(sigStr)) {
            return createSigFailReport({
                encodingReason: '비밀키(PRIVATE KEY) 헤더가 감지되었습니다.',
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
            });
        }

        const decoded = detectAndDecodeSignature(sigStr);
        if (decoded.error || !decoded.bytes) {
            return createSigFailReport({
                encoding: decoded.encoding,
                encodingReason: decoded.encodingReason,
                error: decoded.error
            });
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
                message: `서명 길이(${byteLength}B)가 규격과 다릅니다. FIDO2 PoP 서명은 64바이트 Raw(r||s, P1363) 형식이어야 합니다. DER 형식(보통 70~72바이트, 0x30으로 시작)이라면 Raw r||s 64바이트로 변환해서 입력하세요.`
            };
        }

        if (!rBytes || !sBytes) {
            return createSigFailReport({
                encoding: decoded.encoding,
                encodingReason: decoded.encodingReason,
                byteLength,
                format,
                error
            });
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
                message: '서명 R 값이 0입니다. 서명 생성에 실패했거나 잘못된 값이 전달되었습니다.'
            });
        } else if (rBig >= P256_N) {
            warnings.push({
                code: 'R_GE_N',
                message: '서명 R 값이 P-256 허용 범위를 벗어났습니다. 서명 바이트가 손상되었거나 바이트 순서가 뒤바뀌었는지 확인하세요.'
            });
        }

        if (sBig === 0n) {
            warnings.push({
                code: 'S_ZERO',
                message: '서명 S 값이 0입니다. 서명 생성에 실패했거나 잘못된 값이 전달되었습니다.'
            });
        } else if (sBig >= P256_N) {
            warnings.push({
                code: 'S_GE_N',
                message: '서명 S 값이 P-256 허용 범위를 벗어났습니다. 서명 바이트가 손상되었거나 바이트 순서가 뒤바뀌었는지 확인하세요.'
            });
        }

        if (isHighS) {
            warnings.push({
                code: 'HIGH_S',
                message: "서명 S 값이 상위 범위(High-S)에 있습니다. 표준 WebCrypto/ECDSA 검증은 통과하지만, 서명 변조(Malleability)를 막기 위해 Low-S만 허용하는 게이트웨이에서는 거부될 수 있습니다. 서명 라이브러리의 Low-S 정규화 옵션을 켜거나 s' = n - s 로 변환하세요."
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

    function isPointOnP256Curve(xBig, yBig) {
        if (typeof xBig !== 'bigint' || typeof yBig !== 'bigint') return false;
        const inField = xBig >= 0n && xBig < P256_P && yBig >= 0n && yBig < P256_P;
        if (!inField) return false;
        const lhs = modP(yBig * yBig, P256_P);
        const x2 = modP(xBig * xBig, P256_P);
        const x3 = modP(x2 * xBig, P256_P);
        const ax = modP(P256_A * xBig, P256_P);
        const rhs = modP(x3 + ax + P256_B, P256_P);
        return lhs === rhs;
    }

    async function inspectPublicKey(pemStr) {
        const extracted = extractPublicKeySpkiBytes(pemStr);
        if (!extracted.ok) {
            const extraMeta = extracted.code === 'UNSUPPORTED_ALGORITHM_RSA'
                ? { algorithmOid: OID_RSA_ENCRYPTION, algorithmName: 'rsaEncryption (RSA PKCS#1)' }
                : {};
            return createPubKeyFailReport({
                ...extraMeta,
                warnings: extracted.warnings || [],
                error: {
                    code: extracted.code,
                    message: extracted.message
                }
            });
        }
        const spkiBytes = extracted.spkiBytes;

        const hashBuffer = await _crypto.subtle.digest('SHA-256', spkiBytes);
        const fingerprint = bytesToHex(hashBuffer);
        const baseMeta = { byteLength: spkiBytes.length, fingerprint };

        // Parse outer SubjectPublicKeyInfo SEQUENCE
        const outerSeq = readDerTlv(spkiBytes, 0);
        if (!outerSeq || outerSeq.tag !== 0x30 || outerSeq.nextOffset !== spkiBytes.length) {
            return createPubKeyFailReport({
                ...baseMeta,
                error: {
                    code: 'INVALID_SPKI_DER',
                    subReason: 'outer_sequence',
                    message: '공개키(SPKI) 내부 구조가 손상되었습니다. 복사 과정에서 문자가 누락되었거나 줄바꿈이 깨지지 않았는지, -----BEGIN PUBLIC KEY----- 헤더/푸터가 포함되어 있는지 확인하세요.'
                }
            });
        }

        // Parse AlgorithmIdentifier SEQUENCE (reject if first inner element is PKCS#8 v0 or SEC1 v1 INTEGER)
        const algSeq = readDerTlv(spkiBytes, outerSeq.valueStart);
        if (
            algSeq &&
            algSeq.tag === 0x02 &&
            algSeq.length === 1 &&
            (spkiBytes[algSeq.valueStart] === 0x00 || spkiBytes[algSeq.valueStart] === 0x01)
        ) {
            return createPubKeyFailReport({
                warnings: [
                    {
                        code: 'PRIVATE_KEY_INPUT',
                        message: '비밀키(PRIVATE KEY)가 감지되어 파싱을 중단했습니다. 본 진단기는 비밀키를 요구하지 않으며 공개키(PUBLIC KEY)만 사용합니다.'
                    }
                ],
                error: {
                    code: 'PRIVATE_KEY_REJECTED',
                    message: `보안 경고: 비밀키(PRIVATE KEY)는 입력할 수 없습니다. 공개키(${PEM_PUBLIC_KEY_HEADER})만 입력해 주세요.`
                }
            });
        }
        if (!algSeq || algSeq.tag !== 0x30 || algSeq.nextOffset > outerSeq.valueEnd) {
            return createPubKeyFailReport({
                ...baseMeta,
                error: {
                    code: 'INVALID_SPKI_DER',
                    subReason: 'algorithm_identifier_sequence',
                    message: '공개키(SPKI) 내부 구조가 손상되었습니다. 복사 과정에서 문자가 누락되었거나 줄바꿈이 깨지지 않았는지, -----BEGIN PUBLIC KEY----- 헤더/푸터가 포함되어 있는지 확인하세요.'
                }
            });
        }

        const algOidTlv = readDerTlv(spkiBytes, algSeq.valueStart);
        if (!algOidTlv || algOidTlv.tag !== 0x06 || algOidTlv.nextOffset > algSeq.valueEnd) {
            return createPubKeyFailReport({
                ...baseMeta,
                error: {
                    code: 'INVALID_SPKI_DER',
                    subReason: 'algorithm_oid',
                    message: '공개키(SPKI) 내부 구조가 손상되었습니다. 복사 과정에서 문자가 누락되었거나 줄바꿈이 깨지지 않았는지, -----BEGIN PUBLIC KEY----- 헤더/푸터가 포함되어 있는지 확인하세요.'
                }
            });
        }

        const algorithmOid = decodeOid(spkiBytes.slice(algOidTlv.valueStart, algOidTlv.valueEnd));
        const algorithmName = KNOWN_ALGORITHMS[algorithmOid] || (algorithmOid ? `OID ${algorithmOid}` : null);

        let curveOid = null;
        let curveName = null;
        if (algOidTlv.nextOffset < algSeq.valueEnd) {
            const paramTlv = readDerTlv(spkiBytes, algOidTlv.nextOffset);
            if (!paramTlv || paramTlv.nextOffset !== algSeq.valueEnd) {
                return createPubKeyFailReport({
                    ...baseMeta,
                    algorithmOid,
                    algorithmName,
                    error: {
                        code: 'INVALID_SPKI_DER',
                        subReason: 'algorithm_parameters',
                        message: '공개키(SPKI) 내부 구조가 손상되었습니다. 복사 과정에서 문자가 누락되었거나 줄바꿈이 깨지지 않았는지, -----BEGIN PUBLIC KEY----- 헤더/푸터가 포함되어 있는지 확인하세요.'
                    }
                });
            }
            if (paramTlv.tag === 0x06) {
                curveOid = decodeOid(spkiBytes.slice(paramTlv.valueStart, paramTlv.valueEnd));
                curveName = KNOWN_CURVES[curveOid] || (curveOid ? `OID ${curveOid}` : null);
            }
        }

        const algCurveMeta = { ...baseMeta, algorithmOid, algorithmName, curveOid, curveName };

        // Parse subjectPublicKey BIT STRING
        const bitStringTlv = readDerTlv(spkiBytes, algSeq.nextOffset);
        if (
            !bitStringTlv ||
            bitStringTlv.tag !== 0x03 ||
            bitStringTlv.nextOffset !== outerSeq.valueEnd ||
            bitStringTlv.length < 2 ||
            spkiBytes[bitStringTlv.valueStart] !== 0x00
        ) {
            return createPubKeyFailReport({
                ...algCurveMeta,
                error: {
                    code: 'INVALID_SPKI_DER',
                    subReason: 'subject_public_key_bit_string',
                    message: '공개키(SPKI) 내부 구조가 손상되었습니다. 복사 과정에서 문자가 누락되었거나 줄바꿈이 깨지지 않았는지, -----BEGIN PUBLIC KEY----- 헤더/푸터가 포함되어 있는지 확인하세요.'
                }
            });
        }

        if (algorithmOid !== OID_EC_PUBLIC_KEY) {
            const isRsa = algorithmOid === OID_RSA_ENCRYPTION;
            return createPubKeyFailReport({
                ...algCurveMeta,
                error: {
                    code: isRsa ? 'UNSUPPORTED_ALGORITHM_RSA' : 'UNSUPPORTED_ALGORITHM',
                    message: isRsa
                        ? `RSA 공개키(OID ${OID_RSA_ENCRYPTION})는 지원하지 않습니다. FIDO2 PoP 게이트웨이는 ECDSA P-256 공개키만 허용합니다.`
                        : `지원하지 않는 공개키 알고리즘(${algorithmName || algorithmOid})입니다. ECDSA(OID ${OID_EC_PUBLIC_KEY})만 지원합니다.`
                }
            });
        }

        if (curveOid !== OID_P256) {
            return createPubKeyFailReport({
                ...algCurveMeta,
                error: {
                    code: 'UNSUPPORTED_CURVE',
                    message: `지원하지 않는 타원곡선(${curveName || curveOid || '미지정'})입니다. FIDO2 PoP 게이트웨이는 P-256(OID ${OID_P256})만 지원합니다.`
                }
            });
        }

        const pointBytes = spkiBytes.slice(bitStringTlv.valueStart + 1, bitStringTlv.valueEnd);
        const prefix = pointBytes[0];
        if (prefix !== 0x04) {
            const prefixHex = '0x' + prefix.toString(16).padStart(2, '0');
            const pointFormat = (prefix === 0x02 || prefix === 0x03)
                ? `compressed(${prefixHex})`
                : `invalid(${prefixHex})`;
            return createPubKeyFailReport({
                ...algCurveMeta,
                pointFormat,
                error: {
                    code: 'INVALID_POINT_PREFIX',
                    message: `지원하지 않는 공개키 형식입니다. 이 진단기는 0x04로 시작하는 65바이트 비압축 공개키만 지원합니다(감지된 접두: ${prefixHex}). 압축형(02/03) 키는 비압축 형식으로 변환해서 입력하세요.`
                }
            });
        }

        const pointFormat = 'uncompressed(0x04)';
        if (pointBytes.length !== 65) {
            return createPubKeyFailReport({
                ...algCurveMeta,
                pointFormat,
                error: {
                    code: 'INVALID_POINT_LENGTH',
                    message: `공개키 좌표 바이트 길이(${pointBytes.length}B)가 올바르지 않습니다. FIDO2 PoP 게이트웨이는 65바이트 비압축 공개키(0x04 접두어 + X 32B + Y 32B)만 지원합니다.`
                }
            });
        }

        const xHex = bytesToHex(pointBytes.slice(1, 33));
        const yHex = bytesToHex(pointBytes.slice(33, 65));
        const xBig = BigInt('0x' + xHex);
        const yBig = BigInt('0x' + yHex);
        const onCurve = isPointOnP256Curve(xBig, yBig);

        if (!onCurve) {
            return createPubKeyFailReport({
                ...algCurveMeta,
                pointFormat,
                x: xHex,
                y: yHex,
                onCurve: false,
                error: {
                    code: 'POINT_NOT_ON_CURVE',
                    message: '유효하지 않은 공개키 좌표입니다(P-256 곡선 검증 실패). 좌표 데이터가 손상되었거나 P-256이 아닌 다른 곡선(예: secp256k1)의 키일 수 있습니다.'
                }
            });
        }

        return {
            ok: true,
            ...algCurveMeta,
            pointFormat,
            x: xHex,
            y: yHex,
            onCurve: true,
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
        OID_RSA_ENCRYPTION,
        OID_P256,
        isPointOnP256Curve,
        detectAndDecodeSignature,
        inspectDerStructure,
        inspectSignature,
        inspectPublicKey
    };
});
