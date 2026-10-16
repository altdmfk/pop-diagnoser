(function (root, factory) {
    let deps;
    if (typeof module !== 'undefined' && module.exports) {
        deps = Object.assign(
            {},
            require('./profiles/paper.js'),
            require('./encoding.js'),
            require('./ecdsa.js'),
            require('./inspect.js'),
            require('./curlParser.js'),
            require('./canonical.js'),
            require('./hypotheses.js'),
            require('./jsonError.js')
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
        STAGE_IDS = { HEADERS: 1, TIMESTAMP: 2, NONCE: 3, SIGNATURE: 4, DIGEST: 5 },
        PaperProfile,
        bytesToBinaryString,
        base64UrlDecode,
        base64StandardDecode,
        base64UrlEncodeBytes,
        hashString,
        hashStringToBase64Url,
        bytesToHex,
        PEM_PUBLIC_KEY_HEADER,
        PEM_PUBLIC_KEY_FOOTER,
        containsPrivateKeyMarker,
        extractPublicKeySpkiBytes,
        parseDerSignature,
        importPublicKey,
        derToRaw,
        verifySig,
        generateKeyPairAndSign,
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
        inspectPublicKey,
        MAX_INPUT_LENGTH = 512 * 1024,
        createEmptyInputs,
        parseCurl,
        parseRawHttp,
        buildString,
        HYPOTHESES,
        extractJsonErrorLocation,
        detectJsonErrorHint,
        JSON_HINT_CODES
    } = deps;

    const ERROR_CODES = {
        INVALID_JSON: 'ERR_INVALID_JSON',
        INVALID_URL: 'ERR_INVALID_URL',
        INVALID_PUBKEY: 'ERR_INVALID_PUBKEY',
        INVALID_SIGNATURE_ENCODING: 'ERR_INVALID_SIGNATURE_ENCODING',
        INVALID_TIMESTAMP: 'ERR_INVALID_TIMESTAMP',
        INPUT_TOO_LARGE: 'ERR_INPUT_TOO_LARGE'
    };

    const STAGE_CODES = {
        STAGE1_MISSING_PUBKEY: 'STAGE1_MISSING_PUBKEY',
        STAGE1_MISSING_FIELDS: 'STAGE1_MISSING_FIELDS',
        STAGE2_TIMESTAMP_EXPIRED: 'STAGE2_TIMESTAMP_EXPIRED',
        STAGE3_MISSING_NONCE: 'STAGE3_MISSING_NONCE',
        STAGE4_INVALID_SIG_LENGTH: 'STAGE4_INVALID_SIG_LENGTH',
        STAGE4_SIG_MISMATCH: 'STAGE4_SIG_MISMATCH',
        STAGE4_MISSING_DIGEST: 'STAGE4_MISSING_DIGEST',
        STAGE5_DIGEST_MISMATCH: 'STAGE5_DIGEST_MISMATCH',
        STAGE5_MISSING_DIGEST: 'STAGE5_MISSING_DIGEST'
    };

    const WARNING_CODES = {
        METHOD_UPPERCASED: 'METHOD_UPPERCASED',
        WHITESPACE_STRIPPED: 'WHITESPACE_STRIPPED',
        INVALID_JSON: ERROR_CODES.INVALID_JSON
    };

    function looksLikeJson(bodyStr, contentType) {
        if (!bodyStr || typeof bodyStr !== 'string') return false;
        const trimmed = bodyStr.trim();
        if (!trimmed) return false;
        if (typeof contentType === 'string' && contentType.trim().length > 0) {
            return /application\/([a-z0-9.+-]+\+)?json/i.test(contentType);
        }
        const first = trimmed[0];
        const last = trimmed[trimmed.length - 1];
        if (first === '{') {
            return true;
        }
        if (first === '[') {
            return last === ']' || /^\[\s*(?:["'\d{\[\]]|true\b|false\b|null\b)/.test(trimmed);
        }
        if (last === '}') {
            return /"[^"\\\r\n]*"\s*:/.test(trimmed);
        }
        if (last === ']') {
            return /^["'\d{\[]/.test(trimmed);
        }
        return false;
    }

    function validateJsonBody(bodyStr, errorMessage, contentType) {
        if (!looksLikeJson(bodyStr, contentType)) return null;
        try {
            JSON.parse(bodyStr);
            return null;
        } catch (e) {
            const defaultMsg = '요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n중괄호({, }), 쉼표(,), 따옴표(")가 빠졌거나 오타가 있는지 확인해 주세요.';
            const baseMsg = errorMessage || defaultMsg;
            const loc = typeof extractJsonErrorLocation === 'function'
                ? extractJsonErrorLocation(e, bodyStr)
                : {
                    message: e && e.message ? e.message : String(e),
                    cleanMessage: e && e.message ? e.message : String(e),
                    line: null,
                    column: null,
                    problemLine: null
                };
            const detail = (loc.line !== null && loc.column !== null && loc.problemLine !== null)
                ? `${loc.cleanMessage}\n\n[문제 발생 위치: ${loc.line}번째 줄, ${loc.column}번째 칸]\n${loc.problemLine}`
                : loc.message;
            return {
                code: WARNING_CODES.INVALID_JSON,
                hintCode: loc.hintCode,
                message: baseMsg,
                detail,
                line: loc.line,
                column: loc.column,
                problemLine: loc.problemLine,
                cleanMessage: loc.cleanMessage,
                hint: loc.hint,
                hintExample: loc.hintExample
            };
        }
    }

    function normalizeInputs(inputs) {
        const safe = inputs || {};
        return {
            method: String(safe.method ?? ""),
            urlStr: String(safe.urlStr ?? ""),
            bodyStr: String(safe.bodyStr ?? ""),
            nonce: String(safe.nonce ?? ""),
            timestampStr: String(safe.timestampStr ?? ""),
            signature: String(safe.signature ?? ""),
            pubkeyPem: String(safe.pubkeyPem ?? ""),
            reqDigest: String(safe.reqDigest ?? ""),
            contentType: String(safe.contentType ?? ""),
            evalTime: safe.evalTime
        };
    }

    function evaluateStage1Headers(norm, profile) {
        const def = profile.stages[STAGE_IDS.HEADERS];
        const missingReqFields = [];
        if (!norm.method.trim()) missingReqFields.push('HTTP 메서드');
        if (!norm.urlStr.trim()) missingReqFields.push('요청 URL');
        if (profile.stripWhitespace ? !norm.nonce.trim() : !norm.nonce) missingReqFields.push('Nonce');
        if (!norm.timestampStr.trim()) missingReqFields.push('Timestamp');
        if (!norm.signature.trim()) missingReqFields.push('Signature(서명)');

        const missingPubkey = !norm.pubkeyPem.trim();
        const passed = missingReqFields.length === 0 && !missingPubkey;

        let failReason = def.failReason;
        let code = null;
        if (!passed) {
            if (missingReqFields.length === 0 && missingPubkey) {
                code = STAGE_CODES.STAGE1_MISSING_PUBKEY;
                failReason = "검증에 필요한 공개키(PEM)가 비어 있습니다. '검증 설정' 탭에서 공개키를 입력해 주세요.";
            } else {
                code = STAGE_CODES.STAGE1_MISSING_FIELDS;
                const allMissing = missingPubkey
                    ? [...missingReqFields, '공개키(PEM)']
                    : missingReqFields;
                failReason = `필수 항목 중 누락된 값이 있습니다: ${allMissing.join(', ')}`;
            }
        }

        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "pass" : "fail",
                code,
                reason: passed ? def.passReason : failReason
            }
        };
    }

    function decodeSignatureWithFallback(signature, minByteLength) {
        const decoded = detectAndDecodeSignature(signature);
        if (decoded.error || !decoded.bytes) {
            const err = new Error(decoded.error ? decoded.error.message : "Invalid signature encoding");
            err.code = decoded.error ? decoded.error.code : 'INVALID_ENCODING';
            err.encoding = decoded.encoding || 'unknown';
            throw err;
        }
        const byteBuf = decoded.bytes.buffer.slice(
            decoded.bytes.byteOffset,
            decoded.bytes.byteOffset + decoded.bytes.byteLength
        );
        if (decoded.encoding === 'base64url') {
            return {
                encoding: 'base64url',
                signatureBytes: byteBuf,
                stdBase64Signature: null
            };
        }
        if (decoded.encoding === 'base64(standard)') {
            if (byteBuf.byteLength >= minByteLength) {
                return {
                    encoding: 'base64(standard)',
                    signatureBytes: new ArrayBuffer(0),
                    stdBase64Signature: byteBuf
                };
            }
            const err = new Error("Signature too short");
            err.code = 'INVALID_BYTE_LENGTH';
            err.encoding = 'base64(standard)';
            err.byteLength = byteBuf.byteLength;
            throw err;
        }
        const err = new Error(
            `서명이 Base64url이 아닌 16진수(Hex, ${byteBuf.byteLength}바이트) 형식으로 인코딩되어 있습니다. Base64url 형식으로 변환해 주세요.`
        );
        err.code = 'HEX_SIGNATURE_REJECTED';
        err.encoding = decoded.encoding;
        err.byteLength = byteBuf.byteLength;
        throw err;
    }

    function extractEffectiveHost(url, rawUrlStr) {
        if (url.protocol === 'https:' && !url.port) {
            const match = String(rawUrlStr || '').trim().match(/^https:\/\/([^/?#]*)/i);
            if (match) {
                const authority = match[1];
                const rawHostPort = authority.includes('@')
                    ? authority.slice(authority.lastIndexOf('@') + 1)
                    : authority;
                if (rawHostPort.endsWith(':443')) {
                    return `${url.hostname}:443`;
                }
            }
        }
        return url.host;
    }

    async function parseAndValidateInputs(norm, profile) {
        let url;
        try {
            url = new URL(norm.urlStr);
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                throw new Error("http:// 또는 https:// 프로토콜이 아닙니다.");
            }
        } catch (e) {
            return {
                error: {
                    code: ERROR_CODES.INVALID_URL,
                    message: 'URL 형식이 올바르지 않습니다.',
                    hint: "반드시 'https://' 또는 'http://' 로 시작하는 전체 인터넷 주소를 입력해야 합니다.",
                    hintExample: '(예: https://api.example.com/v1/tx)',
                    detail: e.message
                }
            };
        }

        const effectiveHost = extractEffectiveHost(url, norm.urlStr);

        let cryptoKey;
        try {
            cryptoKey = await importPublicKey(norm.pubkeyPem);
        } catch (e) {
            return {
                warnings: Array.isArray(e.warnings) ? e.warnings : [],
                error: {
                    code: ERROR_CODES.INVALID_PUBKEY,
                    causeCode: e.code || null,
                    message: e.message,
                    detail: e.message
                }
            };
        }

        let sigDecoded;
        try {
            sigDecoded = decodeSignatureWithFallback(norm.signature, profile.signatureByteLength);
        } catch (e) {
            return {
                error: {
                    code: ERROR_CODES.INVALID_SIGNATURE_ENCODING,
                    causeCode: e.code || null,
                    encoding: e.encoding || 'unknown',
                    byteLength: typeof e.byteLength === 'number' ? e.byteLength : null,
                    message: e.encoding === 'hex'
                        ? e.message
                        : "서명(Base64) 디코딩에 실패했습니다. 유효한 문자열인지 확인하세요.",
                    detail: e.message
                }
            };
        }

        const cleanTimestampStr = norm.timestampStr.trim();
        const timestamp = (/^\d+$/.test(cleanTimestampStr) && cleanTimestampStr.length <= 15)
            ? parseInt(cleanTimestampStr, 10)
            : NaN;
        if (cleanTimestampStr.length > 15 || !Number.isSafeInteger(timestamp)) {
            return {
                error: {
                    code: ERROR_CODES.INVALID_TIMESTAMP,
                    message: "타임스탬프가 숫자가 아닙니다.",
                    hint: "초 단위 정수 Unix 타임스탬프를 입력해야 합니다.",
                    hintExample: '(예: 1700000000)'
                }
            };
        }

        return {
            url,
            host: effectiveHost,
            cryptoKey,
            signatureBytes: sigDecoded.signatureBytes,
            stdBase64Signature: sigDecoded.stdBase64Signature,
            timestamp
        };
    }

    function evaluateStage2Timestamp(timestamp, evalTime, profile) {
        const def = profile.stages[STAGE_IDS.TIMESTAMP];
        let parsedEvalTime = NaN;
        if (typeof evalTime === 'number') {
            parsedEvalTime = evalTime;
        } else if (typeof evalTime === 'string' && evalTime.trim() !== '') {
            parsedEvalTime = Number(evalTime.trim());
        }
        const effectiveEvalTime = Number.isFinite(parsedEvalTime) ? parsedEvalTime : Math.floor(Date.now() / 1000);
        const timeDiff = Math.abs(effectiveEvalTime - timestamp);
        const passed = timeDiff <= profile.timestampToleranceSec;
        const stageName = typeof def.formatName === 'function'
            ? def.formatName(profile.timestampToleranceSec)
            : def.name;
        return {
            passed,
            stage: {
                name: stageName,
                status: passed ? "pass" : "fail",
                code: passed ? null : STAGE_CODES.STAGE2_TIMESTAMP_EXPIRED,
                reason: passed ? def.passReason : def.failReason(timeDiff)
            }
        };
    }

    function evaluateStage3Nonce(nonce, profile) {
        const def = profile.stages[STAGE_IDS.NONCE];
        const passed = !!(nonce && nonce.trim().length > 0);
        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "unknown" : "fail",
                code: passed ? null : STAGE_CODES.STAGE3_MISSING_NONCE,
                reason: passed ? def.unknownReason : def.failReason
            }
        };
    }

    function buildBaseRequest(norm, parsed, cleanReqDigest, profile, warnings) {
        const normalizedMethod = profile.methodCase === 'UPPER' ? norm.method.toUpperCase() : norm.method;
        if (norm.method !== normalizedMethod) {
            warnings.push({
                code: WARNING_CODES.METHOD_UPPERCASED,
                message: `입력하신 HTTP 메서드('${norm.method}')를 FIDO2 PoP 규격에 맞춰 대문자('${normalizedMethod}')로 강제 변환 후 진단했습니다.`
            });
        }
        const query = parsed.url.search.substring(1);
        return {
            method: normalizedMethod,
            host: parsed.host || parsed.url.host,
            path: parsed.url.pathname,
            query,
            rawBody: norm.bodyStr,
            bodyHash: cleanReqDigest,
            nonce: norm.nonce,
            timestamp: norm.timestampStr,
            delimiter: profile.delimiter,
            trailingNewline: profile.trailingNewline,
            rawSignature: parsed.signatureBytes,
            parsedSignature: parsed.signatureBytes,
            stdBase64Signature: parsed.stdBase64Signature
        };
    }

    async function evaluateStage4Signature(cryptoKey, baseReq, expectedCanonical, reqDigest, profile) {
        const def = profile.stages[STAGE_IDS.SIGNATURE];
        const actualBytes = baseReq.parsedSignature ? baseReq.parsedSignature.byteLength : 0;
        let status = "fail";
        let code = STAGE_CODES.STAGE4_INVALID_SIG_LENGTH;
        let reason = def.lengthFailReason(actualBytes, profile.signatureByteLength);

        if (actualBytes === profile.signatureByteLength) {
            const verified = await verifySig(cryptoKey, baseReq.parsedSignature, expectedCanonical);
            status = verified ? "pass" : "fail";
            code = verified ? null : STAGE_CODES.STAGE4_SIG_MISMATCH;
            reason = verified ? def.passReason : def.mismatchReason;
        }
        if (!reqDigest) {
            status = "fail";
            code = STAGE_CODES.STAGE4_MISSING_DIGEST;
            reason = def.missingDigestReason;
        }
        return {
            passed: status === "pass",
            stage: { name: def.name, status, code, reason }
        };
    }

    function evaluateStage5Digest(cleanReqDigest, bodyHashHex, profile) {
        const def = profile.stages[STAGE_IDS.DIGEST];
        const passed = Boolean(cleanReqDigest) && cleanReqDigest === bodyHashHex;
        const code = passed
            ? null
            : (cleanReqDigest ? STAGE_CODES.STAGE5_DIGEST_MISMATCH : STAGE_CODES.STAGE5_MISSING_DIGEST);
        const reason = cleanReqDigest
            ? (passed ? def.passReason : def.mismatchReason(cleanReqDigest, bodyHashHex))
            : def.missingDigestReason;
        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "pass" : "fail",
                code,
                reason
            }
        };
    }

    async function applyStage5Hypothesis(req, h, stage5Id) {
        return await h.apply(req, stage5Id);
    }

    async function searchStage5Hypotheses(baseReq, bodyHashHex, cleanReqDigest, profile) {
        if (!cleanReqDigest) {
            return { type: 'no-match', reduced: false };
        }
        const stage5Id = profile.stages[STAGE_IDS.DIGEST].id;
        const stage5Hypotheses = HYPOTHESES
            .filter(h => h.stage === stage5Id || h.stage === 'both')
            .slice()
            .sort((a, b) => (a.priority?.stage5 ?? 10) - (b.priority?.stage5 ?? 10));

        const stage5BaseReq = { ...baseReq, bodyHash: bodyHashHex, targetDigest: cleanReqDigest };
        const rootEntry = { depth: 0, matched: false, minNextIdx: 0, paths: [{ history: [], nextIdx: 0 }] };
        const queue = [{ req: stage5BaseReq, depth: 0, entry: rootEntry }];
        const stage5Matches = [];
        const stateCache = new Map();
        stateCache.set(
            `${stage5BaseReq.bodyHash}|${stage5BaseReq.rawBody.length}|${stage5BaseReq.rawBody.startsWith('\uFEFF') ? 1 : 0}|${stage5BaseReq.rawBody.endsWith('\n') ? 1 : 0}`,
            rootEntry
        );
        let evalCount = 0;
        let reduced = false;

        outerLoop:
        while (queue.length > 0) {
            const current = queue.shift();
            if (current.depth >= profile.maxComboDepth) continue;

            for (let i = current.entry.minNextIdx; i < stage5Hypotheses.length; i++) {
                const eligiblePaths = current.entry.paths.filter(p => i >= p.nextIdx);
                if (eligiblePaths.length === 0) continue;

                const h = stage5Hypotheses[i];
                const nextReq = await applyStage5Hypothesis(current.req, h, stage5Id);
                if (nextReq.bodyHash === current.req.bodyHash && nextReq.rawBody === current.req.rawBody) {
                    continue;
                }

                const nextDepth = current.depth + 1;
                const stateKey = `${nextReq.bodyHash}|${nextReq.rawBody.length}|${nextReq.rawBody.startsWith('\uFEFF') ? 1 : 0}|${nextReq.rawBody.endsWith('\n') ? 1 : 0}`;
                const cached = stateCache.get(stateKey);
                if (cached && cached.depth < nextDepth) {
                    continue;
                }

                const hMeta = {
                    id: h.id,
                    label: h.label,
                    tag: h.tag,
                    targetKind: h.targetKind,
                    priority: h.priority,
                    cause: h.cause,
                    solution: h.solution
                };
                const newPaths = eligiblePaths.map(p => ({
                    history: [...p.history, hMeta],
                    nextIdx: i + 1
                }));

                if (cached && cached.depth === nextDepth) {
                    if (cached.matched) {
                        for (const np of newPaths) {
                            stage5Matches.push({
                                history: np.history,
                                canonical: buildString({ ...baseReq, bodyHash: cleanReqDigest }, profile),
                                signatureHex: bytesToHex(baseReq.parsedSignature)
                            });
                        }
                    } else {
                        cached.paths.push(...newPaths);
                        if (i + 1 < cached.minNextIdx) {
                            cached.minNextIdx = i + 1;
                        }
                    }
                    continue;
                }

                if (evalCount >= profile.maxSearchNodes) {
                    reduced = true;
                    break outerLoop;
                }
                evalCount++;

                const isMatch = nextReq.bodyHash === cleanReqDigest && nextReq.bodyHash !== bodyHashHex;
                const newEntry = { depth: nextDepth, matched: isMatch, minNextIdx: i + 1, paths: newPaths };
                stateCache.set(stateKey, newEntry);

                if (isMatch) {
                    for (const np of newPaths) {
                        stage5Matches.push({
                            history: np.history,
                            canonical: buildString({ ...baseReq, bodyHash: cleanReqDigest }, profile),
                            signatureHex: bytesToHex(baseReq.parsedSignature)
                        });
                    }
                } else if (nextDepth < profile.maxComboDepth) {
                    queue.push({ req: nextReq, depth: nextDepth, entry: newEntry });
                }
            }
        }

        if (stage5Matches.length === 0) {
            return { type: 'no-match', reduced };
        }
        return { type: 'found', sets: groupAndMinimizeMatches(stage5Matches), reduced };
    }

    function filterMinimalMatches(groupMatches) {
        let minimal = [];
        for (let m of groupMatches) {
            const mIds = m.history.map(x => x.id);
            const isSuperset = minimal.some(minM => {
                const minIds = minM.history.map(x => x.id);
                return minIds.every(id => mIds.includes(id));
            });
            if (!isSuperset) {
                minimal = minimal.filter(minM => {
                    const minIds = minM.history.map(x => x.id);
                    return !mIds.every(id => minIds.includes(id));
                });
                minimal.push(m);
            }
        }
        return minimal;
    }

    function groupAndMinimizeMatches(matches) {
        const grouped = {};
        matches.forEach(m => {
            const key = m.canonical + "|" + m.signatureHex;
            if (!grouped[key]) grouped[key] = [];
            m.idStr = m.history.map(x => x.id).sort().join(',');
            grouped[key].push(m);
        });

        const finalSets = [];
        for (let key in grouped) {
            const minimal = filterMinimalMatches(grouped[key]);
            if (minimal.length > 1) {
                finalSets.push({ type: 'indistinguishable', items: minimal, canonical: minimal[0].canonical });
            } else if (minimal.length === 1) {
                finalSets.push({ type: 'match', item: minimal[0], items: minimal, canonical: minimal[0].canonical });
            }
        }
        return finalSets;
    }

    async function searchStage4Hypotheses(baseReq, cryptoKey, profile) {
        const stage4Id = profile.stages[STAGE_IDS.SIGNATURE].id;
        const stage4Hypotheses = HYPOTHESES
            .filter(h => h.stage === stage4Id || h.stage === 'both')
            .slice()
            .sort((a, b) => (a.priority?.stage4 ?? 10) - (b.priority?.stage4 ?? 10));

        const rootCanonical = buildString(baseReq, profile);
        const rootSigHex = bytesToHex(baseReq.parsedSignature);
        const rootEntry = { depth: 0, verified: false, minNextIdx: 0, paths: [{ history: [], nextIdx: 0 }] };
        const stateCache = new Map();
        stateCache.set(`${rootCanonical}|${rootSigHex}|${baseReq.stdBase64Signature ? 1 : 0}`, rootEntry);

        const queue = [{ req: baseReq, depth: 0, entry: rootEntry }];
        const matches = [];
        let verifyCount = 0;
        let reduced = false;

        outerLoop:
        while (queue.length > 0) {
            const current = queue.shift();
            if (current.depth >= profile.maxComboDepth) continue;

            const canonical = buildString(current.req, profile);
            const currentSigHex = bytesToHex(current.req.parsedSignature);

            for (let i = current.entry.minNextIdx; i < stage4Hypotheses.length; i++) {
                const eligiblePaths = current.entry.paths.filter(p => i >= p.nextIdx);
                if (eligiblePaths.length === 0) continue;

                const h = stage4Hypotheses[i];
                const nextReq = await h.apply(current.req, stage4Id);
                const nextCanonical = buildString(nextReq, profile);
                const nextSigHex = bytesToHex(nextReq.parsedSignature);
                if (nextCanonical === canonical && nextSigHex === currentSigHex) {
                    continue;
                }

                const nextDepth = current.depth + 1;
                const stateKey = `${nextCanonical}|${nextSigHex}|${nextReq.stdBase64Signature ? 1 : 0}`;
                const cached = stateCache.get(stateKey);
                if (cached && cached.depth < nextDepth) {
                    continue;
                }

                const hMeta = {
                    id: h.id,
                    label: h.label,
                    tag: h.tag,
                    targetKind: h.targetKind,
                    priority: h.priority,
                    cause: h.cause,
                    solution: h.solution
                };
                const newPaths = eligiblePaths.map(p => ({
                    history: [...p.history, hMeta],
                    nextIdx: i + 1
                }));

                if (cached && cached.depth === nextDepth) {
                    if (cached.verified) {
                        for (const np of newPaths) {
                            matches.push({
                                history: np.history,
                                canonical: nextCanonical,
                                signatureHex: nextSigHex
                            });
                        }
                    } else {
                        cached.paths.push(...newPaths);
                        if (i + 1 < cached.minNextIdx) {
                            cached.minNextIdx = i + 1;
                        }
                    }
                    continue;
                }

                let isSigValid = false;
                if (nextReq.parsedSignature.byteLength === profile.signatureByteLength) {
                    if (verifyCount >= profile.maxSearchNodes) {
                        reduced = true;
                        break outerLoop;
                    }
                    verifyCount++;
                    isSigValid = await verifySig(cryptoKey, nextReq.parsedSignature, nextCanonical);
                }
                const newEntry = { depth: nextDepth, verified: isSigValid, minNextIdx: i + 1, paths: newPaths };
                stateCache.set(stateKey, newEntry);

                if (isSigValid) {
                    for (const np of newPaths) {
                        matches.push({
                            history: np.history,
                            canonical: nextCanonical,
                            signatureHex: nextSigHex
                        });
                    }
                } else if (nextDepth < profile.maxComboDepth) {
                    queue.push({ req: nextReq, depth: nextDepth, entry: newEntry });
                }
            }
        }

        if (matches.length === 0) {
            return { type: 'no-match', reduced };
        }
        return { type: 'found', sets: groupAndMinimizeMatches(matches), reduced };
    }

    function mergeStage4AndStage5Sets(s4Sets, s5Sets) {
        const combinedMatches = [];
        for (const s4Set of s4Sets) {
            const s4Items = s4Set.type === 'indistinguishable' ? s4Set.items : [s4Set.item];
            for (const s5Set of s5Sets) {
                const s5Items = s5Set.type === 'indistinguishable' ? s5Set.items : [s5Set.item];
                for (const it4 of s4Items) {
                    for (const it5 of s5Items) {
                        const mergedHistory = [...it4.history];
                        for (const h5 of it5.history) {
                            if (!mergedHistory.some(existing => existing.id === h5.id)) {
                                mergedHistory.push(h5);
                            }
                        }
                        combinedMatches.push({
                            history: mergedHistory,
                            canonical: it4.canonical,
                            signatureHex: it4.signatureHex
                        });
                    }
                }
            }
        }
        return groupAndMinimizeMatches(combinedMatches);
    }

    async function diagnose(inputs, profile = PaperProfile) {
        const activeProfile = profile || PaperProfile;
        const norm = normalizeInputs(inputs);
        const result = {
            stages: [],
            warnings: [],
            error: null,
            firstFailedStage: null,
            expectedCanonical: "",
            stage5ExpectedCanonical: "",
            stage4HypothesisResult: null,
            stage5HypothesisResult: null,
            hypothesisResult: null
        };

        if (norm.bodyStr.length > MAX_INPUT_LENGTH || norm.urlStr.length > MAX_INPUT_LENGTH) {
            result.error = {
                code: ERROR_CODES.INPUT_TOO_LARGE,
                message: `입력 데이터 크기가 허용 한도(${Math.floor(MAX_INPUT_LENGTH / 1024)}KB)를 초과했습니다.`
            };
            return result;
        }

        const stripWhitespace = (inputs && inputs.stripWhitespace !== false) && (!profile || profile.stripWhitespace !== false);
        if (stripWhitespace) {
            const spacedFields = [];
            const cleanNoSpace = (name, val) => {
                if (typeof val === 'string' && /\s/.test(val)) {
                    spacedFields.push(name);
                    return val.replace(/\s/g, '');
                }
                return val;
            };

            norm.method = cleanNoSpace('HTTP 메서드', norm.method);
            norm.nonce = cleanNoSpace('Nonce', norm.nonce);
            norm.timestampStr = cleanNoSpace('Timestamp', norm.timestampStr);
            norm.signature = cleanNoSpace('Signature', norm.signature);
            norm.reqDigest = cleanNoSpace('Body-Digest', norm.reqDigest);

            if (spacedFields.length > 0) {
                result.warnings.push({
                    code: WARNING_CODES.WHITESPACE_STRIPPED,
                    message: `다음 입력값의 앞뒤나 중간에 잘못된 공백(띄어쓰기, 줄바꿈)이 포함되어 있어 제거 후 진단했습니다: ${spacedFields.join(', ')}`
                });
            }
        }

        const s1 = evaluateStage1Headers(norm, activeProfile);
        result.stages.push(s1.stage);

        const jsonWarn = validateJsonBody(
            norm.bodyStr,
            '요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n중괄호({, }), 쉼표(,), 따옴표(")가 빠졌거나 오타가 있는지 확인해 주세요.',
            norm.contentType
        );
        const appendJsonWarning = (digestFailed) => {
            if (!jsonWarn) return;
            const msgParts = [jsonWarn.message];
            if (jsonWarn.hint) {
                msgParts.push(`힌트: ${jsonWarn.hint}${jsonWarn.hintExample ? ' ' + jsonWarn.hintExample : ''}`);
            }
            if (digestFailed) {
                msgParts.push('5단계 본문 다이제스트 불일치가 이 JSON 문법 오류(중괄호·쉼표·따옴표 누락 등)로 인해 발생했을 수 있습니다.');
            }
            if (jsonWarn.detail) {
                msgParts.push(jsonWarn.detail);
            }
            result.warnings.unshift({
                ...jsonWarn,
                message: msgParts.join('\n')
            });
        };

        if (!s1.passed) {
            appendJsonWarning(false);
            result.firstFailedStage = activeProfile.stages[STAGE_IDS.HEADERS].id;
            return result;
        }

        const parsed = await parseAndValidateInputs(norm, activeProfile);
        if (parsed.error) {
            if (Array.isArray(parsed.warnings) && parsed.warnings.length > 0) {
                result.warnings.push(...parsed.warnings);
            }
            appendJsonWarning(false);
            result.error = parsed.error;
            return result;
        }

        const bodyHashHex = await hashString(norm.bodyStr);
        const cleanReqDigest = norm.reqDigest ? norm.reqDigest.replace(activeProfile.digestPrefix, '') : "";

        const s2 = evaluateStage2Timestamp(parsed.timestamp, norm.evalTime, activeProfile);
        result.stages.push(s2.stage);
        if (!s2.passed && !result.firstFailedStage) result.firstFailedStage = activeProfile.stages[STAGE_IDS.TIMESTAMP].id;

        const s3 = evaluateStage3Nonce(norm.nonce, activeProfile);
        result.stages.push(s3.stage);
        if (!s3.passed && !result.firstFailedStage) result.firstFailedStage = activeProfile.stages[STAGE_IDS.NONCE].id;

        const baseReq = buildBaseRequest(norm, parsed, cleanReqDigest, activeProfile, result.warnings);
        const stage4ExpectedCanonical = buildString(baseReq, activeProfile);
        const stage5ExpectedCanonical = buildString({ ...baseReq, bodyHash: bodyHashHex }, activeProfile);
        result.expectedCanonical = stage4ExpectedCanonical;
        result.stage5ExpectedCanonical = stage5ExpectedCanonical;

        const s4 = await evaluateStage4Signature(parsed.cryptoKey, baseReq, stage4ExpectedCanonical, cleanReqDigest, activeProfile);
        result.stages.push(s4.stage);
        if ((!cleanReqDigest || !s4.passed) && !result.firstFailedStage) {
            result.firstFailedStage = activeProfile.stages[STAGE_IDS.SIGNATURE].id;
        }

        const s5 = evaluateStage5Digest(cleanReqDigest, bodyHashHex, activeProfile);
        result.stages.push(s5.stage);
        if (!s5.passed && !result.firstFailedStage) {
            result.firstFailedStage = activeProfile.stages[STAGE_IDS.DIGEST].id;
        }

        appendJsonWarning(!s5.passed);

        if (s4.passed && s5.passed) {
            result.stage4HypothesisResult = { type: 'skipped' };
            result.stage5HypothesisResult = { type: 'skipped' };
            result.hypothesisResult = { type: 'skipped' };
            return result;
        }

        if (s4.passed && !s5.passed) {
            result.expectedCanonical = stage5ExpectedCanonical;
            const s5Res = await searchStage5Hypotheses(baseReq, bodyHashHex, cleanReqDigest, activeProfile);
            result.stage4HypothesisResult = { type: 'skipped' };
            result.stage5HypothesisResult = { stage: 5, expectedCanonical: stage5ExpectedCanonical, ...s5Res };
            result.hypothesisResult = s5Res;
            return result;
        }

        if (!s4.passed && s5.passed) {
            const s4Res = await searchStage4Hypotheses(baseReq, parsed.cryptoKey, activeProfile);
            result.stage4HypothesisResult = { stage: 4, expectedCanonical: stage4ExpectedCanonical, ...s4Res };
            result.stage5HypothesisResult = { type: 'skipped' };
            result.hypothesisResult = s4Res;
            return result;
        }

        // Both Stage 4 and Stage 5 failed simultaneously (!s4.passed && !s5.passed)
        const s4Res = await searchStage4Hypotheses(baseReq, parsed.cryptoKey, activeProfile);
        const s5Res = await searchStage5Hypotheses(baseReq, bodyHashHex, cleanReqDigest, activeProfile);
        result.stage4HypothesisResult = { stage: 4, expectedCanonical: stage4ExpectedCanonical, ...s4Res };
        result.stage5HypothesisResult = { stage: 5, expectedCanonical: stage5ExpectedCanonical, ...s5Res };

        if (s4Res.type === 'found' && s5Res.type === 'found') {
            result.expectedCanonical = stage5ExpectedCanonical;
            result.hypothesisResult = {
                type: 'found',
                sets: mergeStage4AndStage5Sets(s4Res.sets, s5Res.sets),
                reduced: Boolean(s4Res.reduced || s5Res.reduced),
                stage4: result.stage4HypothesisResult,
                stage5: result.stage5HypothesisResult
            };
        } else if (s4Res.type === 'found') {
            result.hypothesisResult = {
                ...s4Res,
                stage4: result.stage4HypothesisResult,
                stage5: result.stage5HypothesisResult
            };
        } else if (s5Res.type === 'found') {
            result.expectedCanonical = stage5ExpectedCanonical;
            result.hypothesisResult = {
                ...s5Res,
                reduced: Boolean(s4Res.reduced || s5Res.reduced),
                stage4: result.stage4HypothesisResult,
                stage5: result.stage5HypothesisResult
            };
        } else {
            result.hypothesisResult = {
                type: 'no-match',
                reduced: Boolean(s4Res.reduced || s5Res.reduced),
                stage4: result.stage4HypothesisResult,
                stage5: result.stage5HypothesisResult
            };
        }
        return result;
    }

    /**
     * 에러 처리 규약 안내 (`diagnose` vs `generateTestSignature`):
     * - `diagnose(inputs, profile)`는 다단계 진단 파이프라인이므로, 입력 형식 오류가 있어도 예외를 던지지 않고
     *   진단 리포트 객체(`{ stages, warnings, error: { code, message, ... } }`)를 반환해 UI/CLI가 단일 경로로 렌더링하게 한다.
     * - 반면 `generateTestSignature(inputs, profile)`는 키쌍 생성 및 서명 수행이라는 단일 명령형 액션 유틸리티이므로,
     *   URL 형식 오류처럼 서명 대상 자체를 구성할 수 없는 치명적 입력 오류 시에만 `Error`를 throw(Promise reject)하고,
     *   본문 JSON 문법 오류는 서명 생성을 차단하지 않고 반환 객체의 `warning` 필드(`{ code, message, detail, ... }`)로 전달한다.
     */
    async function generateTestSignature(inputs, profile = PaperProfile) {
        const activeProfile = profile || PaperProfile;
        const norm = normalizeInputs(inputs);
        if (norm.bodyStr.length > MAX_INPUT_LENGTH || norm.urlStr.length > MAX_INPUT_LENGTH) {
            const err = new Error(`입력 데이터 크기가 허용 한도(${Math.floor(MAX_INPUT_LENGTH / 1024)}KB)를 초과했습니다.`);
            err.code = ERROR_CODES.INPUT_TOO_LARGE;
            throw err;
        }
        const shouldStrip = !inputs || inputs.stripWhitespace !== false;
        const cleanUrlStr = shouldStrip ? norm.urlStr.trim() : norm.urlStr;
        const cleanMethod = shouldStrip ? norm.method.replace(/\s+/g, '') : norm.method;
        const cleanNonce = shouldStrip ? norm.nonce.replace(/\s+/g, '') : norm.nonce;
        const cleanTimestampStr = shouldStrip ? norm.timestampStr.replace(/\s+/g, '') : norm.timestampStr;

        let url;
        try {
            url = new URL(cleanUrlStr);
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                throw new Error('Only HTTP(S) URLs are supported');
            }
        } catch (e) {
            const err = new Error("URL이 올바르지 않습니다.");
            err.code = ERROR_CODES.INVALID_URL;
            throw err;
        }

        if (
            !cleanTimestampStr ||
            !/^\d+$/.test(cleanTimestampStr) ||
            cleanTimestampStr.length > 15 ||
            !Number.isSafeInteger(Number(cleanTimestampStr))
        ) {
            const err = new Error("Timestamp가 올바른 숫자 형식이 아닙니다.");
            err.code = ERROR_CODES.INVALID_TIMESTAMP;
            throw err;
        }

        const jsonWarn = validateJsonBody(
            norm.bodyStr,
            '요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n게이트웨이는 본문을 원문 바이트 그대로 해시하므로 현재 문자열 기준으로 서명을 생성했지만, 중괄호({, }), 쉼표(,), 따옴표(") 누락이나 오타가 있는지 확인해 주세요.',
            norm.contentType
        );

        const digestHex = await hashString(norm.bodyStr);
        const prefixStr = activeProfile.digestPrefixStr || "sha256=";
        const reqDigest = prefixStr + digestHex;
        const canonicalStr = buildString({
            method: activeProfile.methodCase === 'UPPER' ? cleanMethod.toUpperCase() : cleanMethod,
            host: extractEffectiveHost(url, cleanUrlStr),
            path: url.pathname,
            query: url.search.substring(1) || "",
            bodyHash: digestHex,
            nonce: cleanNonce,
            timestamp: cleanTimestampStr,
            delimiter: activeProfile.delimiter,
            trailingNewline: activeProfile.trailingNewline
        }, activeProfile);

        const { pubkeyPem, signatureBytes } = await generateKeyPairAndSign(canonicalStr);
        return {
            pubkeyPem,
            reqDigest,
            signature: base64UrlEncodeBytes(signatureBytes),
            canonicalStr,
            warning: jsonWarn || null
        };
    }

    // 명시적 공개 API 목록만 노출 (_atob, _btoa, _crypto, binaryStringToBytes 등 내부 헬퍼 제외)
    return {
        diagnose,
        looksLikeJson,
        validateJsonBody,
        generateTestSignature,
        ERROR_CODES,
        STAGE_CODES,
        WARNING_CODES,
        STAGE_IDS,
        PaperProfile,
        HYPOTHESES,
        buildString,
        verifySig,
        generateKeyPairAndSign,
        JSON_HINT_CODES,
        detectJsonErrorHint,
        extractJsonErrorLocation,
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
        inspectPublicKey,
        MAX_INPUT_LENGTH,
        createEmptyInputs,
        parseCurl,
        parseRawHttp,
        containsPrivateKeyMarker,
        extractPublicKeySpkiBytes,
        parseDerSignature,
        importPublicKey,
        derToRaw,
        PEM_PUBLIC_KEY_HEADER,
        PEM_PUBLIC_KEY_FOOTER,
        base64UrlDecode,
        base64StandardDecode,
        base64UrlEncodeBytes,
        bytesToHex,
        bytesToBinaryString,
        hashString,
        hashStringToBase64Url
    };
});
