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
            require('../ui/jsonError.js')
        );
    } else {
        deps = Object.assign({}, root.PopCore, root.PopUI);
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
        base64UrlDecode,
        base64StandardDecode,
        base64UrlEncodeBytes,
        hashString,
        bytesToHex,
        importPublicKey,
        derToRaw,
        verifySig,
        generateKeyPairAndSign,
        buildString,
        HYPOTHESES,
        getJsonErrorSnippet,
        detectJsonErrorHint,
        JSON_HINT_CODES
    } = deps;

    const ERROR_CODES = {
        INVALID_JSON: 'ERR_INVALID_JSON',
        INVALID_URL: 'ERR_INVALID_URL',
        INVALID_PUBKEY: 'ERR_INVALID_PUBKEY',
        INVALID_SIGNATURE_ENCODING: 'ERR_INVALID_SIGNATURE_ENCODING',
        INVALID_TIMESTAMP: 'ERR_INVALID_TIMESTAMP'
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
        WHITESPACE_STRIPPED: 'WHITESPACE_STRIPPED'
    };

    function validateJsonBody(bodyStr, errorMessage) {
        if (!bodyStr || !bodyStr.trim()) return null;
        try {
            JSON.parse(bodyStr);
            return null;
        } catch (e) {
            const hintInfo = typeof detectJsonErrorHint === 'function' ? detectJsonErrorHint(e, bodyStr) : null;
            return {
                code: ERROR_CODES.INVALID_JSON,
                hintCode: hintInfo ? hintInfo.hintCode : undefined,
                message: errorMessage,
                detail: getJsonErrorSnippet(e, bodyStr),
                hint: hintInfo ? hintInfo.hint : undefined,
                hintExample: hintInfo ? hintInfo.hintExample : undefined
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
            evalTime: safe.evalTime
        };
    }

    function evaluateStage1Headers(norm, profile) {
        const def = profile.stages[STAGE_IDS.HEADERS];
        const missingReqFields = [];
        if (!norm.method) missingReqFields.push('HTTP 메서드');
        if (!norm.urlStr) missingReqFields.push('요청 URL');
        if (!norm.nonce) missingReqFields.push('Nonce');
        if (!norm.timestampStr) missingReqFields.push('Timestamp');
        if (!norm.signature) missingReqFields.push('Signature(서명)');

        const missingPubkey = !norm.pubkeyPem;
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
        try {
            return { signatureBytes: base64UrlDecode(signature), stdBase64Signature: null };
        } catch (e) {
            const candidate = base64StandardDecode(signature);
            if (candidate.byteLength >= minByteLength) {
                return { signatureBytes: new ArrayBuffer(0), stdBase64Signature: candidate };
            }
            throw new Error("Signature too short");
        }
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

        let cryptoKey;
        try {
            cryptoKey = await importPublicKey(norm.pubkeyPem);
        } catch (e) {
            return { error: { code: ERROR_CODES.INVALID_PUBKEY, message: e.message, detail: e.message } };
        }

        let sigDecoded;
        try {
            sigDecoded = decodeSignatureWithFallback(norm.signature, profile.signatureByteLength);
        } catch (e) {
            return { error: { code: ERROR_CODES.INVALID_SIGNATURE_ENCODING, message: "서명(Base64) 디코딩에 실패했습니다. 유효한 문자열인지 확인하세요.", detail: e.message } };
        }

        const cleanTimestampStr = norm.timestampStr.trim();
        const timestamp = /^\d+$/.test(cleanTimestampStr) ? parseInt(cleanTimestampStr, 10) : NaN;
        if (isNaN(timestamp)) {
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
            cryptoKey,
            signatureBytes: sigDecoded.signatureBytes,
            stdBase64Signature: sigDecoded.stdBase64Signature,
            timestamp
        };
    }

    function evaluateStage2Timestamp(timestamp, evalTime, profile) {
        const def = profile.stages[STAGE_IDS.TIMESTAMP];
        const parsedEvalTime = (evalTime !== undefined && evalTime !== null && evalTime !== '') ? Number(evalTime) : NaN;
        const effectiveEvalTime = !Number.isNaN(parsedEvalTime) ? parsedEvalTime : Math.floor(Date.now() / 1000);
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
            host: parsed.url.host,
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

    async function searchStage5Hypotheses(baseReq, bodyHashHex, cleanReqDigest, profile) {
        const stage5Id = profile.stages[STAGE_IDS.DIGEST].id;
        const stage5Hypotheses = HYPOTHESES.filter(h => h.stage === stage5Id || h.stage === 'both');
        const stage5BaseReq = { ...baseReq, bodyHash: bodyHashHex, targetDigest: cleanReqDigest };
        const stage5Matches = [];

        for (let h of stage5Hypotheses) {
            const nextReq = await h.apply(stage5BaseReq, stage5Id);
            if (nextReq.bodyHash === cleanReqDigest && nextReq.bodyHash !== bodyHashHex) {
                stage5Matches.push({
                    idStr: h.id,
                    history: [{ id: h.id, label: h.label, tag: h.tag, cause: h.cause, solution: h.solution }],
                    canonical: buildString({ ...baseReq, bodyHash: cleanReqDigest }, profile),
                    signatureHex: bytesToHex(baseReq.parsedSignature)
                });
            }
        }

        if (stage5Matches.length === 0) {
            return { type: 'no-match', reduced: false };
        }
        const sets = stage5Matches.length > 1
            ? [{ type: 'indistinguishable', items: stage5Matches, canonical: stage5Matches[0].canonical }]
            : [{ type: 'match', item: stage5Matches[0], canonical: stage5Matches[0].canonical }];
        return { type: 'found', sets, reduced: false };
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
                finalSets.push({ type: 'match', item: minimal[0], canonical: minimal[0].canonical });
            }
        }
        return finalSets;
    }

    async function searchStage4Hypotheses(baseReq, cryptoKey, profile) {
        const stage4Id = profile.stages[STAGE_IDS.SIGNATURE].id;
        const stage4Hypotheses = HYPOTHESES.filter(h => h.stage === stage4Id || h.stage === 'both');
        const queue = [{ req: baseReq, history: [], ids: new Set() }];
        const matches = [];
        let explored = 0;
        let reduced = false;

        while (queue.length > 0) {
            if (explored >= profile.maxSearchNodes) {
                reduced = true;
                break;
            }
            const current = queue.shift();
            explored++;
            const canonical = buildString(current.req, profile);

            for (let h of stage4Hypotheses) {
                if (current.ids.has(h.id)) continue;
                if (current.history.length >= profile.maxComboDepth && !reduced) continue;

                const nextReq = await h.apply(current.req, stage4Id);
                const nextCanonical = buildString(nextReq, profile);
                if (nextCanonical === canonical && bytesToHex(nextReq.parsedSignature) === bytesToHex(current.req.parsedSignature)) {
                    continue;
                }

                const nextHistory = [...current.history, { id: h.id, label: h.label, tag: h.tag, cause: h.cause, solution: h.solution }];
                const nextIds = new Set(current.ids);
                nextIds.add(h.id);

                const isSigValid = nextReq.parsedSignature.byteLength === profile.signatureByteLength
                    ? await verifySig(cryptoKey, nextReq.parsedSignature, nextCanonical)
                    : false;

                if (isSigValid) {
                    matches.push({
                        history: nextHistory,
                        canonical: nextCanonical,
                        signatureHex: bytesToHex(nextReq.parsedSignature)
                    });
                } else if (nextHistory.length < profile.maxComboDepth) {
                    queue.push({ req: nextReq, history: nextHistory, ids: nextIds });
                }
            }
        }

        if (matches.length === 0) {
            return { type: 'no-match', reduced };
        }
        return { type: 'found', sets: groupAndMinimizeMatches(matches), reduced };
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
            hypothesisResult: null
        };

        const jsonErr = validateJsonBody(
            norm.bodyStr,
            '요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n중괄호({, }), 쉼표(,), 따옴표(")가 빠졌거나 오타가 있는지 확인해 주세요.'
        );
        if (jsonErr) {
            result.error = jsonErr;
            return result;
        }

        const s1 = evaluateStage1Headers(norm, activeProfile);
        result.stages.push(s1.stage);
        if (!s1.passed) {
            result.firstFailedStage = activeProfile.stages[STAGE_IDS.HEADERS].id;
            return result;
        }

        const parsed = await parseAndValidateInputs(norm, activeProfile);
        if (parsed.error) {
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
        result.expectedCanonical = buildString(baseReq, activeProfile);

        const s4 = await evaluateStage4Signature(parsed.cryptoKey, baseReq, result.expectedCanonical, norm.reqDigest, activeProfile);
        result.stages.push(s4.stage);
        if ((!norm.reqDigest || !s4.passed) && !result.firstFailedStage) {
            result.firstFailedStage = activeProfile.stages[STAGE_IDS.SIGNATURE].id;
        }

        const s5 = evaluateStage5Digest(cleanReqDigest, bodyHashHex, activeProfile);
        result.stages.push(s5.stage);
        if (!s5.passed && !result.firstFailedStage) {
            result.firstFailedStage = activeProfile.stages[STAGE_IDS.DIGEST].id;
        }

        if (s4.passed && s5.passed) {
            result.hypothesisResult = { type: 'skipped' };
            return result;
        }

        if (s4.passed && !s5.passed) {
            result.expectedCanonical = buildString({ ...baseReq, bodyHash: bodyHashHex }, activeProfile);
            result.hypothesisResult = await searchStage5Hypotheses(baseReq, bodyHashHex, cleanReqDigest, activeProfile);
            return result;
        }

        result.hypothesisResult = await searchStage4Hypotheses(baseReq, parsed.cryptoKey, activeProfile);
        return result;
    }

    async function generateTestSignature(inputs, profile = PaperProfile) {
        const activeProfile = profile || PaperProfile;
        const norm = normalizeInputs(inputs);

        const jsonErr = validateJsonBody(
            norm.bodyStr,
            '요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\nJSON 문법(중괄호, 쉼표, 따옴표 등)을 먼저 수정해 주셔야 서명을 생성할 수 있습니다.'
        );
        if (jsonErr) {
            const err = new Error(jsonErr.message);
            err.code = jsonErr.code;
            err.detail = jsonErr.detail;
            if (jsonErr.hintCode) err.hintCode = jsonErr.hintCode;
            if (jsonErr.hint) err.hint = jsonErr.hint;
            if (jsonErr.hintExample) err.hintExample = jsonErr.hintExample;
            throw err;
        }

        let url;
        try {
            url = new URL(norm.urlStr);
        } catch (e) {
            const err = new Error("URL이 올바르지 않습니다.");
            err.code = ERROR_CODES.INVALID_URL;
            throw err;
        }

        const digestHex = await hashString(norm.bodyStr);
        const prefixStr = activeProfile.digestPrefixStr || "sha256=";
        const reqDigest = prefixStr + digestHex;
        const canonicalStr = buildString({
            method: activeProfile.methodCase === 'UPPER' ? norm.method.toUpperCase() : norm.method,
            host: url.host,
            path: url.pathname,
            query: url.search.substring(1) || "",
            bodyHash: digestHex,
            nonce: norm.nonce,
            timestamp: norm.timestampStr,
            delimiter: activeProfile.delimiter,
            trailingNewline: activeProfile.trailingNewline
        }, activeProfile);

        const { pubkeyPem, signatureBytes } = await generateKeyPairAndSign(canonicalStr);
        return {
            pubkeyPem,
            reqDigest,
            signature: base64UrlEncodeBytes(signatureBytes),
            canonicalStr
        };
    }

    return Object.assign({}, deps, {
        diagnose,
        generateTestSignature,
        HYPOTHESES,
        derToRaw,
        STAGE_IDS,
        PaperProfile,
        detectJsonErrorHint,
        JSON_HINT_CODES,
        ERROR_CODES,
        STAGE_CODES,
        WARNING_CODES
    });
});
