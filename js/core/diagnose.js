(function (root, factory) {
    let deps;
    if (typeof module !== 'undefined' && module.exports) {
        deps = Object.assign(
            {},
            require('./profiles/paper.js'),
            require('./encoding.js'),
            require('./ecdsa.js'),
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
        getJsonErrorSnippet
    } = deps;

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
        const def = profile.stages[1];
        const passed = !!(norm.method && norm.urlStr && norm.nonce && norm.timestampStr && norm.signature && norm.pubkeyPem);
        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "pass" : "fail",
                reason: passed ? def.passReason : def.failReason
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
        if (norm.bodyStr.trim()) {
            try {
                JSON.parse(norm.bodyStr);
            } catch (e) {
                return {
                    error: {
                        message: '요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n쉼표(,)나 따옴표(")가 빠졌거나 오타가 있는지 확인해 주세요.',
                        detail: getJsonErrorSnippet(e, norm.bodyStr)
                    }
                };
            }
        }

        let url;
        try {
            url = new URL(norm.urlStr);
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                throw new Error("http:// 또는 https:// 프로토콜이 아닙니다.");
            }
        } catch (e) {
            return {
                error: {
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
            return { error: { message: e.message } };
        }

        let sigDecoded;
        try {
            sigDecoded = decodeSignatureWithFallback(norm.signature, profile.signatureByteLength);
        } catch (e) {
            return { error: { message: "서명(Base64) 디코딩에 실패했습니다. 유효한 문자열인지 확인하세요." } };
        }

        const cleanTimestampStr = norm.timestampStr.trim();
        const timestamp = /^\d+$/.test(cleanTimestampStr) ? parseInt(cleanTimestampStr, 10) : NaN;
        if (isNaN(timestamp)) {
            return { error: { message: "타임스탬프가 숫자가 아닙니다." } };
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
        const def = profile.stages[2];
        const parsedEvalTime = (evalTime !== undefined && evalTime !== null && evalTime !== '') ? Number(evalTime) : NaN;
        const effectiveEvalTime = !Number.isNaN(parsedEvalTime) ? parsedEvalTime : Math.floor(Date.now() / 1000);
        const timeDiff = Math.abs(effectiveEvalTime - timestamp);
        const passed = timeDiff <= profile.timestampToleranceSec;
        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "pass" : "fail",
                reason: passed ? def.passReason : def.failReason(timeDiff)
            }
        };
    }

    function evaluateStage3Nonce(nonce, profile) {
        const def = profile.stages[3];
        const passed = !!(nonce && nonce.trim().length > 0);
        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "unknown" : "fail",
                reason: passed ? def.unknownReason : def.failReason
            }
        };
    }

    function buildBaseRequest(norm, parsed, cleanReqDigest, profile, warnings) {
        const normalizedMethod = profile.methodCase === 'UPPER' ? norm.method.toUpperCase() : norm.method;
        if (norm.method !== normalizedMethod) {
            warnings.push({
                message: `입력하신 HTTP 메서드('${norm.method}')를 FIDO2 PoP 규격에 맞춰 대문자('${normalizedMethod}')로 강제 변환 후 진단했습니다.`
            });
        }
        const query = parsed.url.search.substring(1);
        return {
            method: normalizedMethod,
            host: parsed.url.host,
            path: parsed.url.pathname,
            query,
            rawQuery: query,
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
        const def = profile.stages[4];
        const actualBytes = baseReq.parsedSignature ? baseReq.parsedSignature.byteLength : 0;
        let status = "fail";
        let reason = def.lengthFailReason(actualBytes, profile.signatureByteLength);

        if (actualBytes === profile.signatureByteLength) {
            const verified = await verifySig(cryptoKey, baseReq.parsedSignature, expectedCanonical);
            status = verified ? "pass" : "fail";
            reason = verified ? def.passReason : def.mismatchReason;
        }
        if (!reqDigest) {
            status = "fail";
            reason = def.missingDigestReason;
        }
        return {
            passed: status === "pass",
            stage: { name: def.name, status, reason }
        };
    }

    function evaluateStage5Digest(cleanReqDigest, bodyHashHex, profile) {
        const def = profile.stages[5];
        const passed = Boolean(cleanReqDigest) && cleanReqDigest === bodyHashHex;
        const reason = cleanReqDigest
            ? (passed ? def.passReason : def.mismatchReason(cleanReqDigest, bodyHashHex))
            : def.missingDigestReason;
        return {
            passed,
            stage: {
                name: def.name,
                status: passed ? "pass" : "fail",
                reason
            }
        };
    }

    async function searchStage5Hypotheses(baseReq, bodyHashHex, cleanReqDigest, profile) {
        const stage5Id = profile.stages[5].id;
        const stage5Hypotheses = HYPOTHESES.filter(h => h.stage === stage5Id || h.stage === 'both');
        const stage5BaseReq = { ...baseReq, bodyHash: bodyHashHex, targetDigest: cleanReqDigest };
        const stage5Matches = [];

        for (let h of stage5Hypotheses) {
            const nextReq = await h.apply(stage5BaseReq, stage5Id);
            if (nextReq.bodyHash === cleanReqDigest && nextReq.bodyHash !== bodyHashHex) {
                stage5Matches.push({
                    idStr: h.id,
                    history: [{ id: h.id, label: h.label, tag: h.tag }],
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
        const stage4Id = profile.stages[4].id;
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

                const nextHistory = [...current.history, { id: h.id, label: h.label, tag: h.tag }];
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

        const s1 = evaluateStage1Headers(norm, activeProfile);
        result.stages.push(s1.stage);
        if (!s1.passed) {
            result.firstFailedStage = activeProfile.stages[1].id;
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
        if (!s2.passed && !result.firstFailedStage) result.firstFailedStage = activeProfile.stages[2].id;

        const s3 = evaluateStage3Nonce(norm.nonce, activeProfile);
        result.stages.push(s3.stage);
        if (!s3.passed && !result.firstFailedStage) result.firstFailedStage = activeProfile.stages[3].id;

        const baseReq = buildBaseRequest(norm, parsed, cleanReqDigest, activeProfile, result.warnings);
        result.expectedCanonical = buildString(baseReq, activeProfile);

        const s4 = await evaluateStage4Signature(parsed.cryptoKey, baseReq, result.expectedCanonical, norm.reqDigest, activeProfile);
        result.stages.push(s4.stage);
        if ((!norm.reqDigest || !s4.passed) && !result.firstFailedStage) {
            result.firstFailedStage = activeProfile.stages[4].id;
        }

        const s5 = evaluateStage5Digest(cleanReqDigest, bodyHashHex, activeProfile);
        result.stages.push(s5.stage);
        if (!s5.passed && !result.firstFailedStage) {
            result.firstFailedStage = activeProfile.stages[5].id;
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

        if (norm.bodyStr.trim()) {
            try {
                JSON.parse(norm.bodyStr);
            } catch (e) {
                const err = new Error('요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\nJSON 문법(쉼표, 따옴표 등)을 먼저 수정해 주셔야 서명을 생성할 수 있습니다.');
                err.detail = getJsonErrorSnippet(e, norm.bodyStr);
                throw err;
            }
        }

        let url;
        try { url = new URL(norm.urlStr); } catch (e) { throw new Error("URL이 올바르지 않습니다."); }

        const digestHex = await hashString(norm.bodyStr);
        const reqDigest = "sha256=" + digestHex;
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
        PaperProfile
    });
});
