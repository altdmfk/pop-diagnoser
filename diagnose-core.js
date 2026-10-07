const PopCore = (() => {
    const _atob = typeof atob !== 'undefined' ? atob : (str) => Buffer.from(str, 'base64').toString('binary');
    const _btoa = typeof btoa !== 'undefined' ? btoa : (str) => Buffer.from(str, 'binary').toString('base64');
    const _crypto = typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto;

    function base64UrlDecode(base64url) {
        if (!/^[A-Za-z0-9\-_]+={0,2}$/.test(base64url)) {
            throw new Error("Invalid base64url format");
        }
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        const rawData = _atob(base64);
        const output = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; i++) {
            output[i] = rawData.charCodeAt(i);
        }
        return output.buffer;
    }

    async function hashString(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await _crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function hashStringToBase64Url(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await _crypto.subtle.digest('SHA-256', data);
        let b64 = _btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
        return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    async function importPublicKey(pem) {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
            throw new Error("공개키(PEM) 형식이 올바르지 않습니다.");
        }
        const pemContents = pem.substring(pem.indexOf(pemHeader) + pemHeader.length, pem.indexOf(pemFooter)).replace(/\s/g, '');
        let binaryDerString;
        try {
            binaryDerString = _atob(pemContents);
        } catch (e) {
            throw new Error("공개키(PEM) 디코딩에 실패했습니다.");
        }
        const binaryDer = new Uint8Array(binaryDerString.length);
        for (let i = 0; i < binaryDerString.length; i++) {
            binaryDer[i] = binaryDerString.charCodeAt(i);
        }
        return await _crypto.subtle.importKey(
            "spki",
            binaryDer.buffer,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );
    }

    function derToRaw(derBytes) {
        const view = new Uint8Array(derBytes);
        if (view.length < 70) return null; // Too short for DER
        if (view[0] !== 0x30) return null;
        let offset = 2; // assume short length for ECDSA P-256
        if (view[1] > 0x80) offset += view[1] - 0x80 + 1; // plus 1 for length byte itself
        
        if (view[offset] !== 0x02) return null;
        let rLen = view[offset + 1];
        let rStart = offset + 2;
        if (view[rStart] === 0x00) { rStart++; rLen--; }
        const r = view.slice(rStart, rStart + rLen);
        
        offset = rStart + rLen;
        if (view[offset] !== 0x02) return null;
        let sLen = view[offset + 1];
        let sStart = offset + 2;
        if (view[sStart] === 0x00) { sStart++; sLen--; }
        const s = view.slice(sStart, sStart + sLen);

        const raw = new Uint8Array(64);
        raw.set(r.slice(Math.max(0, rLen - 32)), Math.max(0, 32 - rLen));
        raw.set(s.slice(Math.max(0, sLen - 32)), 32 + Math.max(0, 32 - sLen));
        return raw.buffer;
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

    const HYPOTHESES = [
        {
            id: 'query-unsorted',
            label: '쿼리를 URL에 적힌 원래 순서 그대로 사용',
            tag: 'common-mistake',
            apply: async (req) => ({ ...req, query: req.rawQuery })
        },
        {
            id: 'query-sorted',
            label: '쿼리를 알파벳순 정렬',
            tag: 'common-mistake',
            apply: async (req) => {
                if (!req.rawQuery) return req;
                const sorted = req.rawQuery.split('&').sort().join('&');
                return { ...req, query: sorted };
            }
        },
        {
            id: 'query-reverse',
            label: '쿼리를 역순으로 뒤집음',
            tag: 'common-mistake',
            apply: async (req) => {
                if (!req.rawQuery) return req;
                return { ...req, query: req.rawQuery.split('&').reverse().join('&') };
            }
        },
        {
            id: 'method-lowercase',
            label: 'HTTP 메서드를 소문자로 사용',
            tag: 'common-mistake',
            apply: async (req) => ({ ...req, method: req.method.toLowerCase() })
        },
        {
            id: 'path-trailing-slash-add',
            label: 'Path 끝에 슬래시(/) 추가',
            tag: 'common-mistake',
            apply: async (req) => ({ ...req, path: req.path.endsWith('/') ? req.path : req.path + '/' })
        },
        {
            id: 'path-trailing-slash-remove',
            label: 'Path 끝에 슬래시(/) 제거',
            tag: 'common-mistake',
            apply: async (req) => ({ ...req, path: req.path.endsWith('/') && req.path.length > 1 ? req.path.slice(0, -1) : req.path })
        },
        {
            id: 'host-rewritten',
            label: 'Host 포트 누락/추가 또는 대소문자 변형',
            tag: 'common-mistake',
            apply: async (req) => {
                let newHost = req.host;
                if (newHost.includes(':')) {
                    newHost = newHost.split(':')[0]; // 포트 제거
                } else {
                    newHost = newHost + ':443'; // 포트 추가
                }
                return { ...req, host: newHost };
            }
        },
        {
            id: 'sig-der',
            label: '서명이 DER 형식으로 인코딩됨',
            tag: 'encoding',
            apply: async (req) => {
                if (req.rawSignature.byteLength < 70) return req;
                const raw = derToRaw(req.rawSignature);
                if (!raw) return req;
                return { ...req, parsedSignature: raw };
            }
        },
        {
            id: 'sig-base64url',
            label: '서명 디코딩 변형 (Base64url)',
            tag: 'encoding',
            apply: async (req) => req
        }
    ];

    function buildString(req) {
        let str = [req.method, req.host, req.path, req.query, req.bodyHash, req.nonce, req.timestamp].join(req.delimiter);
        if (req.trailingNewline) str += req.delimiter;
        return str;
    }

    function bytesToHex(buffer) {
        return Array.from(new Uint8Array(buffer)).map(b=>b.toString(16).padStart(2,'0')).join('');
    }

    async function diagnose(inputs) {
        const { method, urlStr, bodyStr, nonce, timestampStr, signature, pubkeyPem, evalTime, reqDigest, credentialId } = inputs;
        
        const result = {
            stages: [],
            error: null,
            firstFailedStage: null,
            expectedCanonical: "",
            hypothesisResult: null 
        };

        // Inputs parsing & formatting checks
        let url;
        try { url = new URL(urlStr); } 
        catch (e) { 
            result.error = { message: "올바른 URL을 입력해주세요." }; 
            return result; 
        }

        const host = url.host;
        const path = url.pathname;
        const query = url.search.substring(1); 

        let cryptoKey, signatureBytes;
        try {
            cryptoKey = await importPublicKey(pubkeyPem);
        } catch (e) {
            result.error = { message: e.message };
            return result;
        }

        try {
            signatureBytes = base64UrlDecode(signature);
        } catch (e) {
            result.error = { message: "서명(Base64) 디코딩에 실패했습니다. 유효한 문자열인지 확인하세요." };
            return result;
        }

        const timestamp = parseInt(timestampStr, 10);
        if (isNaN(timestamp)) {
            result.error = { message: "타임스탬프가 숫자가 아닙니다." };
            return result;
        }

        const bodyHashHex = await hashString(bodyStr || "");
        let cleanReqDigest = "";
        if (reqDigest) {
            cleanReqDigest = reqDigest.replace(/^sha256=/i, '');
        }
        
        // Stage 1: Headers presence
        const headersPresent = !!(method && urlStr && nonce && timestampStr && signature && pubkeyPem && credentialId);
        result.stages.push({
            name: "1단계: 필수 헤더 검사 (Fast-Fail)",
            status: headersPresent ? "partial" : "fail",
            reason: headersPresent ? "필수 헤더 존재함 (단, Authorization은 검사 생략, 상태: 401 가능)" : "Method, URL, Nonce, Timestamp, 서명, Credential-ID 중 누락 (상태: 401)"
        });
        if (!headersPresent) { result.firstFailedStage = 1; return result; }

        // Stage 2: Timestamp
        const timeDiff = Math.abs(evalTime - timestamp);
        const timePassed = timeDiff <= 60;
        result.stages.push({
            name: "2단계: 타임스탬프 허용 오차(60초) 검증",
            status: timePassed ? "pass" : "fail",
            reason: timePassed ? "기준 시간 허용 오차 이내" : `기준 시간과 ${timeDiff}초 차이납니다. (만료)`
        });
        if (!timePassed && !result.firstFailedStage) result.firstFailedStage = 2;

        // Stage 3: Nonce
        const noncePresent = nonce && nonce.trim().length > 0;
        result.stages.push({
            name: "3단계: Nonce 검증",
            status: noncePresent ? "unknown" : "fail",
            reason: noncePresent ? "존재 및 형식 확인 (소비 여부 판단 불가: 서버 상태 필요)" : "Nonce가 비어 있습니다."
        });
        if (!noncePresent && !result.firstFailedStage) result.firstFailedStage = 3;

        const baseReq = {
            method: method.toUpperCase(),
            host: host,
            path: path,
            query: query,
            rawQuery: query,
            rawBody: bodyStr || "",
            bodyHash: cleanReqDigest, // Use HEADER for canonical string
            nonce: nonce,
            timestamp: timestampStr,
            delimiter: '\n',
            trailingNewline: false,
            rawSignature: signatureBytes,
            parsedSignature: signatureBytes
        };

        const expectedCanonical = buildString(baseReq);
        result.expectedCanonical = expectedCanonical;

        // Stage 4: Signature Math
        let sigLengthValid = baseReq.parsedSignature.byteLength === 64;
        let sigStatus = "fail";
        let sigReason = "형식 불일치 (64바이트 아님)";

        if (sigLengthValid) {
            const baseVerify = await verifySig(cryptoKey, baseReq.parsedSignature, expectedCanonical);
            if (baseVerify) {
                sigStatus = "pass";
                sigReason = "ECDSA 검증 성공";
            } else {
                sigReason = "서명 검증 실패 (문자열 또는 키 불일치)";
            }
        }

        if (!reqDigest) {
            sigStatus = "fail";
            sigReason = "X-Body-Digest 헤더 누락 (게이트웨이는 서명 검증 전 400 반환)";
        }
        
        result.stages.push({
            name: "4단계: 타원곡선 서명 검증 (ECDSA Math)",
            status: sigStatus,
            reason: sigReason
        });
        
        if (!reqDigest && result.firstFailedStage === null) {
            result.firstFailedStage = 4; // Map it to Stage 4 to represent failure before signature math
        }


        if (sigStatus !== "pass" && !result.firstFailedStage) result.firstFailedStage = 4;

        // Stage 5: Digest Streaming (Only evaluated if Signature passes logically in gateway, but we evaluate all for diagnosis)
        let digestMatch = false;
        let digestReason = "";
        if (cleanReqDigest) {
            digestMatch = cleanReqDigest.toLowerCase() === bodyHashHex.toLowerCase();
            digestReason = digestMatch ? "본문 해시가 헤더와 일치함" : `본문 해시 불일치 (기대: ${cleanReqDigest}, 실제: ${bodyHashHex})`;
        } else {
            digestReason = "입력된 X-Body-Digest 헤더가 없습니다.";
        }
        
        result.stages.push({
            name: "5단계: 다이제스트 스트리밍 대조 (상태: 400)",
            status: digestMatch ? "pass" : "fail",
            reason: digestReason
        });
        
        if (!digestMatch && !result.firstFailedStage) result.firstFailedStage = 5;

        if (sigStatus === "pass" && digestMatch) {
            result.hypothesisResult = { type: 'skipped', matches: [] };
            return result;
        }

        // If Signature passed but Digest failed, we only check Digest hypotheses
        if (sigStatus === "pass" && !digestMatch) {
            let found = null;
            let b64Hash = await hashStringToBase64Url(baseReq.rawBody);
            if (cleanReqDigest === b64Hash) found = "digest-base64url";
            
            if (!found && cleanReqDigest.toLowerCase() === await hashString(baseReq.rawBody).then(h => h.toLowerCase()) && cleanReqDigest !== cleanReqDigest.toLowerCase()) found = "digest-hex";
            
            if (!found) {
                let crlfBody = baseReq.rawBody.replace(/\n/g, "\r\n");
                if (cleanReqDigest === await hashString(crlfBody)) found = "newline-crlf";
            }
            if (!found) {
                let trailingBody = baseReq.rawBody + "\n";
                if (cleanReqDigest === await hashString(trailingBody)) found = "newline-trailing";
            }
            if (!found) {
                let bomBody = "\uFEFF" + baseReq.rawBody;
                if (cleanReqDigest === await hashString(bomBody)) found = "body-bom-added";
            }
            if (!found) {
                try {
                    let parsed = JSON.parse(baseReq.rawBody);
                    let noSpaceHash = await hashString(JSON.stringify(parsed));
                    if (cleanReqDigest === noSpaceHash) found = "body-reserialized-nospace";
                } catch(e) {}
            }
            
            if (found) {
                result.hypothesisResult = { type: 'match', idStr: found, history: [{id: found}] };
            } else {
                result.hypothesisResult = { type: 'no-match' };
            }
            return result;
        }

        // Hypothesis Search (For Signature failures)
        let queue = [{ req: baseReq, history: [], ids: new Set() }];
        let matches = [];
        let explored = 0;
        let reduced = false;
        
        while (queue.length > 0) {
            if (explored >= 2000) {
                reduced = true;
                break;
            }
            const current = queue.shift();
            explored++;

            const canonical = buildString(current.req);
            
            for (let h of HYPOTHESES) {
                if (current.ids.has(h.id)) continue;
                if (current.history.length >= 3 && !reduced) continue;

                let nextReq = await h.apply(current.req);
                let nextCanonical = buildString(nextReq);
                
                if (nextCanonical === canonical && bytesToHex(nextReq.parsedSignature) === bytesToHex(current.req.parsedSignature)) continue;
                
                let nextHistory = [...current.history, { id: h.id, label: h.label, tag: h.tag }];
                let nextIds = new Set(current.ids);
                nextIds.add(h.id);
                
                let isSigValid = false;
                if (nextReq.parsedSignature.byteLength === 64) {
                    isSigValid = await verifySig(cryptoKey, nextReq.parsedSignature, nextCanonical);
                }

                if (isSigValid) {
                    matches.push({
                        history: nextHistory,
                        canonical: nextCanonical,
                        signatureHex: bytesToHex(nextReq.parsedSignature)
                    });
                } else if (nextHistory.length < 3) {
                    queue.push({ req: nextReq, history: nextHistory, ids: nextIds });
                }
            }
        }

        if (matches.length > 0) {
            const grouped = {};
            matches.forEach(m => {
                const key = m.canonical + "|" + m.signatureHex;
                if (!grouped[key]) grouped[key] = [];
                m.idStr = m.history.map(x => x.id).sort().join(',');
                grouped[key].push(m);
            });

            const finalSets = [];
            for (let key in grouped) {
                let groupMatches = grouped[key];
                let minimal = [];
                for (let m of groupMatches) {
                    let mIds = m.history.map(x => x.id);
                    let isSuperset = minimal.some(minM => {
                        let minIds = minM.history.map(x => x.id);
                        return minIds.every(id => mIds.includes(id));
                    });
                    if (!isSuperset) {
                        minimal = minimal.filter(minM => {
                            let minIds = minM.history.map(x => x.id);
                            return !mIds.every(id => minIds.includes(id));
                        });
                        minimal.push(m);
                    }
                }
                
                if (minimal.length > 1) {
                    finalSets.push({ type: 'indistinguishable', items: minimal, canonical: minimal[0].canonical });
                } else if (minimal.length === 1) {
                    finalSets.push({ type: 'match', item: minimal[0], canonical: minimal[0].canonical });
                }
            }

            result.hypothesisResult = { type: 'found', sets: finalSets, reduced };
        } else {
            result.hypothesisResult = { type: 'no-match', reduced };
        }

        return result;
    }

    return { diagnose, HYPOTHESES };
})();
if (typeof module !== 'undefined') module.exports = PopCore;
