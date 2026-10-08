const PopCore = (() => {

function getJsonErrorSnippet(e, jsonStr) {
    let msg = e.message;
    try {
        const match = msg.match(/line\s+(\d+)\s+column\s+(\d+)/i) || msg.match(/position\s+(\d+)/i);
        if (match && jsonStr) {
            let lineNum = 1, colNum = 1;
            
            if (msg.includes('line') && msg.includes('column')) {
                lineNum = parseInt(match[1], 10);
                colNum = parseInt(match[2], 10);
            } else if (msg.includes('position')) {
                const pos = parseInt(match[1], 10);
                const upToPos = jsonStr.substring(0, pos);
                const lines = upToPos.split('\n');
                lineNum = lines.length;
                colNum = lines[lines.length - 1].length + 1;
            }
            
            const lines = jsonStr.split('\n');
            if (lineNum > 0 && lineNum <= lines.length) {
                const problemLine = lines[lineNum - 1];
                let pointer = '';
                for (let i = 0; i < colNum - 1; i++) {
                    pointer += problemLine[i] === '\t' ? '\t' : ' ';
                }
                pointer += '▲';
                
                msg = msg.replace(/in JSON at position.*$/, '').replace(/at line \d+ column \d+.*$/, '').trim();
                return `${msg}\n\n[문제 발생 위치: ${lineNum}번째 줄]\n${problemLine}\n${pointer}`;
            }
        }
    } catch (err) {}
    return msg;
}

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
        
        let hasHeader = pem.includes(pemHeader);
        let hasFooter = pem.includes(pemFooter);
        let pemContents = "";
        
        if (hasHeader && hasFooter) {
            pemContents = pem.substring(pem.indexOf(pemHeader) + pemHeader.length, pem.indexOf(pemFooter)).replace(/\s/g, '');
        } else if (!hasHeader && !hasFooter) {
            // 태그가 둘 다 없으면, 순수 Base64 값만 넣었다고 간주하고 그대로 시도합니다.
            pemContents = pem.replace(/\s/g, '');
        } else {
            // 태그가 하나만 있는 경우 실수로 잘린 것이므로 경고합니다.
            let missing = !hasHeader ? "시작 태그(-----BEGIN PUBLIC KEY-----)" : "종료 태그(-----END PUBLIC KEY-----)";
            throw new Error(`공개키 형식이 올바르지 않습니다. ${missing}가 잘려나갔습니다.\n아예 태그 없이 중간 값(Base64)만 넣으시거나, 양쪽 태그를 모두 포함해 주세요.`);
        }
        
        if (pemContents.length === 0) {
            throw new Error("공개키 내부에 실제 키 데이터(Base64)가 비어 있습니다.");
        }

        let binaryDerString;
        try {
            binaryDerString = _atob(pemContents);
        } catch (e) {
            throw new Error("공개키 내부 데이터(Base64) 디코딩에 실패했습니다.\n공백 외의 잘못된 문자(한글, 특수기호 등)가 섞여 있는지 확인하세요.");
        }
        
        const binaryDer = new Uint8Array(binaryDerString.length);
        for (let i = 0; i < binaryDerString.length; i++) {
            binaryDer[i] = binaryDerString.charCodeAt(i);
        }
        
        try {
            return await _crypto.subtle.importKey(
                "spki",
                binaryDer.buffer,
                { name: "ECDSA", namedCurve: "P-256" },
                true,
                ["verify"]
            );
        } catch (e) {
            throw new Error("공개키 데이터 분석(Import)에 실패했습니다. 키가 손상되었거나 유효한 ECDSA P-256 공개키가 아닐 수 있습니다. (상세 에러: " + e.message + ")");
        }
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
        const { method, urlStr, bodyStr, nonce, timestampStr, signature, pubkeyPem, evalTime, reqDigest } = inputs;
        
        const result = {
            stages: [],
            warnings: [],
            error: null,
            firstFailedStage: null,
            expectedCanonical: "",
            hypothesisResult: null 
        };

        // Stage 1: Headers presence
        const headersPresent = !!(method && urlStr && nonce && timestampStr && signature && pubkeyPem);
        result.stages.push({
            name: "1단계: 필수 데이터 서식 검사 (Offline)",
            status: headersPresent ? "pass" : "fail",
            reason: headersPresent ? "서명 검증에 필요한 모든 항목이 입력되었습니다. (주의: 본 도구는 오프라인 환경이므로 실제 URL 접속 여부나 JWT 토큰 유효성 검증은 생략하고 즉시 서명을 검증합니다.)" : "Method, URL, Nonce, Timestamp, 서명 중 누락된 항목이 있습니다."
        });
        if (!headersPresent) { result.firstFailedStage = 1; return result; }

        // Inputs parsing & formatting checks
        
        if (bodyStr.trim()) {
            try {
                JSON.parse(bodyStr);
            } catch (e) {
                result.error = { message: `요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n쉼표(,)나 따옴표(")가 빠졌거나 오타가 있는지 확인해 주세요.\n<div class="error-detail-box">📌 에러 상세:\n${getJsonErrorSnippet(e, bodyStr)}</div>` };
                return result;
            }
        }

        let url;
        try { 
            url = new URL(urlStr); 
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                throw new Error("http:// 또는 https:// 프로토콜이 아닙니다.");
            }
        } catch (e) { 
            result.error = { message: `URL 형식이 올바르지 않습니다.\n💡 <strong>힌트:</strong> 반드시 'https://' 또는 'http://' 로 시작하는 전체 인터넷 주소를 입력해야 합니다. <span class="text-muted-span">(예: https://api.example.com/v1/tx)</span>\n<div class="error-detail-box">📌 에러 상세:\n${getJsonErrorSnippet(e, bodyStr)}</div>` }; 
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
            reason: noncePresent ? "Nonce 값이 입력되었습니다. (안내: Nonce는 해킹(재전송 공격)을 막기 위한 1회용 값입니다. 본 진단기는 오프라인 도구이므로 실제 서버의 DB를 조회하여 '이미 사용된 Nonce인지' 판단하는 과정은 생략됩니다.)" : "Nonce 값이 비어 있습니다."
        });
        if (!noncePresent && !result.firstFailedStage) result.firstFailedStage = 3;

                let normalizedMethod = method.toUpperCase();
        if (method !== normalizedMethod) {
            result.warnings.push(`입력하신 HTTP 메서드('${method}')를 FIDO2 PoP 규격에 맞춰 대문자('${normalizedMethod}')로 강제 변환 후 진단했습니다.`);
        }
        const baseReq = {
            method: normalizedMethod,
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
        let actualBytes = baseReq.parsedSignature ? baseReq.parsedSignature.byteLength : 0;
        let sigLengthValid = actualBytes === 64;
        let sigStatus = "fail";
        let sigReason = `형식 불일치 (현재 디코딩된 크기: ${actualBytes}바이트. ECDSA P-256 서명은 r, s 각각 32바이트씩 총 64바이트여야 합니다.)`;

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
        let jsonParseError = null;
        if (bodyStr.trim()) {
            try {
                JSON.parse(bodyStr);
            } catch (e) {
                jsonParseError = e.message;
            }
        }

        let digestReason = "";
        if (cleanReqDigest) {
            digestMatch = cleanReqDigest.toLowerCase() === bodyHashHex.toLowerCase();
            digestReason = digestMatch ? "본문 해시가 헤더와 일치함" : `본문 해시 불일치 (기대: ${cleanReqDigest}, 실제: ${bodyHashHex})`;
            if (!digestMatch && jsonParseError) {
                digestReason += `\n⚠️ 힌트: 입력하신 요청 본문(JSON)의 문법이 깨져 있습니다. (${jsonParseError})\n따옴표나 쉼표가 빠졌는지 확인해 보세요. JSON 형식이 잘못되면 해시가 완전히 달라집니다.`;
            }
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


    // --- Generator Helpers ---
    async function generateTestSignature(inputs) {
        const { method, urlStr, bodyStr, nonce, timestampStr } = inputs;

        if (bodyStr.trim()) {
            try {
                JSON.parse(bodyStr);
            } catch (e) {
                throw new Error(`요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\nJSON 문법(쉼표, 따옴표 등)을 먼저 수정해 주셔야 서명을 생성할 수 있습니다.\n<div class="error-detail-box">📌 에러 상세:\n${getJsonErrorSnippet(e, bodyStr)}</div>`);
            }
        }

        
        // 1. Generate Key Pair
        const keyPair = await _crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
        );
        
        // 2. Export Public Key to PEM
        const spki = await _crypto.subtle.exportKey("spki", keyPair.publicKey);
        const spkiBase64 = _btoa(String.fromCharCode(...new Uint8Array(spki)));
        const pubkeyPem = `-----BEGIN PUBLIC KEY-----\n${spkiBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
        
        // 3. Generate Digest
        const digestHex = await hashString(bodyStr || "");
        const reqDigest = "sha256=" + digestHex;
        
        // 4. Build Canonical String
        
        if (bodyStr.trim()) {
            try {
                JSON.parse(bodyStr);
            } catch (e) {
                result.error = { message: `요청 본문(Body)이 올바른 JSON 형식이 아닙니다.\n쉼표(,)나 따옴표(")가 빠졌거나 오타가 있는지 확인해 주세요.\n<div class="error-detail-box">📌 에러 상세:\n${getJsonErrorSnippet(e, bodyStr)}</div>` };
                return result;
            }
        }

        let url;
        try { url = new URL(urlStr); } catch(e) { throw new Error("URL이 올바르지 않습니다."); }
        
        const host = url.host;
        const path = url.pathname;
        const query = url.search.substring(1) || "";
        
        const canonicalStr = [
            method.toUpperCase(),
            host,
            path,
            query,
            digestHex,
            nonce,
            timestampStr
        ].join('\n');
        
        const encoder = new TextEncoder();
        const data = encoder.encode(canonicalStr);
        
        // 5. Sign
        const signatureBytes = await _crypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            keyPair.privateKey,
            data
        );
        
        const signatureBase64Url = _btoa(String.fromCharCode(...new Uint8Array(signatureBytes)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
            
        return {
            pubkeyPem,
            reqDigest,
            signature: signatureBase64Url,
            canonicalStr
        };
    }

    return { diagnose, generateTestSignature, HYPOTHESES };
})();
if (typeof module !== 'undefined') module.exports = PopCore;
