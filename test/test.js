const PopCore = (typeof window !== 'undefined' && window.PopCore)
    ? window.PopCore
    : require('../js/core/diagnose.js');
const fixtures = (typeof window !== 'undefined' && window.FIXTURES)
    ? window.FIXTURES
    : require('./fixtures/fixtures.js');
const PopUI = (typeof window !== 'undefined' && window.PopUI)
    ? window.PopUI
    : Object.assign({}, require('../js/ui/render.js'), require('../js/ui/slots.js'), require('../js/ui/tabs.js'));

async function runTests() {
    const pubkeyPem = fixtures.public_key;
    let passed = 0;
    let failed = 0;

    for (let c of fixtures.cases) {
        const inputs = {
            method: c.method,
            urlStr: `https://${c.host}${c.path}?${c.query}`,
            bodyStr: c.body,
            nonce: c.nonce,
            timestampStr: String(c.timestamp),
            signature: c.signature,
            pubkeyPem: pubkeyPem,
            evalTime: c.evalTime,
            reqDigest: c.digest
        };

        const result = await PopCore.diagnose(inputs);
        let ok = true;

        if (c.expected.firstFailedStage !== undefined && result.firstFailedStage !== c.expected.firstFailedStage) {
            console.log(`[FAIL] ${c.name}: Expected firstFailedStage ${c.expected.firstFailedStage}, got ${result.firstFailedStage}`);
            ok = false;
        }

        if (c.expected.type && result.hypothesisResult) {
            let actualType = result.hypothesisResult.type;
            if (actualType === 'found' && result.hypothesisResult.sets.length > 0) {
                actualType = result.hypothesisResult.sets[0].type;
            }
            if (actualType !== c.expected.type) {
                console.log(`[FAIL] ${c.name}: Expected type ${c.expected.type}, got ${actualType}`);
                ok = false;
            }
            if (c.expected.idStr) {
                let actualIdStr = null;
                if (result.hypothesisResult.type === 'found') {
                    const matchedSet = result.hypothesisResult.sets[0];
                    if (c.expected.type === 'match' && matchedSet && matchedSet.item) {
                        actualIdStr = matchedSet.item.idStr;
                    }
                } else if (result.hypothesisResult.type === 'match') {
                    actualIdStr = result.hypothesisResult.idStr;
                }
                if (actualIdStr !== c.expected.idStr) {
                    console.log(`[FAIL] ${c.name}: Expected idStr ${c.expected.idStr}, got ${actualIdStr}`);
                    ok = false;
                }
            }
        }

        if (ok) passed++; else failed++;
    }

    const validSig = fixtures.cases[0].signature;

    // Input error tests
    const inputTests = [
        { name: "empty-inputs", inputs: {}, expectError: false, expectedStage: 1 },
        { name: "bad-url", inputs: { method: "POST", urlStr: "not-a-url", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: "A" }, expectError: true },
        { name: "bad-pubkey", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: "bad-pem" }, expectError: true },
        { name: "bad-signature", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "+++", pubkeyPem: pubkeyPem }, expectError: true },
        { name: "bad-timestamp", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "abc", signature: validSig, pubkeyPem: pubkeyPem }, expectError: true },
        { name: "bad-signature-length", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "abcde", pubkeyPem: pubkeyPem }, expectError: true },
        { name: "missing-nonce", inputs: { method: "POST", urlStr: "https://a.com/", timestampStr: "1", signature: validSig, pubkeyPem: pubkeyPem }, expectError: false, expectedStage: 1 },
        { name: "bad-json", inputs: { method: "POST", urlStr: "https://a.com/", bodyStr: "{bad json}", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: pubkeyPem }, expectError: true },
        { name: "long-input", inputs: { method: "POST", urlStr: "https://a.com/", bodyStr: JSON.stringify({ data: "A".repeat(100000) }), nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: pubkeyPem }, expectError: false }
    ];

    for (let t of inputTests) {
        const result = await PopCore.diagnose(t.inputs);
        let ok = true;
        if (t.expectError && !result.error) {
            console.log(`[FAIL] ${t.name}: Expected error, got none`);
            ok = false;
        } else if (!t.expectError && result.error) {
            console.log(`[FAIL] ${t.name}: Expected no error, got: ${result.error.message}`);
            ok = false;
        }
        if (t.expectedStage !== undefined && result.firstFailedStage !== t.expectedStage) {
            console.log(`[FAIL] ${t.name}: Expected firstFailedStage ${t.expectedStage}, got ${result.firstFailedStage}`);
            ok = false;
        }
        if (ok) passed++; else failed++;
    }

    // Dynamic tests for newly revived / added hypotheses & DER boundary cases
    const _crypto = typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto;
    const _btoa = typeof btoa !== 'undefined' ? btoa : (str) => Buffer.from(str, 'binary').toString('base64');

    const keyPair = await _crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
    const spki = await _crypto.subtle.exportKey("spki", keyPair.publicKey);
    const spkiB64 = _btoa(String.fromCharCode(...new Uint8Array(spki)));
    const dynPubkeyPem = `-----BEGIN PUBLIC KEY-----\n${spkiB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

    async function sha256Hex(str) {
        const buf = await _crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function toBase64Url(buf) {
        return _btoa(String.fromCharCode(...new Uint8Array(buf)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function toStandardBase64(buf) {
        return _btoa(String.fromCharCode(...new Uint8Array(buf)));
    }

    async function signRaw(canonicalStr) {
        const data = new TextEncoder().encode(canonicalStr);
        return await _crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, keyPair.privateKey, data);
    }

    function rawToDer(rawBuf) {
        const raw = new Uint8Array(rawBuf);
        function encodeInt(bytes32) {
            let start = 0;
            while (start < bytes32.length - 1 && bytes32[start] === 0x00) start++;
            const stripped = bytes32.slice(start);
            if (stripped[0] & 0x80) {
                const out = new Uint8Array(stripped.length + 1);
                out[0] = 0x00;
                out.set(stripped, 1);
                return out;
            }
            return stripped;
        }
        const rDer = encodeInt(raw.slice(0, 32));
        const sDer = encodeInt(raw.slice(32, 64));
        const seqLen = 2 + rDer.length + 2 + sDer.length;
        const out = new Uint8Array(2 + seqLen);
        out[0] = 0x30;
        out[1] = seqLen;
        out[2] = 0x02;
        out[3] = rDer.length;
        out.set(rDer, 4);
        const sOff = 4 + rDer.length;
        out[sOff] = 0x02;
        out[sOff + 1] = sDer.length;
        out.set(sDer, sOff + 2);
        return out.buffer;
    }

    const baseBody = '{\n  "amount": 1000,\n  "to": "alice"\n}';
    const baseBodyHash = await sha256Hex(baseBody);
    const ts = "1791356800";
    const nonce = "n-test-999";

    const stdB64Canonical = ["POST", "api.example.com", "/v1/tx", "a=1", baseBodyHash, nonce, ts].join('\n');
    let stdB64SigStr = "";
    for (let i = 0; i < 50; i++) {
        const rawSig = await signRaw(stdB64Canonical);
        const candidate = toStandardBase64(rawSig);
        if (candidate.includes('+') || candidate.includes('/')) {
            stdB64SigStr = candidate;
            break;
        }
    }

    const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    function bytesToBigInt(bytes) {
        let hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        return BigInt("0x" + hex);
    }
    function bigIntToBytes32(num) {
        const hex = num.toString(16).padStart(64, '0');
        const out = new Uint8Array(32);
        for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        return out;
    }

    let shortDerSigB64Url = "";
    for (let i = 0; i < 1000; i++) {
        const rawSig = new Uint8Array(await signRaw(stdB64Canonical));
        const sVal = bytesToBigInt(rawSig.slice(32, 64));
        const lowS = sVal > (P256_N >> 1n) ? (P256_N - sVal) : sVal;
        rawSig.set(bigIntToBytes32(lowS), 32);
        const derBuf = rawToDer(rawSig.buffer);
        if (derBuf.byteLength < 70) {
            shortDerSigB64Url = toBase64Url(derBuf);
            break;
        }
    }

    const trailingBodyHash = await sha256Hex(baseBody + '\n');
    const upperBodyHash = baseBodyHash.toUpperCase();
    const bomBodyHash = await sha256Hex('\uFEFF' + baseBody);
    const noSpaceBodyHash = await sha256Hex(JSON.stringify(JSON.parse(baseBody)));

    const dynamicCases = [
        {
            name: "hyp-query-reverse",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1&b=2&c=3",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "c=3&b=2&a=1", baseBodyHash, nonce, ts].join('\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "query-reverse"
        },
        {
            name: "hyp-path-trailing-slash-remove",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx/?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", baseBodyHash, nonce, ts].join('\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "path-trailing-slash-remove"
        },
        {
            name: "hyp-sig-base64url",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: stdB64SigStr,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "sig-base64url"
        },
        {
            name: "hyp-newline-crlf-stage4",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", baseBodyHash, nonce, ts].join('\r\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "newline-crlf"
        },
        {
            name: "hyp-newline-trailing-stage4",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", baseBodyHash, nonce, ts].join('\n') + '\n')),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "newline-trailing"
        },
        {
            name: "hyp-newline-trailing-stage5",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", trailingBodyHash, nonce, ts].join('\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${trailingBodyHash}`
            },
            expectedStage: 5,
            expectedIdStr: "newline-trailing"
        },
        {
            name: "hyp-digest-hex",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", upperBodyHash, nonce, ts].join('\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${upperBodyHash}`
            },
            expectedStage: 5,
            expectedIdStr: "digest-hex"
        },
        {
            name: "hyp-body-bom-added",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", bomBodyHash, nonce, ts].join('\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${bomBodyHash}`
            },
            expectedStage: 5,
            expectedIdStr: "body-bom-added"
        },
        {
            name: "hyp-body-reserialized-nospace",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", noSpaceBodyHash, nonce, ts].join('\n'))),
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${noSpaceBodyHash}`
            },
            expectedStage: 5,
            expectedIdStr: "body-reserialized-nospace"
        }
    ];

    if (shortDerSigB64Url) {
        dynamicCases.push({
            name: "hyp-sig-der-short-under-70b",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: shortDerSigB64Url,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "sig-der"
        });
    }

    for (let dc of dynamicCases) {
        const res = await PopCore.diagnose(dc.inputs);
        let ok = true;
        if (res.error) {
            console.log(`[FAIL] ${dc.name}: Unexpected error ${res.error.message}`);
            ok = false;
        }
        if (res.firstFailedStage !== dc.expectedStage) {
            console.log(`[FAIL] ${dc.name}: Expected stage ${dc.expectedStage}, got ${res.firstFailedStage}`);
            ok = false;
        }
        const matchedId = res.hypothesisResult && res.hypothesisResult.type === 'found' && res.hypothesisResult.sets[0] && res.hypothesisResult.sets[0].item
            ? res.hypothesisResult.sets[0].item.idStr
            : null;
        if (matchedId !== dc.expectedIdStr) {
            console.log(`[FAIL] ${dc.name}: Expected idStr ${dc.expectedIdStr}, got ${matchedId}`);
            ok = false;
        }
        if (ok) passed++; else failed++;
    }

    // derToRaw direct boundary unit tests (68-byte valid DER, long-form length, >32B integer rejection, malformed DER)
    {
        // 1) 68-byte valid DER (31-byte r and 31-byte s)
        const der68 = new Uint8Array(68);
        der68[0] = 0x30; der68[1] = 66;
        der68[2] = 0x02; der68[3] = 31; der68[4] = 0x05;
        der68[35] = 0x02; der68[36] = 31; der68[37] = 0x07;
        const raw68 = PopCore.derToRaw(der68.buffer);
        const view68 = raw68 ? new Uint8Array(raw68) : null;
        if (view68 && view68.length === 64 && view68[0] === 0x00 && view68[1] === 0x05 && view68[32] === 0x00 && view68[33] === 0x07) {
            passed++;
        } else {
            console.log("[FAIL] derToRaw-68b: Failed to convert 68-byte valid DER");
            failed++;
        }

        // 2) Long-form length DER (0x81 0x46)
        const derLong = new Uint8Array(73);
        derLong[0] = 0x30; derLong[1] = 0x81; derLong[2] = 70;
        derLong[3] = 0x02; derLong[4] = 33; derLong[5] = 0x00; derLong[6] = 0x80;
        derLong[38] = 0x02; derLong[39] = 33; derLong[40] = 0x00; derLong[41] = 0x81;
        const rawLong = PopCore.derToRaw(derLong.buffer);
        const viewLong = rawLong ? new Uint8Array(rawLong) : null;
        if (viewLong && viewLong.length === 64 && viewLong[0] === 0x80 && viewLong[32] === 0x81) {
            passed++;
        } else {
            console.log("[FAIL] derToRaw-long-form: Failed to parse 0x81 length encoding");
            failed++;
        }

        // 3) Invalid DER (>32 bytes after stripping leading 0x00, or trailing garbage)
        const derInvalid33 = new Uint8Array(72);
        derInvalid33[0] = 0x30; derInvalid33[1] = 70;
        derInvalid33[2] = 0x02; derInvalid33[3] = 34; derInvalid33[4] = 0x01;
        derInvalid33[38] = 0x02; derInvalid33[39] = 32; derInvalid33[40] = 0x01;
        if (PopCore.derToRaw(derInvalid33.buffer) === null) {
            passed++;
        } else {
            console.log("[FAIL] derToRaw-invalid-33b: Expected null for >32-byte r");
            failed++;
        }
    }

    // XSS regression tests (Core pure data return + UI renderResult textContent-only verification)
    {
        const { renderResult, readMemorySlots, writeMemorySlots } = PopUI;

        // 1) Body with <img src=x onerror=alert(1)> in invalid JSON
        const xssBodyPayload = '{"xss": "<img src=x onerror=alert(1)>", broken}';
        const xssBodyRes = await PopCore.diagnose({
            method: "POST",
            urlStr: "https://api.example.com/v1/tx",
            bodyStr: xssBodyPayload,
            nonce: "n1",
            timestampStr: ts,
            signature: validSig,
            pubkeyPem: pubkeyPem
        });
        if (
            xssBodyRes.error &&
            typeof xssBodyRes.error.message === 'string' &&
            !/<(div|strong|span|br)\b/i.test(xssBodyRes.error.message) &&
            typeof xssBodyRes.error.detail === 'string' &&
            xssBodyRes.error.detail.includes('<img src=x onerror=alert(1)>') &&
            !xssBodyRes.error.detail.includes('<div')
        ) {
            passed++;
        } else {
            console.log("[FAIL] xss-core-body-json: Core returned HTML wrapper or lost raw payload in error.detail");
            failed++;
        }

        // 2) URL error returns pure data fields (no <strong>, <span>, <div>)
        const xssUrlRes = await PopCore.diagnose({
            method: "POST",
            urlStr: "javascript:alert(1)",
            bodyStr: "",
            nonce: "n1",
            timestampStr: ts,
            signature: validSig,
            pubkeyPem: pubkeyPem
        });
        if (
            xssUrlRes.error &&
            !/<(div|strong|span|br)\b/i.test(xssUrlRes.error.message) &&
            typeof xssUrlRes.error.hint === 'string' &&
            !/<(div|strong|span|br)\b/i.test(xssUrlRes.error.hint) &&
            typeof xssUrlRes.error.detail === 'string'
        ) {
            passed++;
        } else {
            console.log("[FAIL] xss-core-url: Core returned HTML markup in URL error");
            failed++;
        }

        // 3) Method with <script> tag returns pure warning data and plain expectedCanonical
        const xssMethodRes = await PopCore.diagnose({
            method: "<script>alert(1)</script>",
            urlStr: "https://api.example.com/v1/tx",
            bodyStr: "",
            nonce: "n1",
            timestampStr: ts,
            signature: validSig,
            pubkeyPem: pubkeyPem,
            evalTime: Number(ts),
            reqDigest: `sha256=${await sha256Hex("")}`
        });
        const warnObj = xssMethodRes.warnings && xssMethodRes.warnings[0];
        const warnMsg = typeof warnObj === 'string' ? warnObj : (warnObj && warnObj.message);
        if (
            warnMsg &&
            warnMsg.includes('<script>alert(1)</script>') &&
            warnMsg.includes('<SCRIPT>ALERT(1)</SCRIPT>') &&
            !/<(div|ul|li|strong)\b/i.test(warnMsg) &&
            xssMethodRes.expectedCanonical.startsWith('<SCRIPT>ALERT(1)</SCRIPT>\n')
        ) {
            passed++;
        } else {
            console.log("[FAIL] xss-core-method: Core failed to preserve raw <script> in warning/canonical");
            failed++;
        }

        // 4) generateTestSignature throws pure Error with .detail (no HTML <div class="error-detail-box">)
        let genErrOk = false;
        try {
            await PopCore.generateTestSignature({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: xssBodyPayload,
                nonce: "n1",
                timestampStr: ts
            });
        } catch (err) {
            if (
                err &&
                !/<(div|strong|span|br)\b/i.test(err.message) &&
                typeof err.detail === 'string' &&
                err.detail.includes('<img src=x onerror=alert(1)>') &&
                !err.detail.includes('<div')
            ) {
                genErrOk = true;
            }
        }
        if (genErrOk) {
            passed++;
        } else {
            console.log("[FAIL] xss-core-generate-sig: generateTestSignature error contained HTML or missed .detail");
            failed++;
        }

        // 5) UI renderResult DOM verification: 0 innerHTML assignments, payloads exist strictly in textContent
        let innerHtmlUsed = false;
        function createMockNode(tagName) {
            return {
                tagName,
                className: '',
                children: [],
                _text: '',
                get textContent() {
                    const childText = this.children.map(c => c.textContent).join('');
                    return this._text + childText;
                },
                set textContent(val) {
                    this._text = String(val ?? '');
                    this.children = [];
                },
                set innerHTML(_val) {
                    innerHtmlUsed = true;
                },
                appendChild(child) {
                    this.children.push(child);
                    return child;
                },
                insertBefore(child, refNode) {
                    const idx = this.children.indexOf(refNode);
                    if (idx === -1) this.children.unshift(child);
                    else this.children.splice(idx, 0, child);
                    return child;
                }
            };
        }

        if (typeof window === 'undefined') {
            const mockPanel = createMockNode('div');
            const prevDoc = global.document;
            global.document = {
                getElementById(id) {
                    return id === 'result-panel' ? mockPanel : null;
                },
                createElement(tag) {
                    return createMockNode(tag.toUpperCase());
                },
                createTextNode(text) {
                    const node = createMockNode('#text');
                    node._text = String(text ?? '');
                    return node;
                }
            };

            try {
                renderResult(xssBodyRes);
                const bodyRenderedText = mockPanel.textContent;
                const bodyRenderSafe = !innerHtmlUsed && bodyRenderedText.includes('<img src=x onerror=alert(1)>');

                renderResult(xssMethodRes);
                const methodRenderedText = mockPanel.textContent;
                const methodRenderSafe = !innerHtmlUsed && methodRenderedText.includes('<script>alert(1)</script>');

                if (bodyRenderSafe && methodRenderSafe) {
                    passed++;
                } else {
                    console.log("[FAIL] xss-ui-renderResult: innerHTML was used or textContent missing payload");
                    failed++;
                }
            } finally {
                global.document = prevDoc;
            }

            // 6) localStorage resilience (blocked storage & corrupted JSON)
            const prevStorage = global.localStorage;
            try {
                global.localStorage = {
                    getItem() { throw new Error("SecurityError: localStorage disabled"); },
                    setItem() { throw new Error("QuotaExceededError"); }
                };
                const blockedRead = readMemorySlots();
                const blockedWrite = writeMemorySlots({ slot_1: {} });

                global.localStorage = {
                    getItem() { return "{broken-json"; },
                    setItem() {}
                };
                const corruptedRead = readMemorySlots();

                if (
                    blockedRead.ok === false &&
                    typeof blockedRead.data === 'object' &&
                    blockedWrite.ok === false &&
                    corruptedRead.ok === false &&
                    typeof corruptedRead.data === 'object'
                ) {
                    passed++;
                } else {
                    console.log("[FAIL] storage-resilience: readMemorySlots/writeMemorySlots failed to handle storage errors");
                    failed++;
                }
            } finally {
                global.localStorage = prevStorage;
            }
        } else {
            // Browser environment DOM test
            let tempPanel = document.getElementById('result-panel');
            let createdTemp = false;
            if (!tempPanel) {
                tempPanel = document.createElement('div');
                tempPanel.id = 'result-panel';
                tempPanel.className = 'hidden';
                document.body.appendChild(tempPanel);
                createdTemp = true;
            }
            renderResult(xssBodyRes);
            const bodyOk = tempPanel.textContent.includes('<img src=x onerror=alert(1)>') && tempPanel.querySelectorAll('img').length === 0;
            renderResult(xssMethodRes);
            const methodOk = tempPanel.textContent.includes('<script>alert(1)</script>') && tempPanel.querySelectorAll('script').length === 0;
            if (createdTemp) tempPanel.remove();
            if (bodyOk && methodOk) passed += 2; else failed += 2;
        }

        // 7) Profile parameter injection check (diagnose(inputs, profile))
        const strictTimeProfile = Object.assign({}, PopCore.PaperProfile, {
            timestampToleranceSec: 5
        });
        const vCase = fixtures.cases[0];
        const profileRes = await PopCore.diagnose({
            method: vCase.method,
            urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
            bodyStr: vCase.body,
            nonce: vCase.nonce,
            timestampStr: String(vCase.timestamp),
            signature: vCase.signature,
            pubkeyPem: pubkeyPem,
            evalTime: vCase.timestamp + 10,
            reqDigest: vCase.digest
        }, strictTimeProfile);
        if (profileRes.firstFailedStage === 2 && profileRes.stages[1].status === 'fail') {
            passed++;
        } else {
            console.log("[FAIL] profile-injection: Custom timestampToleranceSec in profile was not applied");
            failed++;
        }

        // 8) Tab keyboard navigation pure function unit test (getNextTabIndex)
        const { getNextTabIndex } = PopUI;
        if (
            typeof getNextTabIndex === 'function' &&
            getNextTabIndex(0, 'ArrowRight', 3) === 1 &&
            getNextTabIndex(2, 'ArrowRight', 3) === 0 &&
            getNextTabIndex(0, 'ArrowLeft', 3) === 2 &&
            getNextTabIndex(2, 'ArrowLeft', 3) === 1 &&
            getNextTabIndex(2, 'Home', 3) === 0 &&
            getNextTabIndex(0, 'End', 3) === 2 &&
            getNextTabIndex(1, 'Tab', 3) === null &&
            getNextTabIndex(-1, 'ArrowRight', 3) === null &&
            getNextTabIndex(0, 'ArrowRight', 0) === null
        ) {
            passed++;
        } else {
            console.log("[FAIL] tab-keyboard-index: getNextTabIndex failed boundary or wrap-around assertions");
            failed++;
        }

        // 9) Static accessibility check (Node): every <label for="..."> in index.html points to an existing id
        if (typeof window === 'undefined') {
            const fs = require('fs');
            const path = require('path');
            const htmlPath = path.join(__dirname, '..', 'index.html');
            const html = fs.readFileSync(htmlPath, 'utf8');

            const allIds = new Set();
            const idRegex = /\bid\s*=\s*"([^"]+)"/g;
            let idMatch;
            while ((idMatch = idRegex.exec(html)) !== null) {
                allIds.add(idMatch[1]);
            }

            const labelTagMatches = html.match(/<label\b[^>]*>/g) || [];
            const labelForIds = [];
            const forRegex = /\bfor\s*=\s*"([^"]+)"/;
            for (const tag of labelTagMatches) {
                const m = forRegex.exec(tag);
                if (m) labelForIds.push(m[1]);
            }

            const allLabelsHaveFor = labelTagMatches.length > 0 && labelTagMatches.length === labelForIds.length;
            const allTargetsExist = labelForIds.every(targetId => allIds.has(targetId));
            const reqUrlHasAriaLabel = /<input\b[^>]*\bid="req-url"[^>]*\baria-label="요청 URL"/.test(html);

            if (allLabelsHaveFor && allTargetsExist && reqUrlHasAriaLabel) {
                passed++;
            } else {
                console.log(`[FAIL] html-label-for-a11y: labels=${labelTagMatches.length}, withFor=${labelForIds.length}, allTargetsExist=${allTargetsExist}, reqUrlHasAriaLabel=${reqUrlHasAriaLabel}`);
                failed++;
            }
        }
    }

    console.log(`\nTests completed. Passed: ${passed}, Failed: ${failed}`);
    if (failed > 0 && typeof process !== 'undefined') process.exitCode = 1;
}

if (typeof window !== 'undefined') {
    window.runTests = runTests;
} else {
    runTests();
}
