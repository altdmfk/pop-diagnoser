const PopCore = (typeof window !== 'undefined' && window.PopCore)
    ? window.PopCore
    : require('../js/core/diagnose.js');
const fixtures = (typeof window !== 'undefined' && window.FIXTURES)
    ? window.FIXTURES
    : require('./fixtures/fixtures.js');
const PopUI = (typeof window !== 'undefined' && window.PopUI)
    ? window.PopUI
    : Object.assign({}, require('../js/ui/render.js'), require('../js/ui/slots.js'), require('../js/ui/tabs.js'), require('../js/ui/inspector.js'), require('../js/ui/importer.js'));

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

    // Input error tests with machine-readable error codes
    const inputTests = [
        { name: "empty-inputs", inputs: {}, expectError: false, expectedStage: 1 },
        { name: "bad-url", inputs: { method: "POST", urlStr: "not-a-url", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: "A" }, expectError: true, expectedCode: PopCore.ERROR_CODES.INVALID_URL },
        { name: "bad-pubkey", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: "bad-pem" }, expectError: true, expectedCode: PopCore.ERROR_CODES.INVALID_PUBKEY },
        { name: "bad-signature", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "+++", pubkeyPem: pubkeyPem }, expectError: true, expectedCode: PopCore.ERROR_CODES.INVALID_SIGNATURE_ENCODING },
        { name: "bad-timestamp", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "abc", signature: validSig, pubkeyPem: pubkeyPem }, expectError: true, expectedCode: PopCore.ERROR_CODES.INVALID_TIMESTAMP },
        { name: "bad-signature-length", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "abcde", pubkeyPem: pubkeyPem }, expectError: true, expectedCode: PopCore.ERROR_CODES.INVALID_SIGNATURE_ENCODING },
        { name: "missing-nonce", inputs: { method: "POST", urlStr: "https://a.com/", timestampStr: "1", signature: validSig, pubkeyPem: pubkeyPem }, expectError: false, expectedStage: 1 },
        { name: "bad-json", inputs: { method: "POST", urlStr: "https://a.com/", bodyStr: "{bad json}", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: pubkeyPem }, expectError: true, expectedCode: PopCore.ERROR_CODES.INVALID_JSON },
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
        if (t.expectedCode && (!result.error || result.error.code !== t.expectedCode)) {
            console.log(`[FAIL] ${t.name}: Expected error code ${t.expectedCode}, got ${result.error ? result.error.code : 'none'}`);
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
    const spkiB64 = _btoa(PopCore.bytesToBinaryString(spki));
    const dynPubkeyPem = `${PopCore.PEM_PUBLIC_KEY_HEADER}\n${spkiB64.match(/.{1,64}/g).join('\n')}\n${PopCore.PEM_PUBLIC_KEY_FOOTER}`;

    const sha256Hex = PopCore.hashString;
    const toBase64Url = PopCore.base64UrlEncodeBytes;
    function toStandardBase64(buf) {
        return _btoa(PopCore.bytesToBinaryString(buf));
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
            const reqUrlHasAriaLabel = /<input\b[^>]*\bid="req-url"[^>]*\baria-label="[^"]+"/.test(html);

            if (allLabelsHaveFor && allTargetsExist && reqUrlHasAriaLabel) {
                passed++;
            } else {
                console.log(`[FAIL] html-label-for-a11y: labels=${labelTagMatches.length}, withFor=${labelForIds.length}, allTargetsExist=${allTargetsExist}, reqUrlHasAriaLabel=${reqUrlHasAriaLabel}`);
                failed++;
            }
        }

        // =========================================================================
        // Signature & Public Key Inspector Tests (js/core/inspect.js & js/ui/inspector.js)
        // =========================================================================
        const { inspectSignature, inspectPublicKey } = PopCore;

        // 10) inspectSignature: valid 64B raw (base64url), standard base64, and hex encodings
        {
            const raw64Res = inspectSignature(vCase.signature);
            const rawBytes = new Uint8Array(PopCore.base64UrlDecode(vCase.signature));
            const rawWithHighBytes = new Uint8Array(rawBytes);
            rawWithHighBytes[0] = 0xfb; // ensures '+' or '/' in standard base64
            rawWithHighBytes[1] = 0xff;
            const stdB64Sig = _btoa(String.fromCharCode(...rawWithHighBytes));
            const stdRes = inspectSignature(stdB64Sig);
            const hexSig = PopCore.bytesToHex(rawBytes);
            const hexRes = inspectSignature(hexSig);

            if (
                raw64Res.ok === true &&
                raw64Res.encoding === 'base64url' &&
                typeof raw64Res.encodingReason === 'string' &&
                raw64Res.byteLength === 64 &&
                raw64Res.format === 'raw-rs(64B)' &&
                raw64Res.r.length === 64 &&
                raw64Res.s.length === 64 &&
                stdRes.ok === true &&
                stdRes.encoding === 'base64(standard)' &&
                stdRes.format === 'raw-rs(64B)' &&
                hexRes.ok === true &&
                hexRes.encoding === 'hex' &&
                hexRes.format === 'raw-rs(64B)' &&
                hexRes.r === raw64Res.r &&
                hexRes.s === raw64Res.s
            ) {
                passed++;
            } else {
                console.log("[FAIL] inspect-sig-encodings: Failed raw64 / standard base64 / hex signature inspection");
                failed++;
            }
        }

        // 11) inspectSignature: DER (70~72B with leading 0x00 and 68~69B without leading 0x00)
        {
            // 72B DER where both r and s have MSB >= 0x80 (so both have leading 0x00 in DER)
            const rHigh = new Uint8Array(32);
            rHigh[0] = 0x8a; rHigh[31] = 0x01;
            const sLow = new Uint8Array(32);
            sLow[0] = 0x90; sLow[31] = 0x02;
            const rawBothHigh = new Uint8Array(64);
            rawBothHigh.set(rHigh, 0);
            rawBothHigh.set(sLow, 32);
            const der72 = rawToDer(rawBothHigh); // 2 + (2+33) + (2+33) = 72 bytes
            const der72Res = inspectSignature(toBase64Url(der72));

            // 68B Short DER where r is 30B (<0x80) and s is 32B (<0x80), no leading 0x00
            const rShort = new Uint8Array(32);
            rShort[2] = 0x45; rShort[31] = 0x11;
            const sNoPad = new Uint8Array(32);
            sNoPad[0] = 0x3f; sNoPad[31] = 0x22;
            const rawShort = new Uint8Array(64);
            rawShort.set(rShort, 0);
            rawShort.set(sNoPad, 32);
            const der68 = rawToDer(rawShort); // 2 + (2+30) + (2+32) = 68 bytes
            const der68Res = inspectSignature(toBase64Url(der68));

            if (
                der72.byteLength === 72 &&
                der72Res.ok === true &&
                der72Res.format === 'der' &&
                der72Res.rLeadingZeroStripped === true &&
                der72Res.sLeadingZeroStripped === true &&
                der72Res.r === PopCore.bytesToHex(rHigh) &&
                der72Res.s === PopCore.bytesToHex(sLow) &&
                der68.byteLength === 68 &&
                der68Res.ok === true &&
                der68Res.format === 'der' &&
                der68Res.rLeadingZeroStripped === false &&
                der68Res.sLeadingZeroStripped === false &&
                der68Res.r === PopCore.bytesToHex(rShort) &&
                der68Res.s === PopCore.bytesToHex(sNoPad)
            ) {
                passed++;
            } else {
                console.log("[FAIL] inspect-sig-der: Failed 72B/68B DER inspection or leading 0x00 detection");
                failed++;
            }
        }

        // 12) inspectSignature: High-S warning, r=0 warning, r>=n warning, invalid length, invalid DER
        {
            // High-S: s = n - 1 (> n/2)
            const highSBytes = new Uint8Array(64);
            highSBytes[31] = 0x01; // r = 1
            const highSHex = (P256_N - 1n).toString(16).padStart(64, '0');
            for (let i = 0; i < 32; i++) {
                highSBytes[32 + i] = parseInt(highSHex.slice(i * 2, i * 2 + 2), 16);
            }
            const highSRes = inspectSignature(toBase64Url(highSBytes));

            // r = 0
            const rZeroBytes = new Uint8Array(64);
            rZeroBytes[63] = 0x01; // r = 0, s = 1
            const rZeroRes = inspectSignature(toBase64Url(rZeroBytes));

            // Invalid length (e.g. 40B not starting with 0x30)
            const badLenBytes = new Uint8Array(40);
            badLenBytes[0] = 0x12;
            const badLenRes = inspectSignature(toBase64Url(badLenBytes));

            // Invalid DER structure (starts with 0x30 but wrong declared length)
            const badDerBytes = new Uint8Array([0x30, 0x44, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
            const badDerRes = inspectSignature(toBase64Url(badDerBytes));

            if (
                highSRes.ok === true &&
                highSRes.isHighS === true &&
                highSRes.warnings.some(w => w.code === 'HIGH_S') &&
                rZeroRes.ok === true &&
                rZeroRes.rOutOfRange === true &&
                rZeroRes.warnings.some(w => w.code === 'R_ZERO') &&
                badLenRes.ok === false &&
                badLenRes.format === 'invalid' &&
                badLenRes.error && badLenRes.error.code === 'INVALID_LENGTH' &&
                badDerRes.ok === false &&
                badDerRes.format === 'invalid' &&
                badDerRes.error && badDerRes.error.code === 'INVALID_DER'
            ) {
                passed++;
            } else {
                console.log("[FAIL] inspect-sig-warnings-errors: Failed High-S, r=0, invalid length, or invalid DER checks");
                failed++;
            }
        }

        // 13) inspectPublicKey: valid P-256 keys (fixture + generateTestSignature) & independent SHA-256 fingerprint check
        {
            const fixPubRes = await inspectPublicKey(pubkeyPem);
            const genOut = await PopCore.generateTestSignature({
                method: 'POST',
                urlStr: 'https://api.example.com/v1/tx',
                bodyStr: '{"ok":true}',
                nonce: 'n-inspect',
                timestampStr: ts
            });
            const genPubRes = await inspectPublicKey(genOut.pubkeyPem);

            // Independently compute SHA-256 fingerprint of fixture SPKI DER using crypto.subtle
            const cleanB64 = pubkeyPem
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\s/g, '');
            const bin = PopCore.base64StandardDecode(cleanB64);
            const independentDigest = await _crypto.subtle.digest('SHA-256', bin);
            const independentFp = PopCore.bytesToHex(independentDigest);

            if (
                fixPubRes.ok === true &&
                fixPubRes.algorithmOid === '1.2.840.10045.2.1' &&
                fixPubRes.curveOid === '1.2.840.10045.3.1.7' &&
                fixPubRes.pointFormat === 'uncompressed(0x04)' &&
                fixPubRes.x.length === 64 &&
                fixPubRes.y.length === 64 &&
                fixPubRes.onCurve === true &&
                fixPubRes.fingerprint === independentFp &&
                genPubRes.ok === true &&
                genPubRes.onCurve === true &&
                genPubRes.fingerprint.length === 64
            ) {
                passed++;
            } else {
                console.log("[FAIL] inspect-pubkey-valid-fp: Failed valid P-256 inspection or independent fingerprint match");
                failed++;
            }
        }

        // 14) inspectPublicKey: off-curve point, non-0x04 prefix, P-384 / RSA rejection, corrupted PEM, PRIVATE KEY rejection
        {
            const cleanB64 = pubkeyPem
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\s/g, '');
            const validSpki = new Uint8Array(PopCore.base64StandardDecode(cleanB64));

            // Corrupt last byte of Y coordinate -> point off curve
            const offCurveSpki = new Uint8Array(validSpki);
            offCurveSpki[offCurveSpki.length - 1] ^= 0x01;
            const offCurvePem = `-----BEGIN PUBLIC KEY-----\n${_btoa(String.fromCharCode(...offCurveSpki))}\n-----END PUBLIC KEY-----`;
            const offCurveRes = await inspectPublicKey(offCurvePem);

            // Change uncompressed prefix 0x04 (at index validSpki.length - 65) to 0x02 (compressed)
            const badPrefixSpki = new Uint8Array(validSpki);
            badPrefixSpki[badPrefixSpki.length - 65] = 0x02;
            const badPrefixPem = `-----BEGIN PUBLIC KEY-----\n${_btoa(String.fromCharCode(...badPrefixSpki))}\n-----END PUBLIC KEY-----`;
            const badPrefixRes = await inspectPublicKey(badPrefixPem);

            // Generate a real P-384 SPKI public key via WebCrypto
            const p384Pair = await _crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-384' },
                true,
                ['sign', 'verify']
            );
            const p384Spki = await _crypto.subtle.exportKey('spki', p384Pair.publicKey);
            const p384Pem = `-----BEGIN PUBLIC KEY-----\n${_btoa(String.fromCharCode(...new Uint8Array(p384Spki)))}\n-----END PUBLIC KEY-----`;
            const p384Res = await inspectPublicKey(p384Pem);

            // Minimal RSA SPKI DER header (AlgorithmIdentifier with OID 1.2.840.113549.1.1.1 + NULL + BIT STRING)
            const rsaSpkiBytes = new Uint8Array([
                0x30, 0x16,
                0x30, 0x0d,
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00,
                0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04
            ]);
            const rsaPem = `-----BEGIN PUBLIC KEY-----\n${_btoa(String.fromCharCode(...rsaSpkiBytes))}\n-----END PUBLIC KEY-----`;
            const rsaRes = await inspectPublicKey(rsaPem);

            // Corrupted PEM (missing END header)
            const corruptedPemRes = await inspectPublicKey('-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY=');

            // PRIVATE KEY immediate rejection
            const privKeyRes = await inspectPublicKey('-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n-----END PRIVATE KEY-----');
            const ecPrivKeyRes = await inspectPublicKey('-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----');

            if (
                offCurveRes.ok === false &&
                offCurveRes.onCurve === false &&
                offCurveRes.error && offCurveRes.error.code === 'POINT_NOT_ON_CURVE' &&
                badPrefixRes.ok === false &&
                badPrefixRes.error && badPrefixRes.error.code === 'INVALID_POINT_PREFIX' &&
                p384Res.ok === false &&
                p384Res.curveOid === '1.3.132.0.34' &&
                p384Res.error && p384Res.error.code === 'UNSUPPORTED_CURVE' &&
                rsaRes.ok === false &&
                rsaRes.algorithmOid === '1.2.840.113549.1.1.1' &&
                rsaRes.error && rsaRes.error.code === 'UNSUPPORTED_ALGORITHM_RSA' &&
                corruptedPemRes.ok === false &&
                corruptedPemRes.error && corruptedPemRes.error.code === 'INVALID_PEM_FORMAT' &&
                privKeyRes.ok === false &&
                privKeyRes.error && privKeyRes.error.code === 'PRIVATE_KEY_REJECTED' &&
                privKeyRes.warnings.some(w => w.code === 'PRIVATE_KEY_INPUT') &&
                ecPrivKeyRes.ok === false &&
                ecPrivKeyRes.error && ecPrivKeyRes.error.code === 'PRIVATE_KEY_REJECTED'
            ) {
                passed++;
            } else {
                console.log("[FAIL] inspect-pubkey-rejections: Failed off-curve, prefix, P-384, RSA, corrupted PEM, or PRIVATE KEY rejection");
                failed++;
            }
        }

        // 15) XSS regression test for Inspector (Core & UI)
        {
            const xssSigReport = inspectSignature('<script>alert(1)</script>');
            const xssPubReport = await inspectPublicKey('<img src=x onerror=alert(1)>');

            let inspectorInnerHtmlUsed = false;
            function createInspectorMockNode(tagName) {
                return {
                    tagName,
                    className: '',
                    children: [],
                    _text: '',
                    get textContent() {
                        return this._text + this.children.map(c => c.textContent).join('');
                    },
                    set textContent(val) {
                        this._text = String(val ?? '');
                        this.children = [];
                    },
                    set innerHTML(_val) {
                        inspectorInnerHtmlUsed = true;
                    },
                    appendChild(child) {
                        this.children.push(child);
                        return child;
                    }
                };
            }

            let uiSafe = true;
            if (typeof window === 'undefined') {
                const prevDoc = global.document;
                global.document = {
                    createElement(tag) {
                        return createInspectorMockNode(tag.toUpperCase());
                    },
                    createTextNode(text) {
                        const n = createInspectorMockNode('#text');
                        n._text = String(text ?? '');
                        return n;
                    }
                };
                try {
                    const sigBox = createInspectorMockNode('DIV');
                    const pubBox = createInspectorMockNode('DIV');
                    PopUI.renderSignatureInspect(sigBox, xssSigReport);
                    PopUI.renderPublicKeyInspect(pubBox, xssPubReport);
                    uiSafe = !inspectorInnerHtmlUsed &&
                        sigBox.textContent.includes('INVALID_ENCODING') &&
                        pubBox.textContent.includes('INVALID_BASE64');
                } finally {
                    global.document = prevDoc;
                }
            }

            if (
                xssSigReport.ok === false &&
                xssSigReport.error &&
                !/<(script|img|div|span)\b/i.test(xssSigReport.error.message) &&
                xssPubReport.ok === false &&
                xssPubReport.error &&
                !/<(script|img|div|span)\b/i.test(xssPubReport.error.message) &&
                uiSafe
            ) {
                passed++;
            } else {
                console.log("[FAIL] inspect-xss-regression: Inspector returned HTML or used innerHTML");
                failed++;
            }
        }

        // =========================================================================
        // cURL & Raw HTTP Parser Tests (js/core/curlParser.js & js/ui/importer.js)
        // =========================================================================
        const { parseCurl, parseRawHttp } = PopCore;

        // 16) Chrome/Firefox DevTools "Copy as cURL (bash)" 3 samples (many headers, JSON body, escaped quotes)
        {
            const sample1ManyHeaders = [
                "curl 'https://api.example.com/v1/tx?c=3&a=1&b=2' \\",
                "  -H 'accept: application/json, text/plain, */*' \\",
                "  -H 'accept-language: ko-KR,ko;q=0.9,en-US;q=0.8' \\",
                "  -H 'authorization: Bearer eyJhbGciOiJFUzI1NiJ9.test' \\",
                "  -H 'content-type: application/json' \\",
                "  -H 'origin: https://app.example.com' \\",
                "  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \\",
                "  -H 'x-fido2-nonce: n-devtools-1' \\",
                "  -H 'x-fido2-timestamp: 1700000000' \\",
                "  -H 'x-fido2-signature: sig-devtools-1' \\",
                "  -H 'x-body-digest: sha256=deadbeef' \\",
                "  --data-raw '{\"amount\":1000,\"to\":\"alice\"}' \\",
                "  --compressed"
            ].join('\n');

            const sample2MultilineJson =
                'curl --url "https://api.example.com/v1/transfer" \\\r\n' +
                '  -X PUT \\\r\n' +
                '  --header "X-FIDO2-Nonce: n-multi" \\\r\n' +
                '  --header "X-FIDO2-Timestamp: 1700000100" \\\r\n' +
                '  --header "X-FIDO2-Signature: sig-multi" \\\r\n' +
                '  --header "X-Body-Digest: sha256=cafebabe" \\\r\n' +
                "  --data-binary '{\n  \"amount\": 2500,\n  \"memo\": \"line1 & line2\"\n}'";

            const sample3EscapedQuotes =
                "curl 'https://api.example.com/v1/note' " +
                "-H 'X-FIDO2-Nonce: n-quote' " +
                "-H 'X-FIDO2-Timestamp: 1700000200' " +
                "-H 'X-FIDO2-Signature: sig-quote' " +
                "-H 'X-Body-Digest: sha256=112233' " +
                "--data-raw $'{\"note\":\"Alice\\'s \\\\\"quoted\\\\\" text\\nline2\"}'";

            const r1 = parseCurl(sample1ManyHeaders);
            const r2 = parseCurl(sample2MultilineJson);
            const r3 = parseCurl(sample3EscapedQuotes);
            const uiSampleValid = parseCurl(PopUI.buildImportSample('curl-valid'));
            const uiSampleDer = parseCurl(PopUI.buildImportSample('curl-der'));
            const uiSampleRaw = parseCurl(PopUI.buildImportSample('raw-http'));

            if (
                r1.ok === true &&
                r1.inputs.method === 'POST' &&
                r1.inputs.urlStr === 'https://api.example.com/v1/tx?c=3&a=1&b=2' &&
                r1.inputs.nonce === 'n-devtools-1' &&
                r1.inputs.timestampStr === '1700000000' &&
                r1.inputs.signature === 'sig-devtools-1' &&
                r1.inputs.reqDigest === 'sha256=deadbeef' &&
                r1.inputs.bodyStr === '{"amount":1000,"to":"alice"}' &&
                r1.missing.length === 0 &&
                r2.ok === true &&
                r2.inputs.method === 'PUT' &&
                r2.inputs.bodyStr === '{\n  "amount": 2500,\n  "memo": "line1 & line2"\n}' &&
                r3.ok === true &&
                r3.inputs.bodyStr === '{"note":"Alice\'s \\"quoted\\" text\nline2"}' &&
                uiSampleValid.ok === true &&
                uiSampleDer.ok === true &&
                uiSampleRaw.ok === true &&
                uiSampleRaw.format === 'raw-http'
            ) {
                passed++;
            } else {
                console.log("[FAIL] curl-devtools-samples: Failed to parse DevTools or UI sample cURL commands");
                failed++;
            }
        }

        // 17) Duplicate headers, -d without -X, multiple -d joined with &, missing required fields
        {
            const dupAndMultiData =
                "curl 'https://api.example.com/v1/tx' " +
                "-H 'X-FIDO2-Nonce: first-nonce' " +
                "-H 'x-fido2-nonce: final-nonce' " +
                "-d '{\"a\":1}' -d '{\"b\":2}'";
            const res = parseCurl(dupAndMultiData);

            if (
                res.ok === true &&
                res.inputs.method === 'POST' &&
                res.inputs.nonce === 'final-nonce' &&
                res.inputs.bodyStr === '{"a":1}&{"b":2}' &&
                res.warnings.some(w => w.code === 'DUPLICATE_HEADER') &&
                res.warnings.some(w => w.code === 'MULTIPLE_DATA_ARGS') &&
                res.missing.includes('timestampStr') &&
                res.missing.includes('signature') &&
                res.missing.includes('reqDigest') &&
                res.inputs.timestampStr === '' &&
                res.inputs.signature === ''
            ) {
                passed++;
            } else {
                console.log("[FAIL] curl-dup-multi-missing: Failed duplicate header, multiple -d, or missing fields check");
                failed++;
            }
        }

        // 18) Unsupported & security checks: -d @file, --data-urlencode, -F, -G, --json, $(...), $VAR, pipe, cmd ^, empty, >1MB
        {
            const fileRes = parseCurl("curl https://api.example.com/v1/tx -d @secret.json");
            const urlencRes = parseCurl("curl https://api.example.com/v1/tx --data-urlencode 'a=b'");
            const formRes = parseCurl("curl https://api.example.com/v1/tx -F 'file=@a.txt'");
            const getFlagRes = parseCurl("curl https://api.example.com/v1/tx -G -d 'a=1'");
            const jsonFlagRes = parseCurl("curl https://api.example.com/v1/tx --json '{\"a\":1}'");
            const cmdSubRes = parseCurl("curl https://api.example.com/v1/tx -H \"X-FIDO2-Nonce: $(whoami)\"");
            const varSubRes = parseCurl("curl https://api.example.com/v1/tx -H $SECRET_HEADER");
            const pipeRes = parseCurl("curl https://api.example.com/v1/tx | sh");
            const caretRes = parseCurl("curl https://api.example.com/v1/tx ^\n  -X POST");
            const emptyRes = parseCurl("   ");
            const nonCurlRes = parseCurl("wget https://api.example.com/v1/tx");
            const hugeInput = "curl https://api.example.com/v1/tx -d '" + "x".repeat(600 * 1024) + "'";
            const hugeRes = parseCurl(hugeInput);

            if (
                fileRes.ok === false && fileRes.unsupported.some(u => u.code === 'FILE_READ_UNSUPPORTED') &&
                urlencRes.ok === false && urlencRes.unsupported.some(u => u.code === 'UNSUPPORTED_OPTION') &&
                formRes.ok === false && formRes.unsupported.some(u => u.code === 'UNSUPPORTED_OPTION') &&
                getFlagRes.ok === false && getFlagRes.unsupported.some(u => u.code === 'UNSUPPORTED_OPTION') &&
                jsonFlagRes.ok === false && jsonFlagRes.unsupported.some(u => u.code === 'UNSUPPORTED_OPTION') &&
                cmdSubRes.ok === false && cmdSubRes.unsupported.some(u => u.code === 'SHELL_EXPANSION_UNSUPPORTED') &&
                varSubRes.ok === false && varSubRes.unsupported.some(u => u.code === 'SHELL_EXPANSION_UNSUPPORTED') &&
                pipeRes.ok === false && pipeRes.unsupported.some(u => u.code === 'PIPE_OR_REDIRECTION_UNSUPPORTED') &&
                caretRes.ok === false && caretRes.unsupported.some(u => u.code === 'CMD_CARET_CONTINUATION') &&
                emptyRes.ok === false && emptyRes.unsupported.some(u => u.code === 'EMPTY_INPUT') &&
                nonCurlRes.ok === false && nonCurlRes.unsupported.some(u => u.code === 'NOT_CURL_COMMAND') &&
                hugeRes.ok === false && hugeRes.unsupported.some(u => u.code === 'INPUT_TOO_LARGE')
            ) {
                passed++;
            } else {
                console.log("[FAIL] curl-unsupported-security: One or more unsupported/security checks did not report properly");
                failed++;
            }
        }

        // 19) Raw HTTP parsing (both CRLF and LF, Host + path reconstruction with https default warning)
        {
            const rawLines = [
                'POST /v1/tx?c=3&a=1&b=2 HTTP/1.1',
                'Host: api.example.com',
                'Content-Type: application/json',
                'X-FIDO2-Nonce: n-raw-1',
                'X-FIDO2-Timestamp: 1700000000',
                'X-FIDO2-Signature: sig-raw-1',
                'X-Body-Digest: sha256=abcdef',
                '',
                '{',
                '  "amount": 1000',
                '}'
            ];
            const crlfHttp = rawLines.join('\r\n');
            const lfHttp = rawLines.join('\n');

            const crlfRes = parseCurl(crlfHttp);
            const lfRes = parseRawHttp(lfHttp);

            const brokenJsonHttp = [
                'POST /v1/tx?c=3&a=1&b=2 HTTP/1.1',
                'Host: api.example.com',
                'Content-Type: application/json',
                'X-FIDO2-Nonce: n-123456789',
                'X-FIDO2-Timestamp: 1791356800',
                'X-FIDO2-Signature: -2M3ebL7X2gWy_XhoePc8igyBlGZDYBbo8hcLztVnhfz-38OER3tW1RrooCSk_ybQ5O-c4DoLeWyaaQjc4Q_Yw',
                'X-Body-Digest: sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18',
                '',
                '',
                '  "amount": 1000,',
                '  "to": "alice"',
                '}'
            ].join('\n');
            const brokenParsed = parseCurl(brokenJsonHttp);
            const brokenDiag = await PopCore.diagnose({
                ...brokenParsed.inputs,
                pubkeyPem: '' // even when pubkeyPem is empty, broken JSON should be caught
            });

            if (
                crlfRes.ok === true &&
                crlfRes.format === 'raw-http' &&
                crlfRes.inputs.method === 'POST' &&
                crlfRes.inputs.urlStr === 'https://api.example.com/v1/tx?c=3&a=1&b=2' &&
                crlfRes.inputs.nonce === 'n-raw-1' &&
                crlfRes.inputs.bodyStr === '{\r\n  "amount": 1000\r\n}' &&
                crlfRes.warnings.some(w => w.code === 'DEFAULT_HTTPS_SCHEME') &&
                lfRes.ok === true &&
                lfRes.inputs.urlStr === 'https://api.example.com/v1/tx?c=3&a=1&b=2' &&
                lfRes.inputs.bodyStr === '{\n  "amount": 1000\n}' &&
                brokenParsed.ok === true &&
                brokenDiag.error &&
                brokenDiag.error.code === PopCore.ERROR_CODES.INVALID_JSON &&
                brokenDiag.error.detail.includes('▲')
            ) {
                passed++;
            } else {
                console.log("[FAIL] raw-http-crlf-lf: Failed CRLF/LF or broken JSON Raw HTTP parsing/diagnosis");
                failed++;
            }
        }

        // 20) Round-trip test: fixture -> cURL command -> parseCurl -> diagnose matches direct fixture diagnosis
        {
            let allRoundTripsOk = true;
            for (const c of fixtures.cases) {
                const url = `https://${c.host}${c.path}?${c.query}`;
                const escapedBody = c.body.replace(/'/g, "'\\''");
                const curlParts = [
                    `curl '${url}'`,
                    `-X '${c.method}'`,
                    `-H 'X-FIDO2-Nonce: ${c.nonce}'`,
                    `-H 'X-FIDO2-Timestamp: ${c.timestamp}'`,
                    `-H 'X-FIDO2-Signature: ${c.signature}'`
                ];
                if (c.digest) {
                    curlParts.push(`-H 'X-Body-Digest: ${c.digest}'`);
                }
                if (c.body !== '') {
                    curlParts.push(`--data-binary '${escapedBody}'`);
                }
                const curlCmd = curlParts.join(' \\\n  ');
                const parsed = parseCurl(curlCmd);
                if (!parsed.ok) {
                    allRoundTripsOk = false;
                    break;
                }

                const directRes = await PopCore.diagnose({
                    method: c.method,
                    urlStr: url,
                    bodyStr: c.body,
                    nonce: c.nonce,
                    timestampStr: String(c.timestamp),
                    signature: c.signature,
                    pubkeyPem,
                    evalTime: c.evalTime,
                    reqDigest: c.digest
                });

                const roundTripRes = await PopCore.diagnose({
                    ...parsed.inputs,
                    pubkeyPem,
                    evalTime: c.evalTime
                });

                if (
                    directRes.firstFailedStage !== roundTripRes.firstFailedStage ||
                    JSON.stringify(directRes.hypothesisResult) !== JSON.stringify(roundTripRes.hypothesisResult)
                ) {
                    allRoundTripsOk = false;
                    break;
                }
            }

            if (allRoundTripsOk) {
                passed++;
            } else {
                console.log("[FAIL] curl-diagnose-roundtrip: Fixture -> cURL -> parseCurl -> diagnose mismatch");
                failed++;
            }
        }

        // 21) XSS regression test for cURL parser & importer UI
        {
            const xssCurl =
                "curl 'https://api.example.com/v1/tx' " +
                "-H 'X-FIDO2-Nonce: <script>alert(1)</script>' " +
                "-H 'X-FIDO2-Nonce: <img src=x onerror=alert(2)>' " +
                "--data-raw '{\"xss\":\"<svg onload=alert(3)>\"}'";
            const xssParsed = parseCurl(xssCurl);

            let importerInnerHtmlUsed = false;
            function createImporterMockNode(tagName) {
                return {
                    tagName,
                    className: '',
                    classList: {
                        remove() {},
                        add() {}
                    },
                    children: [],
                    _text: '',
                    get textContent() {
                        return this._text + this.children.map(c => c.textContent).join('');
                    },
                    set textContent(val) {
                        this._text = String(val ?? '');
                        this.children = [];
                    },
                    set innerHTML(_val) {
                        importerInnerHtmlUsed = true;
                    },
                    appendChild(child) {
                        this.children.push(child);
                        return child;
                    }
                };
            }

            let importerUiSafe = true;
            if (typeof window === 'undefined') {
                const prevDoc = global.document;
                global.document = {
                    createElement(tag) {
                        return createImporterMockNode(tag.toUpperCase());
                    },
                    createTextNode(text) {
                        const n = createImporterMockNode('#text');
                        n._text = String(text ?? '');
                        return n;
                    }
                };
                try {
                    const banner = createImporterMockNode('DIV');
                    PopUI.renderImportStatus(banner, xssParsed);
                    importerUiSafe = !importerInnerHtmlUsed &&
                        banner.children.some(c => c.className === 'import-report import-report-ok');
                } finally {
                    global.document = prevDoc;
                }
            }

            if (
                xssParsed.ok === true &&
                xssParsed.inputs.nonce === '<img src=x onerror=alert(2)>' &&
                xssParsed.inputs.bodyStr === '{"xss":"<svg onload=alert(3)>"}' &&
                importerUiSafe
            ) {
                passed++;
            } else {
                console.log("[FAIL] curl-xss-regression: cURL parser altered HTML payload or importer UI used innerHTML");
                failed++;
            }
        }

        // 22) JSON error detection & smart hint unit and integration tests
        {
            const userCaseBody = '\n  "amount": 1000,\n  "to": "alice"\n}';
            const userCaseRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: userCaseBody,
                nonce: "n1",
                timestampStr: "1700000000",
                signature: validSig,
                pubkeyPem: fixtures.public_key
            });

            const missingClosingRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: '{\n  "amount": 1000',
                nonce: "n1",
                timestampStr: "1700000000",
                signature: validSig,
                pubkeyPem: fixtures.public_key
            });

            const trailingCommaRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: '{\n  "amount": 1000,\n}',
                nonce: "n1",
                timestampStr: "1700000000",
                signature: validSig,
                pubkeyPem: fixtures.public_key
            });

            const singleQuoteRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: "{\n  'amount': 1000\n}",
                nonce: "n1",
                timestampStr: "1700000000",
                signature: validSig,
                pubkeyPem: fixtures.public_key
            });

            const unquotedKeyRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: "{\n  amount: 1000\n}",
                nonce: "n1",
                timestampStr: "1700000000",
                signature: validSig,
                pubkeyPem: fixtures.public_key
            });

            const userCaseOk =
                userCaseRes.error &&
                userCaseRes.error.code === PopCore.ERROR_CODES.INVALID_JSON &&
                userCaseRes.error.hintCode === PopCore.JSON_HINT_CODES.MISSING_OPEN_BRACE &&
                typeof userCaseRes.error.hint === 'string' &&
                userCaseRes.error.detail.includes('▲');

            const missingClosingOk =
                missingClosingRes.error &&
                missingClosingRes.error.code === PopCore.ERROR_CODES.INVALID_JSON &&
                missingClosingRes.error.hintCode === PopCore.JSON_HINT_CODES.MISSING_CLOSE_BRACE &&
                typeof missingClosingRes.error.hint === 'string';

            const trailingCommaOk =
                trailingCommaRes.error &&
                trailingCommaRes.error.code === PopCore.ERROR_CODES.INVALID_JSON &&
                trailingCommaRes.error.hintCode === PopCore.JSON_HINT_CODES.TRAILING_COMMA &&
                typeof trailingCommaRes.error.hint === 'string';

            const singleQuoteOk =
                singleQuoteRes.error &&
                singleQuoteRes.error.code === PopCore.ERROR_CODES.INVALID_JSON &&
                singleQuoteRes.error.hintCode === PopCore.JSON_HINT_CODES.SINGLE_QUOTE &&
                typeof singleQuoteRes.error.hint === 'string';

            const unquotedKeyOk =
                unquotedKeyRes.error &&
                unquotedKeyRes.error.code === PopCore.ERROR_CODES.INVALID_JSON &&
                unquotedKeyRes.error.hintCode === PopCore.JSON_HINT_CODES.UNQUOTED_KEY &&
                typeof unquotedKeyRes.error.hint === 'string';

            if (userCaseOk && missingClosingOk && trailingCommaOk && singleQuoteOk && unquotedKeyOk) {
                passed++;
            } else {
                console.log("[FAIL] json-error-smart-hints: Failed JSON error diagnosis or smart hint generation");
                failed++;
            }
        }

        // 23) Hypotheses actionable cause & solution guidance verification
        {
            const allHypothesesHaveGuide = PopCore.HYPOTHESES.every(h => {
                return typeof h.cause === 'string' && h.cause.length > 5 &&
                       typeof h.solution === 'string' && h.solution.length > 5;
            });

            const derCase = fixtures.cases.find(c => c.name === 'sig-der');
            const derRes = await PopCore.diagnose({
                method: derCase.method,
                urlStr: `https://${derCase.host}${derCase.path}?${derCase.query}`,
                bodyStr: derCase.body,
                nonce: derCase.nonce,
                timestampStr: String(derCase.timestamp),
                signature: derCase.signature,
                pubkeyPem: fixtures.public_key,
                evalTime: derCase.evalTime,
                reqDigest: derCase.digest
            });

            const derHypMatch = derRes.hypothesisResult &&
                               derRes.hypothesisResult.type === 'found' &&
                               derRes.hypothesisResult.sets.length > 0 &&
                               derRes.hypothesisResult.sets[0].item &&
                               derRes.hypothesisResult.sets[0].item.history[0];

            const expectedDerHyp = PopCore.HYPOTHESES.find(h => h.id === 'sig-der');
            const derGuideOk = derHypMatch &&
                               expectedDerHyp &&
                               derHypMatch.id === 'sig-der' &&
                               derHypMatch.cause === expectedDerHyp.cause &&
                               derHypMatch.solution === expectedDerHyp.solution;

            if (allHypothesesHaveGuide && derGuideOk) {
                passed++;
            } else {
                console.log("[FAIL] hypotheses-actionable-guide: Missing cause/solution in hypothesis catalog or diagnose result");
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
