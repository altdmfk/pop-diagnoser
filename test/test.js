const PopCore = (typeof window !== 'undefined' && window.PopCore)
    ? window.PopCore
    : require('../js/core/diagnose.js');
const fixtures = (typeof window !== 'undefined' && window.PopTestFixtures)
    ? window.PopTestFixtures
    : require('./fixtures/fixtures.js');
const PopUI = (typeof window !== 'undefined' && window.PopUI)
    ? window.PopUI
    : Object.assign(
        {},
        require('../js/ui/samples.js'),
        require('../js/ui/jsonError.js'),
        require('../js/ui/render.js'),
        require('../js/ui/slots.js'),
        require('../js/ui/tabs.js'),
        require('../js/ui/inspector.js'),
        require('../js/ui/importer.js')
    );

function createMockElement(tagName, options = {}) {
    const isTextarea = Boolean(options.isTextarea || String(tagName).toUpperCase() === 'TEXTAREA');
    const el = {
        tagName: String(tagName ?? 'DIV'),
        id: '',
        className: '',
        disabled: false,
        dataset: {},
        attributes: {},
        children: [],
        listeners: {},
        _val: '',
        _text: '',
        _htmlTrapTriggered: false,
        classList: {
            add() {},
            remove() {},
            contains(cls) {
                return String(el.className || '').split(/\s+/).includes(cls);
            },
            toggle() {}
        },
        setAttribute(name, val) {
            this.attributes[name] = String(val);
        },
        getAttribute(name) {
            return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
        },
        remove() {},
        addEventListener(ev, fn) {
            this.listeners[ev] = fn;
        },
        get textContent() {
            const childText = this.children
                .map(c => (c && c.textContent !== undefined ? c.textContent : (c && c.text !== undefined ? c.text : '')))
                .join('');
            return this._text + childText;
        },
        set textContent(val) {
            this._text = String(val ?? '');
            this.children = [];
        },
        set innerHTML(_val) {
            this._htmlTrapTriggered = true;
            const trap = options.onHtmlTrap || options.onInnerHtml;
            if (typeof trap === 'function') {
                trap('innerHTML', _val);
            }
        },
        set outerHTML(_val) {
            this._htmlTrapTriggered = true;
            const trap = options.onHtmlTrap || options.onInnerHtml;
            if (typeof trap === 'function') {
                trap('outerHTML', _val);
            }
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
        },
        querySelectorAll(selector) {
            const selectors = String(selector || '').split(',').map(s => s.trim()).filter(Boolean);
            const matches = [];
            const visit = (node) => {
                for (const ch of (node.children || [])) {
                    const matched = selectors.some(sel => {
                        if (sel.startsWith('.')) {
                            return String(ch.className || '').split(/\s+/).includes(sel.slice(1));
                        }
                        if (sel.startsWith('#')) {
                            return ch.id === sel.slice(1);
                        }
                        return String(ch.tagName || '').toUpperCase() === sel.toUpperCase();
                    });
                    if (matched) matches.push(ch);
                    visit(ch);
                }
            };
            visit(this);
            return matches;
        },
        querySelector(selector) {
            const all = this.querySelectorAll(selector);
            return all.length > 0 ? all[0] : null;
        }
    };

    if (isTextarea) {
        Object.defineProperty(el, 'value', {
            get() { return this._val; },
            set(v) { this._val = String(v ?? '').replace(/\r\n/g, '\n'); }
        });
    } else {
        el.value = '';
    }

    return el;
}

function createMockDocument(options = {}) {
    const elMap = options.elements || {};
    const elemOptions = { onHtmlTrap: options.onHtmlTrap || options.onInnerHtml };
    const docListeners = options.listeners || {};
    const autoCreate = Boolean(options.autoCreateById || options.autoCreateElements);
    const defaultTag = options.defaultByIdTag || options.defaultTag || 'INPUT';
    return {
        body: createMockElement('BODY', elemOptions),
        listeners: docListeners,
        addEventListener(ev, fn) {
            docListeners[ev] = fn;
        },
        getElementById(id) {
            if (Object.prototype.hasOwnProperty.call(elMap, id)) {
                return elMap[id];
            }
            if (autoCreate) {
                elMap[id] = createMockElement(defaultTag, elemOptions);
                return elMap[id];
            }
            return null;
        },
        createElement(tag) {
            return createMockElement(String(tag).toUpperCase(), elemOptions);
        },
        createTextNode(text) {
            const node = createMockElement('#text', elemOptions);
            node._text = String(text ?? '');
            return node;
        },
        querySelectorAll(selector) {
            return this.body.querySelectorAll(selector);
        },
        querySelector(selector) {
            return this.body.querySelector(selector);
        }
    };
}

async function runTests() {
    const pubkeyPem = fixtures.public_key;
    let passed = 0;
    let failed = 0;
    let skipped = 0;

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
        { name: "bad-json", inputs: { method: "POST", urlStr: "https://a.com/", bodyStr: "{bad json}", nonce: "1", timestampStr: "1", signature: validSig, pubkeyPem: pubkeyPem }, expectError: false, expectedStage: 2, expectedWarningCode: PopCore.ERROR_CODES.INVALID_JSON },
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
        if (t.expectedWarningCode && (!result.warnings || !result.warnings.some(w => w.code === t.expectedWarningCode))) {
            console.log(`[FAIL] ${t.name}: Expected warning code ${t.expectedWarningCode}, got ${JSON.stringify(result.warnings)}`);
            ok = false;
        }
        if (t.expectedStage !== undefined && result.firstFailedStage !== t.expectedStage) {
            console.log(`[FAIL] ${t.name}: Expected firstFailedStage ${t.expectedStage}, got ${result.firstFailedStage}`);
            ok = false;
        }
        if (ok) passed++; else failed++;
    }

    // Hypothesis catalog & DER boundary tests using independent SHA-256 & ECDSA P-256 test vectors
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

    // Independent SHA-256 hex digest vectors (precomputed via RFC 6234 SHA-256 without calling PopCore.hashString)
    const baseBody = '{\n  "amount": 1000,\n  "to": "alice"\n}';
    const baseBodyHash = "11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18";
    const trailingBodyHash = "c2dcf36bf561397e745b132a268aa8834b6314ad9499d0aab24f5ba787c7f21c";
    const upperBodyHash = "11ABF1E8F4F0C1D061F050DB6235625033A2B55F486027C92C88B02542408E18";
    const bomBodyHash = "e6cf8512c3edd5c1f335b798296f4cff5c8c78ae432f0ce75453ccef82b155bb";
    const bomCrlfBodyHash = "c2253c039a11e3b50dbc4673421bf77203b45a4fad3b3fd365c22587cf7c23c3";
    const noSpaceBodyHash = "1e8ae6aa523704c641f4158680f5d758b2e4cc95380ef867a7e4ecbc4ccb0b16";
    const crlfBodyHash = "6b0421c956fbb12b58aa984ca6338c9f9210ffc0ccde60d5e5cab9117d0a6088";
    const ts = "1791356800";
    const nonce = "n-test-999";

    // Deterministic fixed P-256 key and signatures for standard Base64 (+, /, =) and <70B short DER (69B)
    const FIXED_VEC_PUBKEY_PEM =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsm0SgmJR0zSk4Z3piS6HhAvTceT6\n" +
        "WhNKI8ytpwZOluCDXM9uxZPvAC1uczn+SKE/10g/6yV9SGQPmgYTKvKvMg==\n" +
        "-----END PUBLIC KEY-----";
    const FIXED_VEC_PUBKEY_FP = "b409c9fcb5aa9b4c82cc05c41280f06b24e2b4269dd9a41b146b63d0a2cb5595";
    const FIXED_STD_B64_SIG = "N5pGLOwDMX8uR+ERCvJANUBSJKaIFzAkNyhItAxi4XAHZ8kE5x5th8bASa8GnkN/zHJUalYyc8lSxGBRlsHdFw==";
    const FIXED_SHORT_DER_B64URL = "MEMCHw6bziZsTTot-1eV3xPzPS7mrNfnz9mrom2Pm8VU_PMCIHa7LZUFfnfSyL3NiDBP2NnfBjEOzTXTPreUl5P3MiF0";

    const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

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
                signature: FIXED_STD_B64_SIG,
                pubkeyPem: FIXED_VEC_PUBKEY_PEM,
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
        },
        {
            name: "hyp-sig-der-short-under-70b",
            inputs: {
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: FIXED_SHORT_DER_B64URL,
                pubkeyPem: FIXED_VEC_PUBKEY_PEM,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            },
            expectedStage: 4,
            expectedIdStr: "sig-der"
        }
    ];

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
        const xssJsonWarn = xssBodyRes.warnings && xssBodyRes.warnings.find(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);
        if (
            xssBodyRes.error === null &&
            xssJsonWarn &&
            typeof xssJsonWarn.message === 'string' &&
            !/<(div|strong|span|br)\b/i.test(xssJsonWarn.message) &&
            typeof xssJsonWarn.detail === 'string' &&
            xssJsonWarn.detail.includes('<img src=x onerror=alert(1)>') &&
            !xssJsonWarn.detail.includes('<div')
        ) {
            passed++;
        } else {
            console.log("[FAIL] xss-core-body-json: Core returned HTML wrapper or lost raw payload in warning.detail");
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

        // 4) generateTestSignature returns non-blocking .warning with .detail (no HTML <div class="error-detail-box">)
        let genWarnOk = false;
        let genXssRes = null;
        try {
            genXssRes = await PopCore.generateTestSignature({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: xssBodyPayload,
                nonce: "n1",
                timestampStr: ts
            });
            const w = genXssRes && genXssRes.warning;
            if (
                genXssRes &&
                typeof genXssRes.signature === 'string' &&
                genXssRes.signature.length > 0 &&
                w &&
                w.code === PopCore.ERROR_CODES.INVALID_JSON &&
                !/<(div|strong|span|br)\b/i.test(w.message) &&
                typeof w.detail === 'string' &&
                w.detail.includes('<img src=x onerror=alert(1)>') &&
                !w.detail.includes('<div')
            ) {
                genWarnOk = true;
            }
        } catch (_err) {
            genWarnOk = false;
        }
        if (genWarnOk) {
            passed++;
        } else {
            console.log("[FAIL] xss-core-generate-sig: generateTestSignature threw or warning contained HTML / missed .detail");
            failed++;
        }

        // 5) UI renderResult & renderGenerateSuccess DOM verification: 0 innerHTML assignments, payloads exist strictly in textContent
        let innerHtmlUsed = false;
        const markHtmlTrap = () => { innerHtmlUsed = true; };

        if (typeof window === 'undefined') {
            const mockPanel = createMockElement('DIV', { onHtmlTrap: markHtmlTrap });
            const prevDoc = global.document;
            global.document = createMockDocument({
                elements: { 'result-panel': mockPanel },
                onHtmlTrap: markHtmlTrap
            });

            try {
                renderResult(xssBodyRes);
                const bodyRenderedText = mockPanel.textContent;
                const bodyRenderSafe = !innerHtmlUsed && bodyRenderedText.includes('<img src=x onerror=alert(1)>');

                renderResult(xssMethodRes);
                const methodRenderedText = mockPanel.textContent;
                const methodRenderSafe = !innerHtmlUsed && methodRenderedText.includes('<script>alert(1)</script>');

                let genRenderSafe = false;
                if (genXssRes && typeof PopUI.renderGenerateSuccess === 'function') {
                    PopUI.renderGenerateSuccess(mockPanel, genXssRes);
                    const genRenderedText = mockPanel.textContent;
                    genRenderSafe = !innerHtmlUsed && genRenderedText.includes('<img src=x onerror=alert(1)>');
                }

                if (bodyRenderSafe && methodRenderSafe && genRenderSafe) {
                    passed++;
                } else {
                    console.log("[FAIL] xss-ui-renderResult: innerHTML was used or textContent missing payload");
                    failed++;
                }
            } finally {
                global.document = prevDoc;
            }
        } else {
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
            let genOk = false;
            if (genXssRes && typeof PopUI.renderGenerateSuccess === 'function') {
                PopUI.renderGenerateSuccess(tempPanel, genXssRes);
                genOk = tempPanel.textContent.includes('<img src=x onerror=alert(1)>') && tempPanel.querySelectorAll('img').length === 0;
            }
            if (createdTemp) tempPanel.remove();
            if (bodyOk && methodOk && genOk) {
                passed++;
            } else {
                console.log("[FAIL] xss-ui-renderResult: Browser DOM XSS check failed");
                failed++;
            }
        }

        // 6) localStorage resilience (blocked storage & corrupted JSON — runs in both Node and Browser)
        {
            const blockedStorageMock = {
                getItem() { throw new Error("SecurityError: localStorage disabled"); },
                setItem() { throw new Error("QuotaExceededError"); }
            };
            const blockedRead = readMemorySlots(blockedStorageMock);
            const blockedWrite = writeMemorySlots({ slot_1: {} }, blockedStorageMock);

            const corruptedStorageMock = {
                getItem() { return "{broken-json"; },
                setItem() {}
            };
            const corruptedRead = readMemorySlots(corruptedStorageMock);

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
        }

        // 6-1) Slot storage default label derivation & path extraction
        {
            const { extractSlotPath, deriveDefaultLabel } = PopUI;
            const postTx = deriveDefaultLabel({ method: 'POST', urlStr: 'https://api.example.com/v1/tx?a=1' });
            const getNoUrl = deriveDefaultLabel({ method: 'GET', urlStr: '' });
            const noMethod = deriveDefaultLabel({ method: '', urlStr: 'https://api.example.com/items' });
            const emptyAll = deriveDefaultLabel({ method: '', urlStr: '' });
            const path1 = extractSlotPath('https://api.example.com/v1/orders/123?filter=all#hash');
            const pathEmpty = extractSlotPath('');

            if (
                postTx === 'POST /v1/tx' &&
                getNoUrl === 'GET (URL 없음)' &&
                noMethod === '/items' &&
                emptyAll === '(URL 없음)' &&
                path1 === '/v1/orders/123' &&
                pathEmpty === '(URL 없음)'
            ) {
                passed++;
            } else {
                console.log("[FAIL] slot-storage-default-label: Failed default label derivation or path extraction");
                failed++;
            }
        }

        // 6-2) Slot custom label persistence & backward compatibility
        {
            const { readMemorySlots, writeMemorySlots, deriveDefaultLabel, formatSavedTime, formatSlotPreview } = PopUI;
            const mockStorage = {
                store: {},
                getItem(k) { return Object.prototype.hasOwnProperty.call(this.store, k) ? this.store[k] : null; },
                setItem(k, v) { this.store[k] = String(v); }
            };

            // Custom label persistence
            const customData = {
                slot_1: {
                    label: '사용자 지정 결제 건',
                    method: 'POST',
                    urlStr: 'https://api.example.com/v1/tx',
                    signature: 'MEQCICtestSig1234567890'
                }
            };
            const writeRes = writeMemorySlots(customData, mockStorage);
            const readRes = readMemorySlots(mockStorage);

            // Old-format slot backward compatibility (no label, no savedAt, only legacy time)
            const oldFormatSlot = {
                time: '12:34:56',
                method: 'POST',
                urlStr: 'https://api.example.com/legacy',
                bodyStr: '{"foo":"bar"}'
            };
            const oldDerivedLabel = deriveDefaultLabel(oldFormatSlot);
            const oldFormattedTime = formatSavedTime(oldFormatSlot.savedAt, oldFormatSlot.time);
            const oldPreview = formatSlotPreview(oldFormatSlot);

            if (
                writeRes.ok === true &&
                readRes.ok === true &&
                readRes.data.slot_1.label === '사용자 지정 결제 건' &&
                oldDerivedLabel === 'POST /legacy' &&
                oldFormattedTime === '12:34:56' &&
                oldPreview.includes('URL: https://api.example.com/legacy') &&
                oldPreview.includes('{"foo":"bar"}')
            ) {
                passed++;
            } else {
                console.log("[FAIL] slot-storage-custom-label-and-compat: Custom label persistence or old-format compatibility failed");
                failed++;
            }
        }

        // 6-3) Slot body UTF-8 byte length (including multi-byte Korean) & signature flag
        {
            const { getUtf8ByteLength, formatSlotPreview } = PopUI;
            const asciiLen = getUtf8ByteLength('{"status":"ok"}');
            const koreanLen = getUtf8ByteLength('{"msg":"결제 완료"}');
            const emptyLen = getUtf8ByteLength('');
            const nullLen = getUtf8ByteLength(null);
            const emojiLen = getUtf8ByteLength('{"emoji":"😀"}');

            // Signature flag check
            const sigPresent = Boolean('MEQCIC4h9v...'.trim().length > 0);
            const sigEmpty = Boolean(''.trim().length > 0);
            const sigWhitespace = Boolean('   '.trim().length > 0);

            // Preview truncation check
            const longBody = 'A'.repeat(200);
            const previewLong = formatSlotPreview({
                urlStr: 'https://example.com/test',
                bodyStr: longBody,
                signature: '12345678901234567890'
            });

            if (
                asciiLen === 15 &&
                koreanLen === 23 &&
                emptyLen === 0 &&
                nullLen === 0 &&
                emojiLen === 16 &&
                sigPresent === true &&
                sigEmpty === false &&
                sigWhitespace === false &&
                previewLong.includes('…') &&
                previewLong.includes('1234567890123456…')
            ) {
                passed++;
            } else {
                console.log("[FAIL] slot-storage-body-bytes-and-sig: UTF-8 byte length, signature flag or preview truncation failed");
                failed++;
            }
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

        // 9) Static accessibility check (Node fs): every <label for="..."> in index.html points to an existing id
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
        } else {
            skipped++;
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

        // 11) inspectSignature: DER (72B with leading 0x00 and 68B without leading 0x00 using explicit fixed DER byte arrays)
        {
            // Explicit 72B DER: 30 46 02 21 00 8a 00...00 01 02 21 00 90 00...00 02
            const der72 = new Uint8Array(72);
            der72[0] = 0x30; der72[1] = 70;
            der72[2] = 0x02; der72[3] = 33; der72[4] = 0x00; der72[5] = 0x8a; der72[36] = 0x01;
            der72[37] = 0x02; der72[38] = 33; der72[39] = 0x00; der72[40] = 0x90; der72[71] = 0x02;
            const expectedR72Hex = "8a" + "00".repeat(30) + "01";
            const expectedS72Hex = "90" + "00".repeat(30) + "02";
            const der72Res = inspectSignature(toBase64Url(der72.buffer));

            // Explicit 68B Short DER: 30 42 02 1e 45 00...00 11 02 20 3f 00...00 22
            const der68 = new Uint8Array(68);
            der68[0] = 0x30; der68[1] = 66;
            der68[2] = 0x02; der68[3] = 30; der68[4] = 0x45; der68[33] = 0x11;
            der68[34] = 0x02; der68[35] = 32; der68[36] = 0x3f; der68[67] = 0x22;
            const expectedR68Hex = "000045" + "00".repeat(28) + "11";
            const expectedS68Hex = "3f" + "00".repeat(30) + "22";
            const der68Res = inspectSignature(toBase64Url(der68.buffer));

            if (
                der72.byteLength === 72 &&
                der72Res.ok === true &&
                der72Res.format === 'der' &&
                der72Res.rLeadingZeroStripped === true &&
                der72Res.sLeadingZeroStripped === true &&
                der72Res.r === expectedR72Hex &&
                der72Res.s === expectedS72Hex &&
                der68.byteLength === 68 &&
                der68Res.ok === true &&
                der68Res.format === 'der' &&
                der68Res.rLeadingZeroStripped === false &&
                der68Res.sLeadingZeroStripped === false &&
                der68Res.r === expectedR68Hex &&
                der68Res.s === expectedS68Hex
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

        // 13) inspectPublicKey: valid P-256 keys & independent SHA-256 fingerprint test vector
        {
            const vecPubRes = await inspectPublicKey(FIXED_VEC_PUBKEY_PEM);
            const fixPubRes = await inspectPublicKey(pubkeyPem);
            const genOut = await PopCore.generateTestSignature({
                method: 'POST',
                urlStr: 'https://api.example.com/v1/tx',
                bodyStr: '{"ok":true}',
                nonce: 'n-inspect',
                timestampStr: ts
            });
            const genPubRes = await inspectPublicKey(genOut.pubkeyPem);

            if (
                vecPubRes.ok === true &&
                vecPubRes.algorithmOid === '1.2.840.10045.2.1' &&
                vecPubRes.curveOid === '1.2.840.10045.3.1.7' &&
                vecPubRes.pointFormat === 'uncompressed(0x04)' &&
                vecPubRes.x.length === 64 &&
                vecPubRes.y.length === 64 &&
                vecPubRes.onCurve === true &&
                vecPubRes.fingerprint === FIXED_VEC_PUBKEY_FP &&
                fixPubRes.ok === true &&
                fixPubRes.onCurve === true &&
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
            const markInspectorHtmlTrap = () => { inspectorInnerHtmlUsed = true; };

            let uiSafe = false;
            if (typeof window === 'undefined') {
                const prevDoc = global.document;
                global.document = createMockDocument({ onHtmlTrap: markInspectorHtmlTrap });
                try {
                    const sigBox = createMockElement('DIV', { onHtmlTrap: markInspectorHtmlTrap });
                    const pubBox = createMockElement('DIV', { onHtmlTrap: markInspectorHtmlTrap });
                    PopUI.renderSignatureInspect(sigBox, xssSigReport);
                    PopUI.renderPublicKeyInspect(pubBox, xssPubReport);
                    uiSafe = !inspectorInnerHtmlUsed &&
                        sigBox.textContent.includes('INVALID_ENCODING') &&
                        pubBox.textContent.includes('INVALID_BASE64');
                } finally {
                    global.document = prevDoc;
                }
            } else {
                const sigBox = document.createElement('div');
                const pubBox = document.createElement('div');
                PopUI.renderSignatureInspect(sigBox, xssSigReport);
                PopUI.renderPublicKeyInspect(pubBox, xssPubReport);
                uiSafe =
                    sigBox.querySelectorAll('script,img').length === 0 &&
                    pubBox.querySelectorAll('script,img').length === 0 &&
                    sigBox.textContent.includes('INVALID_ENCODING') &&
                    pubBox.textContent.includes('INVALID_BASE64');
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
                pubkeyPem: '' // Stage 1 runs first (missing pubkey -> stage 1 fail), while broken JSON is recorded as warning
            });
            const brokenWarn = brokenDiag.warnings && brokenDiag.warnings.find(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);

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
                brokenDiag.error === null &&
                brokenDiag.firstFailedStage === 1 &&
                brokenWarn &&
                typeof brokenWarn.line === 'number' &&
                typeof brokenWarn.column === 'number' &&
                !brokenWarn.detail.includes('▲') &&
                PopUI.formatJsonErrorSnippet(brokenWarn).includes('▲')
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
            const markImporterHtmlTrap = () => { importerInnerHtmlUsed = true; };

            let importerUiSafe = false;
            if (typeof window === 'undefined') {
                const prevDoc = global.document;
                global.document = createMockDocument({ onHtmlTrap: markImporterHtmlTrap });
                try {
                    const banner = createMockElement('DIV', { onHtmlTrap: markImporterHtmlTrap });
                    PopUI.renderImportStatus(banner, xssParsed);
                    importerUiSafe = !importerInnerHtmlUsed &&
                        banner.children.some(c => c.className === 'import-report import-report-ok');
                } finally {
                    global.document = prevDoc;
                }
            } else {
                const banner = document.createElement('div');
                PopUI.renderImportStatus(banner, xssParsed);
                importerUiSafe =
                    banner.querySelectorAll('script,img,svg').length === 0 &&
                    banner.querySelector('.import-report-ok') !== null;
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
            const missingOpenBraceBody = '\n  "amount": 1000,\n  "to": "alice"\n}';
            const missingOpenBraceRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx",
                bodyStr: missingOpenBraceBody,
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

            const getJsonWarn = (r) => r.warnings && r.warnings.find(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);
            const wMissingOpen = getJsonWarn(missingOpenBraceRes);
            const wMissingClose = getJsonWarn(missingClosingRes);
            const wTrailing = getJsonWarn(trailingCommaRes);
            const wSingle = getJsonWarn(singleQuoteRes);
            const wUnquoted = getJsonWarn(unquotedKeyRes);

            const missingOpenBraceOk =
                missingOpenBraceRes.error === null &&
                wMissingOpen &&
                wMissingOpen.hintCode === PopCore.JSON_HINT_CODES.MISSING_OPEN_BRACE &&
                typeof wMissingOpen.hint === 'string' &&
                typeof wMissingOpen.line === 'number' &&
                typeof wMissingOpen.column === 'number' &&
                !wMissingOpen.detail.includes('▲') &&
                PopUI.formatJsonErrorSnippet(wMissingOpen).includes('▲');

            const missingClosingOk =
                missingClosingRes.error === null &&
                wMissingClose &&
                wMissingClose.hintCode === PopCore.JSON_HINT_CODES.MISSING_CLOSE_BRACE &&
                typeof wMissingClose.hint === 'string';

            const trailingCommaOk =
                trailingCommaRes.error === null &&
                wTrailing &&
                wTrailing.hintCode === PopCore.JSON_HINT_CODES.TRAILING_COMMA &&
                typeof wTrailing.hint === 'string';

            const singleQuoteOk =
                singleQuoteRes.error === null &&
                wSingle &&
                wSingle.hintCode === PopCore.JSON_HINT_CODES.SINGLE_QUOTE &&
                typeof wSingle.hint === 'string';

            const unquotedKeyOk =
                unquotedKeyRes.error === null &&
                wUnquoted &&
                wUnquoted.hintCode === PopCore.JSON_HINT_CODES.UNQUOTED_KEY &&
                typeof wUnquoted.hint === 'string';

            if (missingOpenBraceOk && missingClosingOk && trailingCommaOk && singleQuoteOk && unquotedKeyOk) {
                passed++;
            } else {
                console.log("[FAIL] json-error-smart-hints: Failed JSON warning diagnosis or smart hint generation");
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

        // 24) Non-JSON body ("hello", empty, plain text, form-urlencoded) passes all 1~5 stages when signed & digested properly
        {
            const nonJsonBodies = ["hello", "", "plain text body", "a=1&b=2&c=hello"];
            let allNonJsonOk = true;
            for (const plainBody of nonJsonBodies) {
                const plainHash = await sha256Hex(plainBody);
                const plainCanonical = ["POST", "api.example.com", "/v1/tx", "a=1", plainHash, nonce, ts].join('\n');
                const plainSig = toBase64Url(await signRaw(plainCanonical));
                const plainRes = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx?a=1",
                    bodyStr: plainBody,
                    nonce,
                    timestampStr: ts,
                    signature: plainSig,
                    pubkeyPem: dynPubkeyPem,
                    evalTime: Number(ts),
                    reqDigest: `sha256=${plainHash}`
                });
                if (
                    plainRes.error !== null ||
                    plainRes.firstFailedStage !== null ||
                    plainRes.stages.length !== 5 ||
                    plainRes.stages[0].status !== 'pass' ||
                    plainRes.stages[1].status !== 'pass' ||
                    plainRes.stages[2].status !== 'unknown' ||
                    plainRes.stages[3].status !== 'pass' ||
                    plainRes.stages[4].status !== 'pass' ||
                    plainRes.warnings.length !== 0 ||
                    !plainRes.hypothesisResult ||
                    plainRes.hypothesisResult.type !== 'skipped'
                ) {
                    allNonJsonOk = false;
                    break;
                }
            }
            if (allNonJsonOk) {
                passed++;
            } else {
                console.log("[FAIL] non-json-body-hello-pass: Non-JSON body ('hello' / empty / form-urlencoded) failed to pass all 5 stages");
                failed++;
            }
        }

        // 25) Broken JSON + digest mismatch shows JSON syntax hint and line/col arrow on result screen
        {
            const validSignedCanonical = ["POST", "api.example.com", "/v1/tx", "a=1", baseBodyHash, nonce, ts].join('\n');
            const validSignedSig = toBase64Url(await signRaw(validSignedCanonical));
            const brokenBody = '{\n  "amount": 1000,\n  "to": "alice"\n'; // missing closing brace '}'
            const mismatchRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: brokenBody,
                nonce,
                timestampStr: ts,
                signature: validSignedSig,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            });

            const jsonWarn = mismatchRes.warnings && mismatchRes.warnings.find(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);
            let renderedHasHint = false;
            if (typeof window === 'undefined') {
                const mockPanel = createMockElement('div');
                const prevDoc = global.document;
                global.document = createMockDocument({ elements: { 'result-panel': mockPanel } });
                try {
                    renderResult(mismatchRes);
                    const renderedText = mockPanel.textContent;
                    renderedHasHint = Boolean(jsonWarn && renderedText.includes(jsonWarn.hint) && renderedText.includes('▲'));
                } finally {
                    global.document = prevDoc;
                }
            } else {
                let tempPanel = document.getElementById('result-panel');
                let createdTemp = false;
                if (!tempPanel) {
                    tempPanel = document.createElement('div');
                    tempPanel.id = 'result-panel';
                    tempPanel.className = 'hidden';
                    document.body.appendChild(tempPanel);
                    createdTemp = true;
                }
                renderResult(mismatchRes);
                const renderedText = tempPanel.textContent;
                renderedHasHint = Boolean(jsonWarn && renderedText.includes(jsonWarn.hint) && renderedText.includes('▲'));
                if (createdTemp) tempPanel.remove();
            }

            if (
                mismatchRes.error === null &&
                mismatchRes.firstFailedStage === 5 &&
                mismatchRes.stages.length === 5 &&
                mismatchRes.stages[3].status === 'pass' &&
                mismatchRes.stages[4].status === 'fail' &&
                jsonWarn &&
                jsonWarn.hintCode === PopCore.JSON_HINT_CODES.MISSING_CLOSE_BRACE &&
                typeof jsonWarn.hint === 'string' &&
                typeof jsonWarn.line === 'number' &&
                typeof jsonWarn.column === 'number' &&
                !jsonWarn.detail.includes('▲') &&
                PopUI.formatJsonErrorSnippet(jsonWarn).includes('▲') &&
                renderedHasHint
            ) {
                passed++;
            } else {
                console.log("[FAIL] broken-json-digest-mismatch-hint: Broken JSON + Stage 5 digest mismatch did not expose JSON hint");
                failed++;
            }
        }

        // 26) Broken JSON with valid signature and matching digest passes all stages (JSON hint only as warning)
        {
            const brokenBodySigned = '{\n  "amount": 1000,\n}'; // trailing comma (broken JSON), but signed & digested as-is
            const brokenHash = await sha256Hex(brokenBodySigned);
            const brokenCanonical = ["POST", "api.example.com", "/v1/tx", "a=1", brokenHash, nonce, ts].join('\n');
            const brokenSig = toBase64Url(await signRaw(brokenCanonical));
            const brokenPassRes = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: brokenBodySigned,
                nonce,
                timestampStr: ts,
                signature: brokenSig,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${brokenHash}`
            });
            const jsonWarn = brokenPassRes.warnings && brokenPassRes.warnings.find(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);

            if (
                brokenPassRes.error === null &&
                brokenPassRes.firstFailedStage === null &&
                brokenPassRes.stages.length === 5 &&
                brokenPassRes.stages[3].status === 'pass' &&
                brokenPassRes.stages[4].status === 'pass' &&
                brokenPassRes.hypothesisResult &&
                brokenPassRes.hypothesisResult.type === 'skipped' &&
                jsonWarn &&
                jsonWarn.hintCode === PopCore.JSON_HINT_CODES.TRAILING_COMMA &&
                typeof jsonWarn.hint === 'string' &&
                typeof jsonWarn.line === 'number' &&
                typeof jsonWarn.column === 'number' &&
                !jsonWarn.detail.includes('▲') &&
                PopUI.formatJsonErrorSnippet(jsonWarn).includes('▲')
            ) {
                passed++;
            } else {
                console.log("[FAIL] broken-json-valid-sig-digest-pass-with-warning: Broken JSON with valid sig/digest did not pass with warning");
                failed++;
            }
        }

        // 27) Signature encoding unification: 128-char hex & ambiguous length/charset priorities (diagnose vs inspectSignature)
        {
            const validCase = fixtures.cases[0];
            const validSigBytes = PopCore.base64UrlDecode(validCase.signature);
            const hex128Sig = PopCore.bytesToHex(validSigBytes); // 128-char deterministic hex of 64B raw signature

            const hexInspect = inspectSignature(hex128Sig);
            const hexDiag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: hex128Sig,
                pubkeyPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });

            // Ambiguous case 1: 86-char [0-9a-f] without 0x and not starting with 30 -> base64url (64B)
            const ambig86B64Url = 'a'.repeat(86);
            const ambig86Inspect = inspectSignature(ambig86B64Url);
            const ambig86Diag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: ambig86B64Url,
                pubkeyPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });

            // Ambiguous case 2: 86-char [0-9a-f] with 0x prefix -> hex (43B)
            const ambig0xHex = '0x' + 'a'.repeat(86);
            const ambig0xInspect = inspectSignature(ambig0xHex);
            const ambig0xDiag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: ambig0xHex,
                pubkeyPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });

            // Ambiguous case 3: 86-char [0-9a-f] starting with 30 (DER tag) -> hex (43B)
            const ambig30Hex = '30' + 'a'.repeat(84);
            const ambig30Inspect = inspectSignature(ambig30Hex);
            const ambig30Diag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: ambig30Hex,
                pubkeyPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });

            if (
                hexInspect.encoding === 'hex' &&
                hexInspect.byteLength === 64 &&
                hexInspect.format === 'raw-rs(64B)' &&
                hexDiag.error !== null &&
                hexDiag.error.code === PopCore.ERROR_CODES.INVALID_SIGNATURE_ENCODING &&
                hexDiag.error.encoding === 'hex' &&
                hexDiag.error.byteLength === 64 &&
                ambig86Inspect.encoding === 'base64url' &&
                ambig86Inspect.byteLength === 64 &&
                ambig86Diag.error === null &&
                ambig86Diag.firstFailedStage === 4 &&
                ambig86Diag.stages[3].code === PopCore.STAGE_CODES.STAGE4_SIG_MISMATCH &&
                ambig0xInspect.encoding === 'hex' &&
                ambig0xInspect.byteLength === 43 &&
                ambig0xDiag.error !== null &&
                ambig0xDiag.error.code === PopCore.ERROR_CODES.INVALID_SIGNATURE_ENCODING &&
                ambig0xDiag.error.encoding === 'hex' &&
                ambig0xDiag.error.byteLength === 43 &&
                ambig30Inspect.encoding === 'hex' &&
                ambig30Inspect.byteLength === 43 &&
                ambig30Diag.error !== null &&
                ambig30Diag.error.code === PopCore.ERROR_CODES.INVALID_SIGNATURE_ENCODING &&
                ambig30Diag.error.encoding === 'hex' &&
                ambig30Diag.error.byteLength === 43
            ) {
                passed++;
            } else {
                console.log("[FAIL] sig-encoding-hex-and-priority-unification: Hex 128-char or ambiguous priority mismatch between diagnose and inspectSignature");
                failed++;
            }
        }

        // 28) Base64url '=' padding rejection & standard Base64 fallback (deterministic alphanumeric signature without + or /)
        {
            const fixedAlnumPubkeyPem =
                "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP7uvaVeraWeOIDV4K7/Z/+RjtmlF\n" +
                "FmdiKrNshwZyvSpbNX3ggco8hxZb4E/oOqw4GvosaOqlSigVnKnVmozQvw==\n" +
                "-----END PUBLIC KEY-----";
            // Valid 64B signature for POST https://api.example.com/v1/tx?b=2&a=1 (nonce=n123456, ts=1791356800) whose standard Base64 has no '+' or '/'
            const paddedAlnumSig = "2Ay7MngNhRy9ajqfz4IpFr5MhUu2gwj7fk17r6ZV68obefYefbmM7phAt4ZZxeIW8Ho0RzszLFzcWsPzr2ypqQ==";
            const unpaddedAlnumSig = paddedAlnumSig.slice(0, -2);
            const validCase = fixtures.cases[0];

            let b64UrlThrewOnPadding = false;
            try {
                PopCore.base64UrlDecode(paddedAlnumSig);
            } catch (e) {
                b64UrlThrewOnPadding = true;
            }

            const paddedInspect = inspectSignature(paddedAlnumSig);
            const paddedDiag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: baseBody,
                nonce: validCase.nonce,
                timestampStr: ts,
                signature: paddedAlnumSig,
                pubkeyPem: fixedAlnumPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            });

            const unpaddedInspect = inspectSignature(unpaddedAlnumSig);
            const unpaddedDiag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: baseBody,
                nonce: validCase.nonce,
                timestampStr: ts,
                signature: unpaddedAlnumSig,
                pubkeyPem: fixedAlnumPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${baseBodyHash}`
            });

            const matchedHypId = paddedDiag.hypothesisResult &&
                paddedDiag.hypothesisResult.type === 'found' &&
                paddedDiag.hypothesisResult.sets[0] &&
                paddedDiag.hypothesisResult.sets[0].item
                ? paddedDiag.hypothesisResult.sets[0].item.idStr
                : null;

            if (
                b64UrlThrewOnPadding &&
                paddedInspect.encoding === 'base64(standard)' &&
                paddedInspect.byteLength === 64 &&
                paddedInspect.encodingReason.includes('=') &&
                paddedDiag.error === null &&
                paddedDiag.firstFailedStage === 4 &&
                matchedHypId === 'sig-base64url' &&
                unpaddedInspect.ok === true &&
                unpaddedInspect.encoding === 'base64url' &&
                unpaddedDiag.error === null &&
                unpaddedDiag.firstFailedStage === null
            ) {
                passed++;
            } else {
                console.log("[FAIL] sig-encoding-base64url-padding-rejected: '=' padded signature without +,/ did not reject in base64UrlDecode or fall back to sig-base64url");
                failed++;
            }
        }

        // 29) PRIVATE KEY PEM input immediately rejected by both importPublicKey/diagnose and inspectPublicKey
        {
            const pkcs8PrivPem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";
            const ecPrivPem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI\n-----END EC PRIVATE KEY-----";
            const validCase = fixtures.cases[0];

            let importPkcs8Err = null;
            try {
                await PopCore.importPublicKey(pkcs8PrivPem);
            } catch (e) {
                importPkcs8Err = e;
            }

            let importEcErr = null;
            try {
                await PopCore.importPublicKey(ecPrivPem);
            } catch (e) {
                importEcErr = e;
            }

            const diagPriv = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: validCase.signature,
                pubkeyPem: pkcs8PrivPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });
            const inspectPriv = await inspectPublicKey(pkcs8PrivPem);
            const inspectEcPriv = await inspectPublicKey(ecPrivPem);

            if (
                importPkcs8Err && importPkcs8Err.code === 'PRIVATE_KEY_REJECTED' &&
                importEcErr && importEcErr.code === 'PRIVATE_KEY_REJECTED' &&
                diagPriv.error && diagPriv.error.code === PopCore.ERROR_CODES.INVALID_PUBKEY &&
                diagPriv.error.causeCode === 'PRIVATE_KEY_REJECTED' &&
                inspectPriv.ok === false && inspectPriv.error && inspectPriv.error.code === 'PRIVATE_KEY_REJECTED' &&
                inspectEcPriv.ok === false && inspectEcPriv.error && inspectEcPriv.error.code === 'PRIVATE_KEY_REJECTED'
            ) {
                passed++;
            } else {
                console.log("[FAIL] pubkey-private-key-rejected-both: PRIVATE KEY PEM was not rejected with PRIVATE_KEY_REJECTED in both modules");
                failed++;
            }
        }

        // 30) Reversed BEGIN/END PEM headers rejected by both importPublicKey/diagnose and inspectPublicKey
        {
            const cleanB64 = pubkeyPem
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .trim();
            const reversedPem = `-----END PUBLIC KEY-----\n${cleanB64}\n-----BEGIN PUBLIC KEY-----`;
            const validCase = fixtures.cases[0];

            let importRevErr = null;
            try {
                await PopCore.importPublicKey(reversedPem);
            } catch (e) {
                importRevErr = e;
            }

            const diagRev = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: validCase.signature,
                pubkeyPem: reversedPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });
            const inspectRev = await inspectPublicKey(reversedPem);

            if (
                importRevErr && importRevErr.code === 'INVALID_PEM_FORMAT' &&
                diagRev.error && diagRev.error.code === PopCore.ERROR_CODES.INVALID_PUBKEY &&
                diagRev.error.causeCode === 'INVALID_PEM_FORMAT' &&
                inspectRev.ok === false && inspectRev.error && inspectRev.error.code === 'INVALID_PEM_FORMAT'
            ) {
                passed++;
            } else {
                console.log("[FAIL] pubkey-reversed-headers-rejected-both: Reversed BEGIN/END PEM headers were not rejected by both modules");
                failed++;
            }
        }

        // 31) DER non-minimal integer encoding (e.g. 02 02 00 05) rejected by both derToRaw/diagnose and inspectSignature
        {
            // Case 1: 02 02 00 05 and 02 02 00 07 inside DER SEQUENCE (30 08 02 02 00 05 02 02 00 07)
            const smallNonMinimalDer = new Uint8Array([0x30, 0x08, 0x02, 0x02, 0x00, 0x05, 0x02, 0x02, 0x00, 0x07]);
            const smallNonMinimalB64Url = PopCore.base64UrlEncodeBytes(smallNonMinimalDer.buffer);
            const smallRaw = PopCore.derToRaw(smallNonMinimalDer.buffer);
            const smallInspect = inspectSignature(smallNonMinimalB64Url);

            // Case 2: 72-byte DER signature for fixtures.cases[0] where s has 02 21 00 1e... (unnecessary leading 0x00 before 0x1e < 0x80)
            const nonMinimal72B64Url = "MEYCIQDp8itqSFTHlK53le0AuRs2mihUOMX8c9KZBXZXpRsa_AIhAB548K8bBzfpaj9moQAACC2dB3nUhy0iI23oNDwXczPd";
            const nonMinimal72Bytes = PopCore.base64UrlDecode(nonMinimal72B64Url);
            const nonMinimal72Raw = PopCore.derToRaw(nonMinimal72Bytes);
            const nonMinimal72Inspect = inspectSignature(nonMinimal72B64Url);
            const validCase = fixtures.cases[0];
            const nonMinimal72Diag = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: nonMinimal72B64Url,
                pubkeyPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });

            if (
                smallRaw === null &&
                smallInspect.ok === false &&
                smallInspect.error && smallInspect.error.code === 'INVALID_DER' &&
                nonMinimal72Raw === null &&
                nonMinimal72Inspect.ok === false &&
                nonMinimal72Inspect.error && nonMinimal72Inspect.error.code === 'INVALID_DER' &&
                nonMinimal72Diag.error === null &&
                nonMinimal72Diag.firstFailedStage === 4 &&
                nonMinimal72Diag.hypothesisResult &&
                nonMinimal72Diag.hypothesisResult.type === 'no-match'
            ) {
                passed++;
            } else {
                console.log("[FAIL] der-non-minimal-integer-rejected-both: Non-minimal DER integer encoding was not rejected by both derToRaw/diagnose and inspectSignature");
                failed++;
            }
        }

        // 32) Non-Base64 chars (Korean/symbols) in PEM rejected by both modules, and generateKeyPairAndSign uses extractable: false
        {
            const cleanB64 = pubkeyPem
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .trim();
            const corruptedWithKoreanPem = `-----BEGIN PUBLIC KEY-----\n가나다!@#${cleanB64}\n-----END PUBLIC KEY-----`;
            const validCase = fixtures.cases[0];

            let importKorErr = null;
            try {
                await PopCore.importPublicKey(corruptedWithKoreanPem);
            } catch (e) {
                importKorErr = e;
            }

            const diagKor = await PopCore.diagnose({
                method: validCase.method,
                urlStr: `https://${validCase.host}${validCase.path}?${validCase.query}`,
                bodyStr: validCase.body,
                nonce: validCase.nonce,
                timestampStr: String(validCase.timestamp),
                signature: validCase.signature,
                pubkeyPem: corruptedWithKoreanPem,
                evalTime: validCase.evalTime,
                reqDigest: validCase.digest
            });
            const inspectKor = await inspectPublicKey(corruptedWithKoreanPem);

            let extractableFalseChecked = true;
            const origGenKey = _crypto.subtle.generateKey.bind(_crypto.subtle);
            let capturedExtractable = null;
            _crypto.subtle.generateKey = async (alg, extractable, usages) => {
                capturedExtractable = extractable;
                return origGenKey(alg, extractable, usages);
            };
            try {
                await PopCore.generateTestSignature({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: "{}",
                    nonce: "n1",
                    timestampStr: ts
                });
                extractableFalseChecked = capturedExtractable === false;
            } finally {
                _crypto.subtle.generateKey = origGenKey;
            }

            if (
                importKorErr && importKorErr.code === 'INVALID_BASE64' &&
                diagKor.error && diagKor.error.code === PopCore.ERROR_CODES.INVALID_PUBKEY &&
                diagKor.error.causeCode === 'INVALID_BASE64' &&
                inspectKor.ok === false && inspectKor.error && inspectKor.error.code === 'INVALID_BASE64' &&
                extractableFalseChecked
            ) {
                passed++;
            } else {
                console.log("[FAIL] pubkey-non-base64-chars-and-extractable: Non-Base64 chars in PEM were not rejected by both modules or generateKeyPairAndSign has extractable: true");
                failed++;
            }
        }

        // 33) BFS permutation & state deduplication spy test (0 duplicate verify calls, indistinguishable & sig-base64url+sig-der preserved)
        {
            const origVerify = _crypto.subtle.verify.bind(_crypto.subtle);
            let verifyCallCount = 0;
            let duplicateVerifyCount = 0;
            const seenVerifyStates = new Set();

            _crypto.subtle.verify = async (alg, key, sig, data) => {
                verifyCallCount++;
                const sigHex = PopCore.bytesToHex(sig);
                const dataStr = new TextDecoder().decode(data);
                const stateKey = `${sigHex}|${dataStr}`;
                if (seenVerifyStates.has(stateKey)) {
                    duplicateVerifyCount++;
                } else {
                    seenVerifyStates.add(stateKey);
                }
                return origVerify(alg, key, sig, data);
            };

            try {
                // 1) outside-catalog (1 query param -> 5 active Stage 4 hypotheses: 1 initial + C(5,1)+C(5,2)+C(5,3) = 26 verify calls)
                const outCase = fixtures.cases.find(x => x.name === 'outside-catalog');
                verifyCallCount = 0;
                duplicateVerifyCount = 0;
                seenVerifyStates.clear();
                await PopCore.diagnose({
                    method: outCase.method,
                    urlStr: `https://${outCase.host}${outCase.path}?${outCase.query}`,
                    bodyStr: outCase.body,
                    nonce: outCase.nonce,
                    timestampStr: String(outCase.timestamp),
                    signature: outCase.signature,
                    pubkeyPem,
                    evalTime: outCase.evalTime,
                    reqDigest: outCase.digest
                });
                const outVerifyCount = verifyCallCount;
                const outDupCount = duplicateVerifyCount;

                // 2) Worst-case 3-query param input (?c=3&a=1&b=2 -> 7 active Stage 4 hypotheses: 1 initial + C(7,1)+C(7,2)+C(7,3) = 64 verify calls)
                verifyCallCount = 0;
                duplicateVerifyCount = 0;
                seenVerifyStates.clear();
                await PopCore.diagnose({
                    method: outCase.method,
                    urlStr: `https://${outCase.host}${outCase.path}?c=3&a=1&b=2`,
                    bodyStr: outCase.body,
                    nonce: outCase.nonce,
                    timestampStr: String(outCase.timestamp),
                    signature: outCase.signature,
                    pubkeyPem,
                    evalTime: outCase.evalTime,
                    reqDigest: outCase.digest
                });
                const worstVerifyCount = verifyCallCount;
                const worstDupCount = duplicateVerifyCount;

                // 3) Indistinguishable case (query: b=2&a=1) preserves both query-sorted & query-reverse with 0 duplicate verify calls
                const indCase = fixtures.cases.find(x => x.name === 'indistinguishable');
                verifyCallCount = 0;
                duplicateVerifyCount = 0;
                seenVerifyStates.clear();
                const indRes = await PopCore.diagnose({
                    method: indCase.method,
                    urlStr: `https://${indCase.host}${indCase.path}?${indCase.query}`,
                    bodyStr: indCase.body,
                    nonce: indCase.nonce,
                    timestampStr: String(indCase.timestamp),
                    signature: indCase.signature,
                    pubkeyPem,
                    evalTime: indCase.evalTime,
                    reqDigest: indCase.digest
                });
                const indDupCount = duplicateVerifyCount;
                const indSet = indRes.hypothesisResult && indRes.hypothesisResult.sets && indRes.hypothesisResult.sets[0];
                const indIds = indSet && indSet.type === 'indistinguishable'
                    ? indSet.items.map(it => it.idStr).sort().join('|')
                    : '';

                // 4) Order-dependent pair: sig-base64url + sig-der (DER signature encoded in standard Base64)
                const derCase = fixtures.cases.find(x => x.name === 'sig-der');
                const derBytes = PopCore.base64UrlDecode(derCase.signature);
                const derStdB64 = toStandardBase64(derBytes); // ends with '=' so detected as base64(standard)
                const derStdRes = await PopCore.diagnose({
                    method: derCase.method,
                    urlStr: `https://${derCase.host}${derCase.path}?${derCase.query}`,
                    bodyStr: derCase.body,
                    nonce: derCase.nonce,
                    timestampStr: String(derCase.timestamp),
                    signature: derStdB64,
                    pubkeyPem,
                    evalTime: derCase.evalTime,
                    reqDigest: derCase.digest
                });
                const derStdIdStr = derStdRes.hypothesisResult &&
                    derStdRes.hypothesisResult.type === 'found' &&
                    derStdRes.hypothesisResult.sets[0] &&
                    derStdRes.hypothesisResult.sets[0].item
                    ? derStdRes.hypothesisResult.sets[0].item.idStr
                    : null;

                if (
                    outDupCount === 0 &&
                    outVerifyCount === 26 &&
                    worstDupCount === 0 &&
                    worstVerifyCount === 64 &&
                    indDupCount === 0 &&
                    indIds === 'query-reverse|query-sorted' &&
                    derStdIdStr === 'sig-base64url,sig-der'
                ) {
                    passed++;
                } else {
                    console.log(`[FAIL] bfs-no-permutation-or-inverse-duplicates: outVerify=${outVerifyCount}(dup=${outDupCount}), worstVerify=${worstVerifyCount}(dup=${worstDupCount}), indIds=${indIds}(dup=${indDupCount}), derStdIdStr=${derStdIdStr}`);
                    failed++;
                }
            } finally {
                _crypto.subtle.verify = origVerify;
            }
        }

        // 34) Inverse pair exclusion & reachable maxSearchNodes (reduced: true) test
        {
            const mCase = fixtures.cases.find(x => x.name === 'method-lowercase');
            const mRes = await PopCore.diagnose({
                method: mCase.method,
                urlStr: `https://${mCase.host}${mCase.path}?${mCase.query}`,
                bodyStr: mCase.body,
                nonce: mCase.nonce,
                timestampStr: String(mCase.timestamp),
                signature: mCase.signature,
                pubkeyPem,
                evalTime: mCase.evalTime,
                reqDigest: mCase.digest
            });
            const hasInverseNoise = mRes.hypothesisResult &&
                mRes.hypothesisResult.sets &&
                mRes.hypothesisResult.sets.some(s => {
                    const items = s.type === 'indistinguishable' ? s.items : [s.item];
                    return items.some(it => it.idStr.includes('path-trailing-slash-add') || it.idStr.includes('path-trailing-slash-remove'));
                });

            // Force reduced: true using a small maxSearchNodes cap (5 verify calls)
            const outCase = fixtures.cases.find(x => x.name === 'outside-catalog');
            const origVerify = _crypto.subtle.verify.bind(_crypto.subtle);
            let cappedVerifyCalls = 0;
            _crypto.subtle.verify = async (...args) => {
                cappedVerifyCalls++;
                return origVerify(...args);
            };
            let cappedRes;
            try {
                const cappedProfile = Object.assign({}, PopCore.PaperProfile, { maxSearchNodes: 5 });
                cappedRes = await PopCore.diagnose({
                    method: outCase.method,
                    urlStr: `https://${outCase.host}${outCase.path}?${outCase.query}`,
                    bodyStr: outCase.body,
                    nonce: outCase.nonce,
                    timestampStr: String(outCase.timestamp),
                    signature: outCase.signature,
                    pubkeyPem,
                    evalTime: outCase.evalTime,
                    reqDigest: outCase.digest
                }, cappedProfile);
            } finally {
                _crypto.subtle.verify = origVerify;
            }

            let renderedReducedMsg = false;
            if (typeof window === 'undefined') {
                const mockPanel = createMockElement('div');
                const prevDoc = global.document;
                global.document = createMockDocument({ elements: { 'result-panel': mockPanel } });
                try {
                    renderResult(cappedRes);
                    renderedReducedMsg = mockPanel.textContent.includes('탐색 범위를 줄였음 (최대 탐색 상한 도달)');
                } finally {
                    global.document = prevDoc;
                }
            } else {
                const hBox = PopUI.renderHypothesisSection(cappedRes);
                renderedReducedMsg = Boolean(hBox && hBox.textContent.includes('탐색 범위를 줄였음 (최대 탐색 상한 도달)'));
            }

            if (
                !hasInverseNoise &&
                mRes.hypothesisResult.sets.length === 1 &&
                mRes.hypothesisResult.sets[0].item.idStr === 'method-lowercase' &&
                cappedRes.hypothesisResult &&
                cappedRes.hypothesisResult.reduced === true &&
                cappedVerifyCalls === 6 && // 1 in Stage 4 + 5 in searchStage4Hypotheses
                renderedReducedMsg
            ) {
                passed++;
            } else {
                console.log(`[FAIL] bfs-inverse-and-reduced-cap: hasInverseNoise=${hasInverseNoise}, reduced=${cappedRes.hypothesisResult && cappedRes.hypothesisResult.reduced}, cappedVerifyCalls=${cappedVerifyCalls}, renderedReducedMsg=${renderedReducedMsg}`);
                failed++;
            }
        }

        // 35) Stage 5 combo search (depth 2~3, e.g. body-bom-added + digest-hex) & simultaneous Stage 4 + Stage 5 failure diagnosis
        {
            // 1) Stage 5 depth-2 combo: body-bom-added + digest-hex (Stage 4 passes, Stage 5 fails)
            const bomUpperDigest = bomBodyHash.toUpperCase();
            const s5Combo2Canonical = ["POST", "api.example.com", "/v1/tx", "a=1", bomUpperDigest, nonce, ts].join('\n');
            const s5Combo2Sig = toBase64Url(await signRaw(s5Combo2Canonical));
            const s5Combo2Res = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: s5Combo2Sig,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${bomUpperDigest}`
            });
            const s5Combo2Id = s5Combo2Res.hypothesisResult &&
                s5Combo2Res.hypothesisResult.type === 'found' &&
                s5Combo2Res.hypothesisResult.sets[0] &&
                s5Combo2Res.hypothesisResult.sets[0].item
                ? s5Combo2Res.hypothesisResult.sets[0].item.idStr
                : null;

            // 2) Stage 5 depth-3 combo: newline-crlf + body-bom-added + digest-hex (Stage 4 passes, Stage 5 fails)
            const crlfBomUpperDigest = bomCrlfBodyHash.toUpperCase();
            const s5Combo3Canonical = ["POST", "api.example.com", "/v1/tx", "a=1", crlfBomUpperDigest, nonce, ts].join('\n');
            const s5Combo3Sig = toBase64Url(await signRaw(s5Combo3Canonical));
            const s5Combo3Res = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: s5Combo3Sig,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${crlfBomUpperDigest}`
            });
            const s5Combo3Id = s5Combo3Res.hypothesisResult &&
                s5Combo3Res.hypothesisResult.type === 'found' &&
                s5Combo3Res.hypothesisResult.sets[0] &&
                s5Combo3Res.hypothesisResult.sets[0].item
                ? s5Combo3Res.hypothesisResult.sets[0].item.idStr
                : null;

            // 3) Simultaneous Stage 4 (method-lowercase) + Stage 5 (body-bom-added + digest-hex) failure
            const simS4S5Canonical = ["post", "api.example.com", "/v1/tx", "a=1", bomUpperDigest, nonce, ts].join('\n');
            const simS4S5Sig = toBase64Url(await signRaw(simS4S5Canonical));
            const simS4S5Res = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: simS4S5Sig,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${bomUpperDigest}`
            });
            const s4SubId = simS4S5Res.stage4HypothesisResult &&
                simS4S5Res.stage4HypothesisResult.type === 'found' &&
                simS4S5Res.stage4HypothesisResult.sets[0] &&
                simS4S5Res.stage4HypothesisResult.sets[0].item
                ? simS4S5Res.stage4HypothesisResult.sets[0].item.idStr
                : null;
            const s5SubId = simS4S5Res.stage5HypothesisResult &&
                simS4S5Res.stage5HypothesisResult.type === 'found' &&
                simS4S5Res.stage5HypothesisResult.sets[0] &&
                simS4S5Res.stage5HypothesisResult.sets[0].item
                ? simS4S5Res.stage5HypothesisResult.sets[0].item.idStr
                : null;
            const combinedId = simS4S5Res.hypothesisResult &&
                simS4S5Res.hypothesisResult.type === 'found' &&
                simS4S5Res.hypothesisResult.sets[0] &&
                simS4S5Res.hypothesisResult.sets[0].item
                ? simS4S5Res.hypothesisResult.sets[0].item.idStr
                : null;

            if (
                s5Combo2Res.firstFailedStage === 5 &&
                s5Combo2Id === 'body-bom-added,digest-hex' &&
                s5Combo3Res.firstFailedStage === 5 &&
                s5Combo3Id === 'body-bom-added,digest-hex,newline-crlf' &&
                simS4S5Res.firstFailedStage === 4 &&
                simS4S5Res.stages[3].status === 'fail' &&
                simS4S5Res.stages[4].status === 'fail' &&
                s4SubId === 'method-lowercase' &&
                s5SubId === 'body-bom-added,digest-hex' &&
                combinedId === 'body-bom-added,digest-hex,method-lowercase'
            ) {
                passed++;
            } else {
                console.log(`[FAIL] stage5-combo-and-simultaneous-s4-s5: s5Combo2Id=${s5Combo2Id}, s5Combo3Id=${s5Combo3Id}, s4SubId=${s4SubId}, s5SubId=${s5SubId}, combinedId=${combinedId}`);
                failed++;
            }
        }

        // 36) Host port (:443 preservation & toggle, custom :8443 untouched, IPv6 [::1] and [::1]:8443 intact)
        {
            const hostHyp = PopCore.HYPOTHESES.find(h => h.id === 'host-rewritten');
            const bodyHash = baseBodyHash;
            const reqDigest = `sha256=${bodyHash}`;

            // (1) Request to https://api.example.com:443/p, client signed without port (api.example.com)
            const canonicalWithout443 = ["POST", "api.example.com", "/p", "", bodyHash, nonce, ts].join('\n');
            const sigWithout443 = toBase64Url(await signRaw(canonicalWithout443));
            const resReqWith443 = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com:443/p",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: sigWithout443,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest
            });
            const reqWith443Id = resReqWith443.hypothesisResult &&
                resReqWith443.hypothesisResult.type === 'found' &&
                resReqWith443.hypothesisResult.sets[0] &&
                resReqWith443.hypothesisResult.sets[0].item
                ? resReqWith443.hypothesisResult.sets[0].item.idStr
                : null;

            // (2) Request to https://api.example.com/p, client signed with :443 (api.example.com:443)
            const canonicalWith443 = ["POST", "api.example.com:443", "/p", "", bodyHash, nonce, ts].join('\n');
            const sigWith443 = toBase64Url(await signRaw(canonicalWith443));
            const resReqWithout443 = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/p",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: sigWith443,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest
            });
            const reqWithout443Id = resReqWithout443.hypothesisResult &&
                resReqWithout443.hypothesisResult.type === 'found' &&
                resReqWithout443.hypothesisResult.sets[0] &&
                resReqWithout443.hypothesisResult.sets[0].item
                ? resReqWithout443.hypothesisResult.sets[0].item.idStr
                : null;

            // (3) https://api.example.com:8443/p (custom port never modified by host-rewritten)
            const customPortApplied = await hostHyp.apply({ host: 'api.example.com:8443' });
            const canonical8443 = ["POST", "api.example.com:8443", "/p", "", bodyHash, nonce, ts].join('\n');
            const sig8443 = toBase64Url(await signRaw(canonical8443));
            const res8443Pass = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com:8443/p",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: sig8443,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest
            });
            // If client signed without :8443, host-rewritten must NOT strip :8443 to match it
            const res8443NoMatch = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com:8443/p",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: sigWithout443,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest
            });

            // (4) https://[::1]/p and https://[::1]:8443/p (IPv6 host never broken)
            const ipv6Applied = await hostHyp.apply({ host: '[::1]' });
            const ipv6PortApplied = await hostHyp.apply({ host: '[::1]:8443' });

            const canonicalIpv6 = ["POST", "[::1]", "/p", "", bodyHash, nonce, ts].join('\n');
            const sigIpv6 = toBase64Url(await signRaw(canonicalIpv6));
            const resIpv6Pass = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://[::1]/p",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: sigIpv6,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest
            });

            const canonicalIpv6LowerMethod = ["post", "[::1]:8443", "/p", "", bodyHash, nonce, ts].join('\n');
            const sigIpv6LowerMethod = toBase64Url(await signRaw(canonicalIpv6LowerMethod));
            const resIpv6PortDiag = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://[::1]:8443/p",
                bodyStr: baseBody,
                nonce,
                timestampStr: ts,
                signature: sigIpv6LowerMethod,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest
            });
            const ipv6PortDiagId = resIpv6PortDiag.hypothesisResult &&
                resIpv6PortDiag.hypothesisResult.type === 'found' &&
                resIpv6PortDiag.hypothesisResult.sets[0] &&
                resIpv6PortDiag.hypothesisResult.sets[0].item
                ? resIpv6PortDiag.hypothesisResult.sets[0].item.idStr
                : null;

            if (
                resReqWith443.firstFailedStage === 4 &&
                resReqWith443.expectedCanonical.split('\n')[1] === 'api.example.com:443' &&
                reqWith443Id === 'host-rewritten' &&
                resReqWithout443.firstFailedStage === 4 &&
                resReqWithout443.expectedCanonical.split('\n')[1] === 'api.example.com' &&
                reqWithout443Id === 'host-rewritten' &&
                customPortApplied.host === 'api.example.com:8443' &&
                res8443Pass.firstFailedStage === null &&
                res8443Pass.expectedCanonical.split('\n')[1] === 'api.example.com:8443' &&
                res8443NoMatch.firstFailedStage === 4 &&
                res8443NoMatch.hypothesisResult.type === 'no-match' &&
                ipv6Applied.host === '[::1]' &&
                ipv6PortApplied.host === '[::1]:8443' &&
                resIpv6Pass.firstFailedStage === null &&
                resIpv6Pass.expectedCanonical.split('\n')[1] === '[::1]' &&
                resIpv6PortDiag.firstFailedStage === 4 &&
                resIpv6PortDiag.expectedCanonical.split('\n')[1] === '[::1]:8443' &&
                ipv6PortDiagId === 'method-lowercase'
            ) {
                passed++;
            } else {
                console.log(`[FAIL] host-rewritten-port-and-ipv6: reqWith443Id=${reqWith443Id} (stage=${resReqWith443.firstFailedStage}, host=${resReqWith443.expectedCanonical && resReqWith443.expectedCanonical.split('\n')[1]}), reqWithout443Id=${reqWithout443Id}, customPortHost=${customPortApplied.host}, res8443NoMatch=${res8443NoMatch.hypothesisResult && res8443NoMatch.hypothesisResult.type}, ipv6Host=${ipv6Applied.host}, ipv6PortHost=${ipv6PortApplied.host}, ipv6PortDiagId=${ipv6PortDiagId}`);
                failed++;
            }
        }

        // 37) Stage 5 newline-crlf bidirectional toggle: (a) LF hash + CRLF body, (b) CRLF hash + LF body, (c) both match (LF+LF and CRLF+CRLF)
        {
            const lfBody = '{\n  "amount": 1000,\n  "to": "alice"\n}';
            const crlfBody = '{\r\n  "amount": 1000,\r\n  "to": "alice"\r\n}';
            const lfHash = baseBodyHash;
            const crlfHash = crlfBodyHash;

            const sigWithLfHash = toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", lfHash, nonce, ts].join('\n')));
            const sigWithCrlfHash = toBase64Url(await signRaw(["POST", "api.example.com", "/v1/tx", "a=1", crlfHash, nonce, ts].join('\n')));

            // (a) LF hash + CRLF body -> Stage 5 fails and matches newline-crlf
            const resLfHashCrlfBody = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: crlfBody,
                nonce,
                timestampStr: ts,
                signature: sigWithLfHash,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${lfHash}`
            });
            const idLfHashCrlfBody = resLfHashCrlfBody.hypothesisResult &&
                resLfHashCrlfBody.hypothesisResult.type === 'found' &&
                resLfHashCrlfBody.hypothesisResult.sets[0] &&
                resLfHashCrlfBody.hypothesisResult.sets[0].item
                ? resLfHashCrlfBody.hypothesisResult.sets[0].item.idStr
                : null;

            // (b) CRLF hash + LF body -> Stage 5 fails and matches newline-crlf
            const resCrlfHashLfBody = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: lfBody,
                nonce,
                timestampStr: ts,
                signature: sigWithCrlfHash,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${crlfHash}`
            });
            const idCrlfHashLfBody = resCrlfHashLfBody.hypothesisResult &&
                resCrlfHashLfBody.hypothesisResult.type === 'found' &&
                resCrlfHashLfBody.hypothesisResult.sets[0] &&
                resCrlfHashLfBody.hypothesisResult.sets[0].item
                ? resCrlfHashLfBody.hypothesisResult.sets[0].item.idStr
                : null;

            // (c-1) Both match: LF hash + LF body -> passes all stages (skipped)
            const resBothLf = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: lfBody,
                nonce,
                timestampStr: ts,
                signature: sigWithLfHash,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${lfHash}`
            });

            // (c-2) Both match: CRLF hash + CRLF body -> passes all stages (skipped)
            const resBothCrlf = await PopCore.diagnose({
                method: "POST",
                urlStr: "https://api.example.com/v1/tx?a=1",
                bodyStr: crlfBody,
                nonce,
                timestampStr: ts,
                signature: sigWithCrlfHash,
                pubkeyPem: dynPubkeyPem,
                evalTime: Number(ts),
                reqDigest: `sha256=${crlfHash}`
            });

            // (d) Browser <textarea> LF normalization simulation + CRLF preservation via setRawTextareaValue/readRequestBody & UI notice
            const mockTextarea = createMockElement('TEXTAREA', { isTextarea: true });
            PopUI.setRawTextareaValue(mockTextarea, crlfBody);
            const normalizedDomVal = mockTextarea.value;
            const preservedCrlfRead = PopUI.readRequestBody(mockTextarea);
            mockTextarea.value = '{"edited": true}\n';
            const editedRead = PopUI.readRequestBody(mockTextarea);

            let hasLfNotice = false;
            const parsedAnsiCrlf = parseCurl(
                "curl 'https://api.example.com/v1/tx?a=1' " +
                "-H 'X-FIDO2-Nonce: n1' -H 'X-FIDO2-Timestamp: 1700000000' " +
                "-H 'X-FIDO2-Signature: s1' -H 'X-Body-Digest: sha256=ab' " +
                "--data-raw $'{\\r\\n  \"amount\": 1000\\r\\n}'"
            );
            if (typeof window === 'undefined') {
                const prevDoc = global.document;
                global.document = createMockDocument();
                try {
                    const bannerNode = createMockElement('DIV');
                    PopUI.renderImportStatus(bannerNode, parsedAnsiCrlf);
                    hasLfNotice =
                        parsedAnsiCrlf.inputs.bodyStr === '{\r\n  "amount": 1000\r\n}' &&
                        bannerNode.textContent.includes('브라우저 입력창(textarea)은 HTML 표준에 따라');
                } finally {
                    global.document = prevDoc;
                }
            } else {
                const bannerNode = document.createElement('div');
                PopUI.renderImportStatus(bannerNode, parsedAnsiCrlf);
                hasLfNotice =
                    parsedAnsiCrlf.inputs.bodyStr === '{\r\n  "amount": 1000\r\n}' &&
                    bannerNode.textContent.includes('브라우저 입력창(textarea)은 HTML 표준에 따라');
            }

            if (
                resLfHashCrlfBody.firstFailedStage === 5 &&
                idLfHashCrlfBody === 'newline-crlf' &&
                resCrlfHashLfBody.firstFailedStage === 5 &&
                idCrlfHashLfBody === 'newline-crlf' &&
                resBothLf.firstFailedStage === null &&
                resBothLf.hypothesisResult.type === 'skipped' &&
                resBothCrlf.firstFailedStage === null &&
                resBothCrlf.hypothesisResult.type === 'skipped' &&
                normalizedDomVal === lfBody &&
                preservedCrlfRead === crlfBody &&
                editedRead === '{"edited": true}\n' &&
                hasLfNotice
            ) {
                passed++;
            } else {
                console.log(`[FAIL] newline-crlf-bidirectional: (a) stage=${resLfHashCrlfBody.firstFailedStage} id=${idLfHashCrlfBody}, (b) stage=${resCrlfHashLfBody.firstFailedStage} id=${idCrlfHashLfBody}, (c-1) stage=${resBothLf.firstFailedStage}, (c-2) stage=${resBothCrlf.firstFailedStage}, preserved=${preservedCrlfRead === crlfBody}, hasLfNotice=${hasLfNotice}`);
                failed++;
            }
        }

        // 38) Module boundaries (core -> ui 0 refs), jsonError data/UI split, PopCore explicit public API, slots explicit require, and fixtures/samples separation
        {
            // (a) PopCore explicit public API: no internal helpers (_atob, _btoa, _crypto, binaryStringToBytes) or UI functions (getJsonErrorSnippet, isFullWidthChar)
            const noInternalLeak =
                PopCore._atob === undefined &&
                PopCore._btoa === undefined &&
                PopCore._crypto === undefined &&
                PopCore.binaryStringToBytes === undefined &&
                PopCore.getJsonErrorSnippet === undefined &&
                PopCore.isFullWidthChar === undefined;

            // (b) Core jsonError vs UI jsonError responsibility split
            const coreHasJsonLoc =
                typeof PopCore.extractJsonErrorLocation === 'function' &&
                typeof PopCore.detectJsonErrorHint === 'function' &&
                typeof PopCore.JSON_HINT_CODES === 'object';
            const uiHasJsonFormat =
                typeof PopUI.formatJsonErrorSnippet === 'function' &&
                typeof PopUI.getJsonErrorSnippet === 'function' &&
                typeof PopUI.isFullWidthChar === 'function';

            let jsonSplitOk = false;
            if (coreHasJsonLoc && uiHasJsonFormat) {
                const brokenKorJson = '{\n  "이름": "홍길동",\n  "amount": 1000,\n}';
                let errMsg = 'Unexpected token } in JSON at position 35';
                try {
                    JSON.parse(brokenKorJson);
                } catch (e) {
                    errMsg = e.message;
                }
                const loc = PopCore.extractJsonErrorLocation(brokenKorJson, errMsg);
                const formatted = PopUI.formatJsonErrorSnippet(loc);
                const validated = PopCore.validateJsonBody(brokenKorJson);
                jsonSplitOk =
                    loc &&
                    typeof loc.line === 'number' &&
                    typeof loc.column === 'number' &&
                    typeof loc.problemLine === 'string' &&
                    !String(loc.problemLine).includes('▲') &&
                    typeof formatted === 'string' &&
                    formatted.includes('▲') &&
                    validated !== null &&
                    typeof validated.line === 'number' &&
                    typeof validated.column === 'number' &&
                    typeof validated.problemLine === 'string' &&
                    !String(validated.detail).includes('▲') &&
                    PopUI.formatJsonErrorSnippet(validated).includes('▲');
            }

            // (c) Operational samples module (PopUI.DEMO_SAMPLES)
            const samplesOk =
                PopUI.DEMO_SAMPLES &&
                typeof PopUI.DEMO_SAMPLES.public_key === 'string' &&
                Array.isArray(PopUI.DEMO_SAMPLES.cases) &&
                PopUI.DEMO_SAMPLES.cases.length >= 7;

            // (d) Node-specific static & module checks: 0 core->ui refs, index.html script tags, fixtures.js UMD, slots.js resetInspector in Node
            let nodeChecksOk = true;
            if (typeof window === 'undefined') {
                const fs = require('fs');
                const path = require('path');
                const rootDir = path.join(__dirname, '..');

                // Check all files in js/core/** for any reference to ../ui, js/ui, or PopUI
                const coreDir = path.join(rootDir, 'js', 'core');
                const listJsFiles = (dir) => {
                    let results = [];
                    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                        const full = path.join(dir, entry.name);
                        if (entry.isDirectory()) results = results.concat(listJsFiles(full));
                        else if (entry.name.endsWith('.js')) results.push(full);
                    }
                    return results;
                };
                const coreFiles = listJsFiles(coreDir);
                const hasCoreJsonErrorFile = fs.existsSync(path.join(coreDir, 'jsonError.js'));
                const hasUiSamplesFile = fs.existsSync(path.join(rootDir, 'js', 'ui', 'samples.js'));
                let coreUiRefCount = 0;
                for (const f of coreFiles) {
                    const content = fs.readFileSync(f, 'utf8');
                    if (/(\.\.\/ui\/|js\/ui\/|\bPopUI\b)/.test(content)) {
                        coreUiRefCount++;
                    }
                }

                // Check index.html does not load test/fixtures/fixtures.js and loads js/ui/samples.js & js/core/jsonError.js
                const indexHtml = fs.readFileSync(path.join(rootDir, 'index.html'), 'utf8');
                const indexNoTestFixtures = !indexHtml.includes('test/fixtures/fixtures.js');
                const indexLoadsSamples = indexHtml.includes('js/ui/samples.js');
                const indexLoadsCoreJsonError = indexHtml.includes('js/core/jsonError.js');

                // Check test/fixtures/fixtures.js uses UMD and does not have top-level `const FIXTURES`
                const fixturesSrc = fs.readFileSync(path.join(rootDir, 'test', 'fixtures', 'fixtures.js'), 'utf8');
                const fixturesIsUmd = !/^const\s+FIXTURES\s*=/m.test(fixturesSrc) && fixturesSrc.includes('module.exports');

                // Check slots.js explicitly requires ./inspector.js and invokes resetInspector() when loading a slot in Node
                const slotsSrc = fs.readFileSync(path.join(rootDir, 'js', 'ui', 'slots.js'), 'utf8');
                const slotsRequiresInspector = slotsSrc.includes("require('./inspector.js')");

                const inspectorMod = require('../js/ui/inspector.js');
                const renderMod = require('../js/ui/render.js');
                let resetInspectorCalledOnSlotLoad = false;
                const origResetInspector = inspectorMod.resetInspector;
                const origShowToast = renderMod.showToast;
                const prevDoc = global.document;
                const prevStorage = global.localStorage;
                try {
                    inspectorMod.resetInspector = () => { resetInspectorCalledOnSlotLoad = true; };
                    renderMod.showToast = () => {};
                    global.localStorage = {
                        getItem() { return JSON.stringify({ slot_1: { time: '12:00:00', method: 'POST' } }); },
                        setItem() {}
                    };
                    const containerEl = createMockElement('DIV');
                    const panelEl = createMockElement('DIV');
                    global.document = createMockDocument({
                        elements: {
                            'memory-slots-container': containerEl,
                            'result-panel': panelEl
                        },
                        autoCreateElements: true,
                        defaultTag: 'INPUT'
                    });
                    PopUI.initMemorySlots();
                    const firstSlotDiv = containerEl.children[0];
                    const loadBtn = firstSlotDiv && firstSlotDiv.children.find(b => b.className.includes('btn-slot-load'));
                    if (loadBtn && loadBtn.listeners.click) {
                        loadBtn.listeners.click();
                    }
                } finally {
                    inspectorMod.resetInspector = origResetInspector;
                    renderMod.showToast = origShowToast;
                    global.document = prevDoc;
                    global.localStorage = prevStorage;
                }

                nodeChecksOk =
                    hasCoreJsonErrorFile &&
                    hasUiSamplesFile &&
                    coreUiRefCount === 0 &&
                    indexNoTestFixtures &&
                    indexLoadsSamples &&
                    indexLoadsCoreJsonError &&
                    fixturesIsUmd &&
                    slotsRequiresInspector &&
                    resetInspectorCalledOnSlotLoad;
            }

            if (noInternalLeak && coreHasJsonLoc && uiHasJsonFormat && jsonSplitOk && samplesOk && nodeChecksOk) {
                passed++;
            } else {
                console.log(`[FAIL] architecture-module-boundaries-and-api: noInternalLeak=${noInternalLeak}, coreHasJsonLoc=${coreHasJsonLoc}, uiHasJsonFormat=${uiHasJsonFormat}, jsonSplitOk=${jsonSplitOk}, samplesOk=${samplesOk}, nodeChecksOk=${nodeChecksOk}`);
                failed++;
            }
        }

        // 39) UI rendering: multiple sets (sets[0..n]), indistinguishable candidate guides with ID deduplication, diff-row actual/expected classes, and simultaneous Stage 4 + 5 failure display
        {
            const qSortedHyp = PopCore.HYPOTHESES.find(h => h.id === 'query-sorted');
            const qRevHyp = PopCore.HYPOTHESES.find(h => h.id === 'query-reverse');
            const mLowerHyp = PopCore.HYPOTHESES.find(h => h.id === 'method-lowercase');

            let renderSpyInnerHtmlUsed = false;
            const onInnerHtmlSpy = () => { renderSpyInnerHtmlUsed = true; };

            const findNodesByClass = (root, cls) => {
                let out = [];
                const classes = String(root.className || '').split(/\s+/);
                if (classes.includes(cls)) out.push(root);
                const children = root.children ? Array.from(root.children) : [];
                for (const ch of children) {
                    out = out.concat(findNodesByClass(ch, cls));
                }
                return out;
            };

            let mockPanel;
            let prevDoc;
            let createdBrowserPanel = false;
            if (typeof window === 'undefined') {
                mockPanel = createMockElement('DIV', { onInnerHtml: onInnerHtmlSpy });
                prevDoc = global.document;
                global.document = createMockDocument({
                    elements: { 'result-panel': mockPanel },
                    onInnerHtml: onInnerHtmlSpy
                });
            } else {
                mockPanel = document.getElementById('result-panel');
                if (!mockPanel) {
                    mockPanel = document.createElement('div');
                    mockPanel.id = 'result-panel';
                    mockPanel.className = 'hidden';
                    document.body.appendChild(mockPanel);
                    createdBrowserPanel = true;
                }
            }

            let multiSetsOk = false;
            let indistGuidesOk = false;
            let diffClassOk = false;
            let bothFailRenderOk = false;

            try {
                // (a) Multiple sets in hRes.sets (sets[0] and sets[1] must both be rendered)
                const multiSetResult = {
                    stages: [
                        { name: '1단계', status: 'pass' },
                        { name: '2단계', status: 'pass' },
                        { name: '3단계', status: 'unknown' },
                        { name: '4단계', status: 'fail', reason: '서명 불일치' },
                        { name: '5단계', status: 'pass' }
                    ],
                    warnings: [],
                    error: null,
                    firstFailedStage: 4,
                    expectedCanonical: 'POST\napi.example.com\n/v1/tx\nb=2&a=1\nhash\nn1\n1700000000',
                    hypothesisResult: {
                        type: 'found',
                        reduced: false,
                        sets: [
                            {
                                type: 'match',
                                item: { history: [qSortedHyp], idStr: 'query-sorted' },
                                canonical: 'POST\napi.example.com\n/v1/tx\na=1&b=2\nhash\nn1\n1700000000'
                            },
                            {
                                type: 'match',
                                item: { history: [mLowerHyp], idStr: 'method-lowercase' },
                                canonical: 'post\napi.example.com\n/v1/tx\nb=2&a=1\nhash\nn1\n1700000000'
                            }
                        ]
                    }
                };
                PopUI.renderResult(multiSetResult);
                const multiText = mockPanel.textContent;
                multiSetsOk =
                    multiText.includes(qSortedHyp.label) &&
                    multiText.includes(mLowerHyp.label) &&
                    multiText.includes(qSortedHyp.solution) &&
                    multiText.includes(mLowerHyp.solution);

                // (b) Indistinguishable set with shared + distinct hypothesis IDs: all candidate guides rendered, duplicate IDs deduplicated
                const indistComboResult = {
                    stages: multiSetResult.stages,
                    warnings: [],
                    error: null,
                    firstFailedStage: 4,
                    expectedCanonical: 'POST\napi.example.com\n/v1/tx\nb=2&a=1\nhash\nn1\n1700000000',
                    hypothesisResult: {
                        type: 'found',
                        reduced: false,
                        sets: [
                            {
                                type: 'indistinguishable',
                                canonical: 'post\napi.example.com\n/v1/tx\na=1&b=2\nhash\nn1\n1700000000',
                                items: [
                                    { history: [mLowerHyp, qSortedHyp], idStr: 'method-lowercase,query-sorted' },
                                    { history: [mLowerHyp, qRevHyp], idStr: 'method-lowercase,query-reverse' }
                                ]
                            }
                        ]
                    }
                };
                PopUI.renderResult(indistComboResult);
                const guideTitles = findNodesByClass(mockPanel, 'guide-item-title').map(n => n.textContent);
                indistGuidesOk =
                    guideTitles.length === 3 &&
                    guideTitles.some(t => t.includes(mLowerHyp.label)) &&
                    guideTitles.some(t => t.includes(qSortedHyp.label)) &&
                    guideTitles.some(t => t.includes(qRevHyp.label)) &&
                    mockPanel.textContent.includes(qRevHyp.cause) &&
                    mockPanel.textContent.includes(qRevHyp.solution);

                // (c) Diff row classes: client signed value (actualCanonical) -> 'diff-row actual', gateway expected (expectedCanonical) -> 'diff-row expected'
                const actualRows = findNodesByClass(mockPanel, 'diff-row').filter(n => n.className === 'diff-row actual');
                const expectedRows = findNodesByClass(mockPanel, 'diff-row').filter(n => n.className === 'diff-row expected');
                diffClassOk =
                    actualRows.length >= 2 &&
                    expectedRows.length >= 2 &&
                    actualRows[0].textContent === 'post' &&
                    expectedRows[0].textContent === 'POST' &&
                    actualRows[1].textContent === 'a=1&b=2' &&
                    expectedRows[1].textContent === 'b=2&a=1';

                // (d) Simultaneous Stage 4 + Stage 5 failure rendering (both-fail fixture: Stage 4 found + Stage 5 no-match, and both found)
                const bothFailCase = fixtures.cases.find(c => c.name === 'both-fail');
                const bothFailDiag = await PopCore.diagnose({
                    method: bothFailCase.method,
                    urlStr: `https://${bothFailCase.host}${bothFailCase.path}?${bothFailCase.query}`,
                    bodyStr: bothFailCase.body,
                    nonce: bothFailCase.nonce,
                    timestampStr: String(bothFailCase.timestamp),
                    signature: bothFailCase.signature,
                    pubkeyPem,
                    evalTime: bothFailCase.evalTime,
                    reqDigest: bothFailCase.digest
                });
                PopUI.renderResult(bothFailDiag);
                const bothFailText = mockPanel.textContent;

                const bomUpperDigest = bomBodyHash.toUpperCase();
                const simBothFoundSig = toBase64Url(await signRaw(["post", "api.example.com", "/v1/tx", "a=1", bomUpperDigest, nonce, ts].join('\n')));
                const simBothFoundDiag = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx?a=1",
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: simBothFoundSig,
                    pubkeyPem: dynPubkeyPem,
                    evalTime: Number(ts),
                    reqDigest: `sha256=${bomUpperDigest}`
                });
                PopUI.renderResult(simBothFoundDiag);
                const simBothFoundText = mockPanel.textContent;

                bothFailRenderOk =
                    bothFailText.includes('Host') &&
                    bothFailText.includes('원인 파악 실패') &&
                    simBothFoundText.includes('서명이 검증됩니다') &&
                    simBothFoundText.includes('다이제스트가 검증됩니다');
            } finally {
                if (typeof window === 'undefined') {
                    global.document = prevDoc;
                } else if (createdBrowserPanel) {
                    mockPanel.remove();
                }
            }

            if (!renderSpyInnerHtmlUsed && multiSetsOk && indistGuidesOk && diffClassOk && bothFailRenderOk) {
                passed++;
            } else {
                console.log(`[FAIL] ui-render-multi-sets-indistinguishable-diff-and-both-fail: innerHtml=${renderSpyInnerHtmlUsed}, multiSetsOk=${multiSetsOk}, indistGuidesOk=${indistGuidesOk}, diffClassOk=${diffClassOk}, bothFailRenderOk=${bothFailRenderOk}`);
                failed++;
            }
        }

        // 40) wrong-key fixture STAGE4_SIG_MISMATCH verification & check_encoding.py exit code 1 on broken UTF-8
        {
            const wrongKeyCase = fixtures.cases.find(c => c.name === 'wrong-key');
            const wrongKeyDiag = await PopCore.diagnose({
                method: wrongKeyCase.method,
                urlStr: `https://${wrongKeyCase.host}${wrongKeyCase.path}?${wrongKeyCase.query}`,
                bodyStr: wrongKeyCase.body,
                nonce: wrongKeyCase.nonce,
                timestampStr: String(wrongKeyCase.timestamp),
                signature: wrongKeyCase.signature,
                pubkeyPem,
                evalTime: wrongKeyCase.evalTime,
                reqDigest: wrongKeyCase.digest
            });
            const wrongKeyIsSigMismatch =
                wrongKeyDiag.firstFailedStage === 4 &&
                wrongKeyDiag.stages[3] &&
                wrongKeyDiag.stages[3].code === PopCore.STAGE_CODES.STAGE4_SIG_MISMATCH;

            let encodingCheckExitOk = true;
            if (typeof window === 'undefined') {
                const fs = require('fs');
                const os = require('os');
                const path = require('path');
                const { spawnSync } = require('child_process');
                const tmpBrokenFile = path.join(os.tmpdir(), `pop_broken_utf8_${Date.now()}.txt`);
                try {
                    fs.writeFileSync(tmpBrokenFile, Buffer.from([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xff, 0xfe]));
                    const proc = spawnSync('python', [path.join(__dirname, '..', 'tools', 'check_encoding.py'), tmpBrokenFile], { encoding: 'utf8' });
                    encodingCheckExitOk = proc.status === 1;
                } finally {
                    if (fs.existsSync(tmpBrokenFile)) fs.unlinkSync(tmpBrokenFile);
                }
            }

            if (wrongKeyIsSigMismatch && encodingCheckExitOk) {
                passed++;
            } else {
                console.log(`[FAIL] fixtures-wrong-key-and-check-encoding: wrongKeyCode=${wrongKeyDiag.stages[3] && wrongKeyDiag.stages[3].code}, encodingCheckExitOk=${encodingCheckExitOk}`);
                failed++;
            }
        }

        // 41) Additional audit fixes: generateTestSignature (:443 & protocol check), slots CRLF/LF _rawBody preservation, and Stage 5 hypothesis direct rawBody update
        {
            // (a) generateTestSignature rejects non-HTTP(S) URLs and preserves explicit :443 so diagnose() passes
            let nonHttpRejected = false;
            try {
                await PopCore.generateTestSignature({
                    method: 'POST',
                    urlStr: 'javascript:alert(1)',
                    bodyStr: 'hello',
                    nonce: 'n-test-1234',
                    timestampStr: '1700000000'
                });
            } catch (e) {
                nonHttpRejected = e && e.code === PopCore.ERROR_CODES.INVALID_URL;
            }

            const gen443 = await PopCore.generateTestSignature({
                method: 'POST',
                urlStr: 'https://api.example.com:443/v1/tx?a=1',
                bodyStr: 'hello',
                nonce: 'n-test-1234',
                timestampStr: '1700000000'
            });
            const diag443 = await PopCore.diagnose({
                method: 'POST',
                urlStr: 'https://api.example.com:443/v1/tx?a=1',
                bodyStr: 'hello',
                nonce: 'n-test-1234',
                timestampStr: '1700000000',
                signature: gen443.signature,
                pubkeyPem: gen443.pubkeyPem,
                evalTime: 1700000000,
                reqDigest: gen443.reqDigest
            });
            const gen443RoundTripOk = diag443.firstFailedStage === null && diag443.stages.every(s => s.status === 'pass' || s.status === 'unknown');

            // (b) Stage 5 hypotheses directly update rawBody alongside bodyHash when h.apply(req, 5) is invoked
            const s5TrailingHyp = PopCore.HYPOTHESES.find(h => h.id === 'newline-trailing');
            const s5BomHyp = PopCore.HYPOTHESES.find(h => h.id === 'body-bom-added');
            const s5MinifiedHyp = PopCore.HYPOTHESES.find(h => h.id === 'body-reserialized-nospace');
            const sampleReq = { rawBody: '{\n  "a": 1\n}', bodyHash: '' };
            const trailingApplied = await s5TrailingHyp.apply(sampleReq, 5);
            const bomApplied = await s5BomHyp.apply(sampleReq, 5);
            const minifiedApplied = await s5MinifiedHyp.apply(sampleReq, 5);
            const s5RawBodyOk =
                trailingApplied.rawBody === '{\n  "a": 1\n}\n' &&
                bomApplied.rawBody === '\uFEFF{\n  "a": 1\n}' &&
                minifiedApplied.rawBody === '{"a":1}';

            // (c) slots.js preserves CRLF _rawBody on save and overwrites stale _rawBody on load
            let slotsCrlfOk = false;
            const crlfSample = '{\r\n  "x": 1\r\n}';
            const lfSample = '{\n  "x": 1\n}';

            const storageMap = {};
            const mockStorage = {
                getItem(k) { return Object.prototype.hasOwnProperty.call(storageMap, k) ? storageMap[k] : null; },
                setItem(k, v) { storageMap[k] = String(v); }
            };

            if (typeof window === 'undefined') {
                const renderMod = require('../js/ui/render.js');
                const inspectorMod = require('../js/ui/inspector.js');
                const origShowToast = renderMod.showToast;
                const origResetInspector = inspectorMod.resetInspector;
                const prevDoc = global.document;
                const prevStorage = global.localStorage;
                try {
                    renderMod.showToast = () => {};
                    inspectorMod.resetInspector = () => {};
                    global.localStorage = mockStorage;
                    const elMap = {
                        'memory-slots-container': createMockElement('DIV'),
                        'result-panel': createMockElement('DIV'),
                        'req-body': createMockElement('TEXTAREA', { isTextarea: true })
                    };
                    global.document = createMockDocument({
                        elements: elMap,
                        autoCreateElements: true,
                        defaultTag: 'INPUT'
                    });

                    // Set CRLF body in req-body and save to slot_1
                    PopUI.setRawTextareaValue(elMap['req-body'], crlfSample);
                    PopUI.initMemorySlots();
                    let slot1Div = elMap['memory-slots-container'].children[0];
                    let saveBtn1 = slot1Div.children.find(b => b.className.includes('btn-slot-save'));
                    saveBtn1.listeners.click();

                    // Overwrite req-body with LF, then load slot_1 -> should restore CRLF via readRequestBody
                    PopUI.setRawTextareaValue(elMap['req-body'], lfSample);
                    slot1Div = elMap['memory-slots-container'].children[0];
                    let loadBtn1 = slot1Div.children.find(b => b.className.includes('btn-slot-load'));
                    loadBtn1.listeners.click();
                    const loadedCrlf = PopUI.readRequestBody(elMap['req-body']);

                    // Save LF to slot_2, put CRLF in req-body, then load slot_2 -> should overwrite stale CRLF _rawBody with LF
                    PopUI.setRawTextareaValue(elMap['req-body'], lfSample);
                    let slot2Div = elMap['memory-slots-container'].children[1];
                    let saveBtn2 = slot2Div.children.find(b => b.className.includes('btn-slot-save'));
                    saveBtn2.listeners.click();

                    PopUI.setRawTextareaValue(elMap['req-body'], crlfSample);
                    slot2Div = elMap['memory-slots-container'].children[1];
                    let loadBtn2 = slot2Div.children.find(b => b.className.includes('btn-slot-load'));
                    loadBtn2.listeners.click();
                    const loadedLf = PopUI.readRequestBody(elMap['req-body']);

                    slotsCrlfOk = (loadedCrlf === crlfSample && loadedLf === lfSample);
                } finally {
                    renderMod.showToast = origShowToast;
                    inspectorMod.resetInspector = origResetInspector;
                    global.document = prevDoc;
                    global.localStorage = prevStorage;
                }
            } else {
                const reqBodyEl = document.getElementById('req-body') || createMockElement('TEXTAREA', { isTextarea: true });
                PopUI.setRawTextareaValue(reqBodyEl, crlfSample);
                const readCrlf = PopUI.readRequestBody(reqBodyEl);
                PopUI.setRawTextareaValue(reqBodyEl, lfSample);
                const readLf = PopUI.readRequestBody(reqBodyEl);
                slotsCrlfOk = (readCrlf === crlfSample && readLf === lfSample);
            }

            if (nonHttpRejected && gen443RoundTripOk && s5RawBodyOk && slotsCrlfOk) {
                passed++;
            } else {
                console.log(`[FAIL] audit-fixes-generate-sig-slots-and-s5-rawbody: nonHttpRejected=${nonHttpRejected}, gen443RoundTripOk=${gen443RoundTripOk}, s5RawBodyOk=${s5RawBodyOk}, slotsCrlfOk=${slotsCrlfOk}`);
                failed++;
            }
        }

        // 42) Browser global load order & PopCore public symbol preservation (STAGE_IDS, buildString, verifySig, UMD symmetry, etc.)
        {
            const expectedSymbols = [
                'STAGE_IDS',
                'PaperProfile',
                'buildString',
                'verifySig',
                'generateKeyPairAndSign',
                'derToRaw',
                'importPublicKey',
                'extractPublicKeySpkiBytes',
                'containsPrivateKeyMarker',
                'parseDerSignature',
                'detectAndDecodeSignature',
                'inspectSignature',
                'inspectPublicKey',
                'inspectDerStructure',
                'isPointOnP256Curve',
                'P256_P',
                'P256_A',
                'P256_B',
                'P256_N',
                'P256_HALF_N',
                'OID_EC_PUBLIC_KEY',
                'OID_RSA_ENCRYPTION',
                'OID_P256',
                'parseCurl',
                'parseRawHttp',
                'MAX_INPUT_LENGTH',
                'createEmptyInputs',
                'HYPOTHESES',
                'JSON_HINT_CODES',
                'detectJsonErrorHint',
                'extractJsonErrorLocation',
                'looksLikeJson',
                'diagnose',
                'validateJsonBody',
                'generateTestSignature',
                'ERROR_CODES',
                'STAGE_CODES',
                'WARNING_CODES',
                'PEM_PUBLIC_KEY_HEADER',
                'PEM_PUBLIC_KEY_FOOTER',
                'base64UrlDecode',
                'base64StandardDecode',
                'base64UrlEncodeBytes',
                'bytesToHex',
                'bytesToBinaryString',
                'hashString',
                'hashStringToBase64Url'
            ];
            const forbiddenInternalSymbols = ['_atob', '_btoa', '_crypto', 'binaryStringToBytes'];

            const directPopCoreOk =
                expectedSymbols.every(sym => PopCore[sym] !== undefined) &&
                forbiddenInternalSymbols.every(sym => PopCore[sym] === undefined);

            let browserVmOk = true;
            let exactKeySymmetryOk = true;
            if (typeof window === 'undefined') {
                const fs = require('fs');
                const path = require('path');
                const vm = require('vm');
                const rootDir = path.join(__dirname, '..');
                const ctx = vm.createContext({
                    console,
                    crypto: _crypto,
                    atob: typeof atob !== 'undefined' ? atob : (s) => Buffer.from(s, 'base64').toString('binary'),
                    btoa: _btoa,
                    TextEncoder,
                    TextDecoder,
                    Uint8Array,
                    ArrayBuffer,
                    URL,
                    Date,
                    Math,
                    BigInt,
                    Set,
                    Map,
                    Promise,
                    Error,
                    String,
                    Number,
                    Boolean,
                    Array,
                    Object,
                    RegExp,
                    JSON,
                    parseInt,
                    isNaN,
                    setTimeout,
                    clearTimeout
                });
                ctx.window = ctx;
                ctx.globalThis = ctx;

                const scriptOrder = [
                    'js/core/profiles/paper.js',
                    'js/core/encoding.js',
                    'js/core/ecdsa.js',
                    'js/core/inspect.js',
                    'js/core/curlParser.js',
                    'js/core/canonical.js',
                    'js/core/hypotheses.js',
                    'js/core/jsonError.js',
                    'js/core/diagnose.js'
                ];
                for (const relPath of scriptOrder) {
                    const code = fs.readFileSync(path.join(rootDir, relPath), 'utf8');
                    vm.runInContext(code, ctx, { filename: relPath });
                }

                exactKeySymmetryOk =
                    Boolean(ctx.PopCore) &&
                    Object.keys(ctx.PopCore).sort().join(',') === Object.keys(PopCore).sort().join(',');

                browserVmOk =
                    Boolean(ctx.PopCore) &&
                    expectedSymbols.every(sym => ctx.PopCore[sym] !== undefined) &&
                    forbiddenInternalSymbols.every(sym => ctx.PopCore[sym] === undefined) &&
                    exactKeySymmetryOk;
            }

            if (directPopCoreOk && browserVmOk && exactKeySymmetryOk) {
                passed++;
            } else {
                console.log(`[FAIL] popcore-global-symbols-preservation: directPopCoreOk=${directPopCoreOk}, browserVmOk=${browserVmOk}, exactKeySymmetryOk=${exactKeySymmetryOk}`);
                failed++;
            }
        }

        // 43) Hypothesis cause/solution accuracy (newline-trailing last canonical field Timestamp + Stage 4/5 coverage, host-rewritten bidirectional :443 guidance)
        {
            const canonicalFields = PopCore.PaperProfile.canonicalFields;
            const lastCanonicalField = canonicalFields[canonicalFields.length - 1];
            const nlTrailingHyp = PopCore.HYPOTHESES.find(h => h.id === 'newline-trailing');
            const hostRewrittenHyp = PopCore.HYPOTHESES.find(h => h.id === 'host-rewritten');

            const nlTrailingAccurate =
                Boolean(nlTrailingHyp) &&
                lastCanonicalField === 'timestamp' &&
                !nlTrailingHyp.solution.includes('마지막 항목(Body-Digest)') &&
                /Timestamp/i.test(nlTrailingHyp.solution) &&
                (nlTrailingHyp.cause.includes('본문') || nlTrailingHyp.solution.includes('본문')) &&
                (nlTrailingHyp.cause.includes('4단계') || nlTrailingHyp.solution.includes('4단계')) &&
                (nlTrailingHyp.cause.includes('5단계') || nlTrailingHyp.solution.includes('5단계'));

            const hostRewrittenAccurate =
                Boolean(hostRewrittenHyp) &&
                hostRewrittenHyp.solution.includes(':443') &&
                hostRewrittenHyp.solution.includes('일치') &&
                !hostRewrittenHyp.solution.includes('포트 번호(\':443\') 없이 도메인 이름만 사용합니다');

            if (nlTrailingAccurate && hostRewrittenAccurate) {
                passed++;
            } else {
                console.log(`[FAIL] hypothesis-guide-text-accuracy: nlTrailingAccurate=${nlTrailingAccurate}, hostRewrittenAccurate=${hostRewrittenAccurate}`);
                failed++;
            }
        }

        // 44) generateTestSignature plaintext support, looksLikeJson refinement, and Content-Type propagation (a, b, c, d)
        {
            let caseAOk = false;
            let caseBOk = false;
            let caseCOk = false;
            let caseDOk = false;
            let heuristicsAndCurlOk = false;

            try {
                // (a) Plaintext "[OK]" body -> no warning + signature generation succeeds
                const resPlain = await PopCore.generateTestSignature({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: "Plain text log [OK]",
                    nonce: "n1",
                    timestampStr: "1700000000"
                });
                const diagPlain = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: "Plain text log [OK]",
                    nonce: "n1",
                    timestampStr: "1700000000",
                    signature: resPlain.signature,
                    pubkeyPem: resPlain.pubkeyPem,
                    reqDigest: resPlain.reqDigest,
                    evalTime: 1700000000
                });
                caseAOk =
                    Boolean(resPlain && resPlain.signature && resPlain.reqDigest && resPlain.pubkeyPem) &&
                    !resPlain.warning &&
                    diagPlain.error === null &&
                    diagPlain.firstFailedStage === null &&
                    !diagPlain.warnings.some(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);

                // (b) Broken JSON ('{"a":1') -> warning present + signature generation succeeds
                const resBroken = await PopCore.generateTestSignature({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: '{"a":1',
                    nonce: "n1",
                    timestampStr: "1700000000"
                });
                caseBOk =
                    Boolean(resBroken && resBroken.signature && resBroken.reqDigest && resBroken.pubkeyPem) &&
                    Boolean(resBroken.warning) &&
                    resBroken.warning.code === PopCore.ERROR_CODES.INVALID_JSON &&
                    typeof resBroken.warning.message === 'string' &&
                    resBroken.warning.message.length > 0;

                // (c) Content-Type: text/plain + body ending with '}' -> no warning
                const resTextPlainBrace = await PopCore.generateTestSignature({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: 'plain text ending with {"key": broken}',
                    contentType: "text/plain; charset=utf-8",
                    nonce: "n1",
                    timestampStr: "1700000000"
                });
                const curlTextPlain = parseCurl(
                    "curl 'https://api.example.com/v1/tx' " +
                    "-H 'Content-Type: text/plain' " +
                    "-H 'X-FIDO2-Nonce: n1' " +
                    "-H 'X-FIDO2-Timestamp: 1700000000' " +
                    `-H 'X-FIDO2-Signature: ${resTextPlainBrace.signature}' ` +
                    `-H 'X-Body-Digest: ${resTextPlainBrace.reqDigest}' ` +
                    "--data-raw 'plain text ending with {\"key\": broken}'"
                );
                const diagFromCurl = await PopCore.diagnose({
                    ...curlTextPlain.inputs,
                    pubkeyPem: resTextPlainBrace.pubkeyPem,
                    evalTime: 1700000000
                });
                caseCOk =
                    Boolean(resTextPlainBrace && resTextPlainBrace.signature) &&
                    !resTextPlainBrace.warning &&
                    curlTextPlain.ok === true &&
                    curlTextPlain.inputs.contentType === 'text/plain' &&
                    diagFromCurl.error === null &&
                    diagFromCurl.firstFailedStage === null &&
                    !diagFromCurl.warnings.some(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);

                // (d) Valid JSON -> no warning + signature generation succeeds
                const resValidJson = await PopCore.generateTestSignature({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: '{"amount":1000,"to":"alice"}',
                    nonce: "n1",
                    timestampStr: "1700000000"
                });
                caseDOk =
                    Boolean(resValidJson && resValidJson.signature && resValidJson.reqDigest && resValidJson.pubkeyPem) &&
                    !resValidJson.warning;

                // Additional looksLikeJson heuristics: "function foo() { return 1; }" -> false (no warning)
                const resFunc = await PopCore.generateTestSignature({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: "function foo() { return 1; }",
                    nonce: "n1",
                    timestampStr: "1700000000"
                });
                heuristicsAndCurlOk =
                    Boolean(resFunc && resFunc.signature) &&
                    !resFunc.warning &&
                    PopCore.validateJsonBody("Plain text log [OK]") === null &&
                    PopCore.validateJsonBody("function foo() { return 1; }") === null &&
                    PopCore.validateJsonBody('{"a":1') !== null &&
                    PopCore.validateJsonBody('"a": 1}') !== null &&
                    PopCore.validateJsonBody('1, 2, 3]') !== null;
            } catch (_e) {
                // Pre-fix generateTestSignature throws on non-JSON / broken JSON
            }

            if (caseAOk && caseBOk && caseCOk && caseDOk && heuristicsAndCurlOk) {
                passed++;
            } else {
                console.log(`[FAIL] plaintext-generate-sig-and-looks-like-json: caseAOk=${caseAOk}, caseBOk=${caseBOk}, caseCOk=${caseCOk}, caseDOk=${caseDOk}, heuristicsAndCurlOk=${heuristicsAndCurlOk}`);
                failed++;
            }
        }

        // 45) Verification of multi-byte hex escapes, argument-taking flags, whitespace normalization, numeric hardening, looksLikeJson refinement
        {
            let t1Ok = false;
            let t2Ok = false;
            let t3Ok = false;
            let t4Ok = false;
            let t5Ok = false;

            // 1) Multi-byte UTF-8 Hex Escapes
            try {
                const curlUtf8 = "curl 'https://api.example.com/v1/tx' -d $'{\"name\":\"\\xed\\x99\\x8d\"}'";
                const parsedUtf8 = parseCurl(curlUtf8);
                const curlMulti = "curl 'https://api.example.com/v1/tx' -d $'\\xed\\x99\\x8d\\xea\\xb8\\xb8\\xeb\\x8f\\x99'";
                const parsedMulti = parseCurl(curlMulti);
                if (
                    parsedUtf8.ok && parsedUtf8.inputs.bodyStr === '{"name":"홍"}' &&
                    parsedMulti.ok && parsedMulti.inputs.bodyStr === '홍길동'
                ) {
                    t1Ok = true;
                }
            } catch (e) {
                console.log("Error in t1:", e);
            }

            // 2) Harmless argument-taking flags and URL candidate preference
            try {
                const curlFlags = [
                    "curl https://api.example.com/v1/tx -A 'Mozilla/5.0' -b 'c=1' -e 'https://ref.com' -m 10 --connect-timeout 5",
                    "curl --user-agent='Mozilla/5.0' --cookie='c=1' --referer='https://ref.com' --max-time=10 --connect-timeout=5 https://api.example.com/v1/tx",
                    "curl -A\"Mozilla/5.0\" -bc=1 -ehttps://ref.com -m10 https://api.example.com/v1/tx",
                    "curl --unknown-flag bareToken https://api.example.com/v1/tx",
                    "curl https://api.example.com/v1/tx --unknown-flag bareToken"
                ];
                const resFlags = curlFlags.map(c => parseCurl(c));
                const allUrlsMatch = resFlags.every(r => r.inputs.urlStr === 'https://api.example.com/v1/tx');
                const ignoredWarningsPresent = resFlags[0].warnings.filter(w => w.code === 'IGNORED_FLAG').length === 5 &&
                                              resFlags[1].warnings.filter(w => w.code === 'IGNORED_FLAG').length === 5 &&
                                              resFlags[2].warnings.filter(w => w.code === 'IGNORED_FLAG').length === 4;
                if (allUrlsMatch && ignoredWarningsPresent) {
                    t2Ok = true;
                }
            } catch (e) {
                console.log("Error in t2:", e);
            }

            // 3) Whitespace normalization in diagnose()
            try {
                const vCase = fixtures.cases[0];
                const diagSpaced = await PopCore.diagnose({
                    method: " POST ",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: " n-test 123 ",
                    timestampStr: ` ${vCase.timestamp} \n`,
                    signature: `\n ${vCase.signature} \n`,
                    pubkeyPem: pubkeyPem,
                    evalTime: vCase.evalTime,
                    reqDigest: ` sha256=${vCase.digest ? vCase.digest.replace('sha256=', '') : ''} `
                });
                const wsWarn = diagSpaced.warnings.find(w => w.code === 'WHITESPACE_STRIPPED');
                const hasExpectedFields = wsWarn &&
                    wsWarn.message.includes('HTTP 메서드') &&
                    wsWarn.message.includes('Nonce') &&
                    wsWarn.message.includes('Timestamp') &&
                    wsWarn.message.includes('Signature') &&
                    wsWarn.message.includes('Body-Digest');

                const diagNoStrip = await PopCore.diagnose({
                    method: "POST",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: "n1",
                    timestampStr: "abc",
                    signature: vCase.signature,
                    pubkeyPem: pubkeyPem,
                    stripWhitespace: false
                });

                if (diagSpaced.error === null && hasExpectedFields && diagNoStrip.warnings.every(w => w.code !== 'WHITESPACE_STRIPPED')) {
                    t3Ok = true;
                }
            } catch (e) {
                console.log("Error in t3:", e);
            }

            // 4) Numeric hardening (>15 digits, !isSafeInteger, evalTime types and finiteness)
            try {
                const vCase = fixtures.cases[0];
                const diagLongTs = await PopCore.diagnose({
                    method: "POST",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: "n1",
                    timestampStr: "1234567890123456", // 16 digits
                    signature: vCase.signature,
                    pubkeyPem: pubkeyPem
                });
                const longTsRejected = diagLongTs.error && diagLongTs.error.code === PopCore.ERROR_CODES.INVALID_TIMESTAMP;

                const diagMaxSafe = await PopCore.diagnose({
                    method: "POST",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: "n1",
                    timestampStr: "9999999999999999", // 16 digits > max safe
                    signature: vCase.signature,
                    pubkeyPem: pubkeyPem
                });
                const maxSafeRejected = diagMaxSafe.error && diagMaxSafe.error.code === PopCore.ERROR_CODES.INVALID_TIMESTAMP;

                // Stage 2 evalTime fallback checks
                const nowSec = Math.floor(Date.now() / 1000);
                const s2Whitespace = await PopCore.diagnose({
                    method: "POST",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: "n1",
                    timestampStr: String(nowSec),
                    signature: vCase.signature,
                    pubkeyPem: pubkeyPem,
                    evalTime: "   " // whitespace only -> fallback to now -> pass
                });
                const s2Bool = await PopCore.diagnose({
                    method: "POST",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: "n1",
                    timestampStr: String(nowSec),
                    signature: vCase.signature,
                    pubkeyPem: pubkeyPem,
                    evalTime: true // boolean -> fallback to now -> pass
                });
                const s2Infinity = await PopCore.diagnose({
                    method: "POST",
                    urlStr: `https://${vCase.host}${vCase.path}?${vCase.query}`,
                    bodyStr: vCase.body,
                    nonce: "n1",
                    timestampStr: String(nowSec),
                    signature: vCase.signature,
                    pubkeyPem: pubkeyPem,
                    evalTime: Infinity // Infinity -> fallback to now -> pass
                });

                const evalTimePassed = s2Whitespace.stages[1].status === 'pass' &&
                                       s2Bool.stages[1].status === 'pass' &&
                                       s2Infinity.stages[1].status === 'pass';

                if (longTsRejected && maxSafeRejected && evalTimePassed) {
                    t4Ok = true;
                }
            } catch (e) {
                console.log("Error in t4:", e);
            }

            // 5) Refine looksLikeJson
            try {
                const plainLog = "[INFO] server started";
                const errLog = "[ERROR] 2026-10-14 Connection failed";
                const validArray = "[1, 2, 3]";
                const brokenArrayWithObject = "[ {\"a\": 1";
                const brokenArrayWithBool = "[ true, ";
                const brokenArrayWithNull = "[ null, ";
                const brokenArrayWithNumber = "[ 42, ";
                const brokenArrayWithString = "[ 'str', ";

                const plainIsJson = PopCore.looksLikeJson(plainLog);
                const errIsJson = PopCore.looksLikeJson(errLog);
                const validIsJson = PopCore.looksLikeJson(validArray);
                const truncObjIsJson = PopCore.looksLikeJson(brokenArrayWithObject);
                const truncBoolIsJson = PopCore.looksLikeJson(brokenArrayWithBool);
                const truncNullIsJson = PopCore.looksLikeJson(brokenArrayWithNull);
                const truncNumIsJson = PopCore.looksLikeJson(brokenArrayWithNumber);
                const truncStrIsJson = PopCore.looksLikeJson(brokenArrayWithString);

                const plainDiag = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: plainLog,
                    nonce: "n1",
                    timestampStr: "1700000000",
                    signature: validSig,
                    pubkeyPem: pubkeyPem
                });
                const noInvalidJsonWarn = !plainDiag.warnings.some(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);

                if (
                    !plainIsJson && !errIsJson && validIsJson &&
                    truncObjIsJson && truncBoolIsJson && truncNullIsJson &&
                    truncNumIsJson && truncStrIsJson && noInvalidJsonWarn
                ) {
                    t5Ok = true;
                }
            } catch (e) {
                console.log("Error in t5:", e);
            }

            if (t1Ok && t2Ok && t3Ok && t4Ok && t5Ok) {
                passed++;
            } else {
                console.log(`[FAIL] regression-fixes-5-items: t1Ok=${t1Ok}, t2Ok=${t2Ok}, t3Ok=${t3Ok}, t4Ok=${t4Ok}, t5Ok=${t5Ok}`);
                failed++;
            }
        }

        // 46) BFS deduplication & Stage 5 maxSearchNodes cap test
        {
            let s5CapOk = false;
            let sameDepthDedupeOk = false;

            try {
                // 1) Stage 5 maxSearchNodes cap
                const s5Profile = Object.assign({}, PopCore.PaperProfile, { maxSearchNodes: 2 });
                const s5Res = await PopCore.diagnose({
                    method: 'POST',
                    urlStr: 'https://api.example.com/v1/tx',
                    bodyStr: '{"amount": 1000}',
                    nonce: 'n1',
                    timestampStr: '1700000000',
                    signature: fixtures.cases[0].signature,
                    pubkeyPem: fixtures.public_key,
                    evalTime: 1700000000,
                    reqDigest: 'sha256=unmatchable_digest_that_does_not_exist_in_catalog'
                }, s5Profile);

                if (s5Res.stage5HypothesisResult && s5Res.stage5HypothesisResult.reduced === true) {
                    s5CapOk = true;
                }
            } catch (e) {
                console.log("Error in s5Cap:", e);
            }

            try {
                // 2) Indistinguishable query parameters with 0 duplicate verify calls and stateKey including stdBase64Signature
                const indCase = fixtures.cases.find(x => x.name === 'indistinguishable');
                const origVerify = _crypto.subtle.verify.bind(_crypto.subtle);
                let callCount = 0;
                let dupCalls = 0;
                const seenKeys = new Set();
                _crypto.subtle.verify = async (alg, key, sig, data) => {
                    callCount++;
                    const keyStr = `${PopCore.bytesToHex(sig)}|${new TextDecoder().decode(data)}`;
                    if (seenKeys.has(keyStr)) dupCalls++;
                    else seenKeys.add(keyStr);
                    return origVerify(alg, key, sig, data);
                };

                try {
                    const res = await PopCore.diagnose({
                        method: indCase.method,
                        urlStr: `https://${indCase.host}${indCase.path}?${indCase.query}`,
                        bodyStr: indCase.body,
                        nonce: indCase.nonce,
                        timestampStr: String(indCase.timestamp),
                        signature: indCase.signature,
                        pubkeyPem,
                        evalTime: indCase.evalTime,
                        reqDigest: indCase.digest
                    });
                    const s = res.hypothesisResult && res.hypothesisResult.sets && res.hypothesisResult.sets[0];
                    if (dupCalls === 0 && s && s.type === 'indistinguishable' && s.items.length === 2) {
                        sameDepthDedupeOk = true;
                    }
                } finally {
                    _crypto.subtle.verify = origVerify;
                }
            } catch (e) {
                console.log("Error in sameDepthDedupe:", e);
            }

            if (s5CapOk && sameDepthDedupeOk) {
                passed++;
            } else {
                console.log(`[FAIL] bfs-dedupe-and-stage5-cap: s5CapOk=${s5CapOk}, sameDepthDedupeOk=${sameDepthDedupeOk}`);
                failed++;
            }
        }

        // 47) Slot contentType isolation, body metadata encapsulation, and button async concurrency guard
        {
            let helpersOk = false;
            let slotIsolationOk = false;
            let buttonConcurrencyOk = false;

            // (a) Body state helpers in PopUI
            try {
                const mockEl = { value: '', _rawBody: '', _contentType: '' };
                PopUI.setRawTextareaValue(mockEl, '{"test":123}', 'application/json');
                const readVal = PopUI.readRequestBody(mockEl);
                const readCt = PopUI.readRequestContentType(mockEl);

                PopUI.setRawTextareaValue(mockEl, 'plain text', '');
                const readEmptyCt = PopUI.readRequestContentType(mockEl);
                const hasNoProp = !Object.prototype.hasOwnProperty.call(mockEl, '_contentType');

                if (
                    readVal === '{"test":123}' &&
                    readCt === 'application/json' &&
                    readEmptyCt === '' &&
                    hasNoProp
                ) {
                    helpersOk = true;
                }
            } catch (e) {
                console.log("Error in helpersOk:", e);
            }

            // (b) Slot contentType persistence and isolation across slots
            try {
                const storageMap = {};
                const mockStorage = {
                    getItem(k) { return Object.prototype.hasOwnProperty.call(storageMap, k) ? storageMap[k] : null; },
                    setItem(k, v) { storageMap[k] = String(v); }
                };

                const prevDoc = global.document;
                const prevStorage = global.localStorage;
                try {
                    global.localStorage = mockStorage;
                    const elMap = {
                        'memory-slots-container': createMockElement('DIV'),
                        'result-panel': createMockElement('DIV'),
                        'req-body': createMockElement('TEXTAREA', { isTextarea: true })
                    };
                    global.document = createMockDocument({
                        elements: elMap,
                        autoCreateElements: true,
                        defaultTag: 'INPUT'
                    });

                    PopUI.initMemorySlots();

                    // Save slot 1 with text/plain
                    PopUI.setRawTextareaValue(elMap['req-body'], 'plain text', 'text/plain');
                    let slot1Div = elMap['memory-slots-container'].children[0];
                    let saveBtn1 = slot1Div.children.find(b => b.className.includes('btn-slot-save'));
                    saveBtn1.listeners.click();

                    // Save slot 2 with broken JSON without content-type
                    const brokenJsonStr = '{\n  "amount": 1000';
                    PopUI.setRawTextareaValue(elMap['req-body'], brokenJsonStr, '');
                    let slot2Div = elMap['memory-slots-container'].children[1];
                    let saveBtn2 = slot2Div.children.find(b => b.className.includes('btn-slot-save'));
                    saveBtn2.listeners.click();

                    // Load slot 1 -> should have text/plain (re-query slot1Div because DOM was re-rendered)
                    slot1Div = elMap['memory-slots-container'].children[0];
                    let loadBtn1 = slot1Div.children.find(b => b.className.includes('btn-slot-load'));
                    loadBtn1.listeners.click();
                    const ctSlot1 = PopUI.readRequestContentType(elMap['req-body']);

                    // Load slot 2 -> should reset contentType to empty, not leak text/plain (re-query slot2Div because DOM was re-rendered)
                    slot2Div = elMap['memory-slots-container'].children[1];
                    let loadBtn2 = slot2Div.children.find(b => b.className.includes('btn-slot-load'));
                    loadBtn2.listeners.click();
                    const ctSlot2 = PopUI.readRequestContentType(elMap['req-body']);
                    const bodySlot2 = PopUI.readRequestBody(elMap['req-body']);

                    const isJson = PopCore.looksLikeJson(bodySlot2, ctSlot2);
                    const isNotJsonWithStaleCt = PopCore.looksLikeJson(bodySlot2, 'text/plain');

                    // Diagnose slot 2 data: broken JSON must trigger INVALID_JSON warning because contentType is empty
                    const diagRes = await PopCore.diagnose({
                        method: 'POST',
                        urlStr: 'https://api.example.com/v1/tx',
                        bodyStr: bodySlot2,
                        contentType: ctSlot2,
                        nonce: 'n1',
                        timestampStr: '1700000000',
                        signature: fixtures.cases[0].signature,
                        pubkeyPem: fixtures.public_key,
                        evalTime: 1700000000,
                        reqDigest: 'sha256=xxx'
                    });
                    const hasJsonWarn = diagRes.warnings && diagRes.warnings.some(w => w.code === PopCore.ERROR_CODES.INVALID_JSON);

                    if (
                        ctSlot1 === 'text/plain' &&
                        ctSlot2 === '' &&
                        isJson === true &&
                        isNotJsonWithStaleCt === false &&
                        hasJsonWarn === true
                    ) {
                        slotIsolationOk = true;
                    }
                } finally {
                    global.document = prevDoc;
                    global.localStorage = prevStorage;
                }
            } catch (e) {
                console.log("Error in slotIsolationOk:", e);
            }

            // (c) Action buttons async concurrency guard
            try {
                const elMap = {};
                const prevDoc = global.document;
                const prevGlobalPopCore = global.PopCore;
                const prevGlobalPopUI = global.PopUI;
                try {
                    const mockDoc = createMockDocument({
                        elements: elMap,
                        autoCreateElements: true,
                        defaultTag: 'DIV'
                    });
                    global.document = mockDoc;

                    let diagnoseCalls = 0;
                    let resolveDiagnose;
                    global.PopCore = Object.assign({}, PopCore, {
                        diagnose: async () => {
                            diagnoseCalls++;
                            return new Promise(resolve => {
                                resolveDiagnose = () => resolve({ error: null, stages: [], firstFailedStage: null, warnings: [] });
                            });
                        }
                    });

                    let generateCalls = 0;
                    let resolveGenerate;
                    global.PopCore.generateTestSignature = async () => {
                        generateCalls++;
                        return new Promise(resolve => {
                            resolveGenerate = () => resolve({ reqDigest: 'd', signature: 's', pubkeyPem: 'p' });
                        });
                    };
                    global.PopUI = PopUI;

                    delete require.cache[require.resolve('../js/app.js')];
                    require('../js/app.js');
                    if (mockDoc.listeners['DOMContentLoaded']) {
                        mockDoc.listeners['DOMContentLoaded']();
                    }

                    const btnDiag = elMap['btn-diagnose'];
                    const btnGen = elMap['btn-generate-test'];

                    // Test btn-diagnose concurrency guard
                    let diagDisabledDuring = false;
                    const pDiag1 = btnDiag.listeners['click']();
                    diagDisabledDuring = btnDiag.disabled === true;
                    const pDiag2 = btnDiag.listeners['click'](); // second click should be ignored
                    if (typeof resolveDiagnose === 'function') resolveDiagnose();
                    await pDiag1;
                    await pDiag2;
                    const diagReEnabledAfter = btnDiag.disabled === false;

                    // Test btn-generate-test concurrency guard
                    elMap['req-url'].value = 'https://api.example.com/v1/tx';
                    let genDisabledDuring = false;
                    const pGen1 = btnGen.listeners['click']();
                    genDisabledDuring = btnGen.disabled === true;
                    const pGen2 = btnGen.listeners['click'](); // second click should be ignored
                    if (typeof resolveGenerate === 'function') resolveGenerate();
                    await pGen1;
                    await pGen2;
                    const genReEnabledAfter = btnGen.disabled === false;

                    if (
                        diagDisabledDuring &&
                        diagnoseCalls === 1 &&
                        diagReEnabledAfter &&
                        genDisabledDuring &&
                        generateCalls === 1 &&
                        genReEnabledAfter
                    ) {
                        buttonConcurrencyOk = true;
                    }
                } finally {
                    global.document = prevDoc;
                    global.PopCore = prevGlobalPopCore;
                    global.PopUI = prevGlobalPopUI;
                }
            } catch (e) {
                console.log("Error in buttonConcurrencyOk:", e);
            }

            if (helpersOk && slotIsolationOk && buttonConcurrencyOk) {
                passed++;
            } else {
                console.log(`[FAIL] slot-metadata-and-button-concurrency: helpersOk=${helpersOk}, slotIsolationOk=${slotIsolationOk}, buttonConcurrencyOk=${buttonConcurrencyOk}`);
                failed++;
            }
        }

        // 48) Regression tests for Top 5 Senior Review Refactorings:
        // (1) BFS stateCache multi-path preservation at depth 2-3 (indistinguishable combo hypotheses)
        // (2) ASN.1 DER negative INTEGER (MSB >= 0x80 without 0x00 prefix) rejection
        // (3) Stage 1 whitespace-only URL/Pubkey, Stage 4 prefix-only reqDigest ('sha256='), and generateTestSignature normalization/validation
        // (4) Shell tokenizer double-quoted $(...) with inner quotes, special shell vars ($1, $?, $@), and \UHHHHHHHH escapes
        // (5) JSON EOF error location fallback, nested unclosed brace/bracket hint, Unicode unquoted key, and astral surrogate width
        {
            let bfsComboIndistOk = false;
            let derNegativeRejectedOk = false;
            let stageAndGenValidationOk = false;
            let curlTokenizerEdgeOk = false;
            let jsonErrorEdgeOk = false;

            // (1) BFS depth-2 indistinguishable combo: (query-sorted + method-lowercase) vs (query-reverse + method-lowercase)
            try {
                const comboCanonical = ["post", "api.example.com", "/v1/tx", "a=1&b=2", baseBodyHash, nonce, ts].join('\n');
                const comboSig = toBase64Url(await signRaw(comboCanonical));
                const comboDiag = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx?b=2&a=1",
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: comboSig,
                    pubkeyPem: dynPubkeyPem,
                    evalTime: Number(ts),
                    reqDigest: `sha256=${baseBodyHash}`
                });
                const comboSet = comboDiag.hypothesisResult &&
                    comboDiag.hypothesisResult.type === 'found' &&
                    comboDiag.hypothesisResult.sets &&
                    comboDiag.hypothesisResult.sets[0];
                const comboIds = comboSet && comboSet.type === 'indistinguishable'
                    ? comboSet.items.map(it => it.idStr).sort().join('|')
                    : '';
                bfsComboIndistOk =
                    comboSet &&
                    comboSet.type === 'indistinguishable' &&
                    comboIds === 'method-lowercase,query-reverse|method-lowercase,query-sorted';
            } catch (e) {
                console.log("Error in bfsComboIndistOk:", e);
            }

            // (2) ASN.1 DER negative INTEGER rejection (MSB >= 0x80 without leading 0x00)
            try {
                const negDerBytes = new Uint8Array(6 + 64);
                negDerBytes[0] = 0x30;
                negDerBytes[1] = 68;
                negDerBytes[2] = 0x02;
                negDerBytes[3] = 32;
                negDerBytes[4] = 0x80; // negative two's complement MSB set without 0x00 prefix
                negDerBytes[36] = 0x02;
                negDerBytes[37] = 32;
                negDerBytes[38] = 0x01;
                const negParsed = PopCore.parseDerSignature(negDerBytes);
                const negRaw = PopCore.derToRaw(negDerBytes);
                const negInspected = PopCore.inspectSignature(PopCore.base64UrlEncodeBytes(negDerBytes));
                derNegativeRejectedOk =
                    Boolean(negParsed && negParsed.ok === false) &&
                    negRaw === null &&
                    negInspected.ok === false &&
                    negInspected.format === 'invalid' &&
                    negInspected.error &&
                    negInspected.error.code === 'INVALID_DER';
            } catch (e) {
                console.log("Error in derNegativeRejectedOk:", e);
            }

            // (3) Stage 1 whitespace-only URL/Pubkey, Stage 4 prefix-only reqDigest ('sha256='), and generateTestSignature validation
            try {
                const wsUrlDiag = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "   ",
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem
                });
                const wsPubDiag = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx",
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem: "   \n  "
                });
                const prefixOnlyDiag = await PopCore.diagnose({
                    method: "POST",
                    urlStr: "https://api.example.com/v1/tx?a=1",
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem,
                    evalTime: Number(ts),
                    reqDigest: "sha256="
                });
                const genSpaced = await PopCore.generateTestSignature({
                    method: " POST ",
                    urlStr: "  https://api.example.com/v1/tx?a=1  ",
                    bodyStr: baseBody,
                    nonce: " n-space ",
                    timestampStr: ` ${ts} `
                });
                const diagFromGenSpaced = await PopCore.diagnose({
                    method: " POST ",
                    urlStr: "  https://api.example.com/v1/tx?a=1  ",
                    bodyStr: baseBody,
                    nonce: " n-space ",
                    timestampStr: ` ${ts} `,
                    signature: genSpaced.signature,
                    pubkeyPem: genSpaced.pubkeyPem,
                    reqDigest: genSpaced.reqDigest,
                    evalTime: Number(ts)
                });
                let badTsRejected = false;
                try {
                    await PopCore.generateTestSignature({
                        method: "POST",
                        urlStr: "https://api.example.com/v1/tx",
                        bodyStr: baseBody,
                        nonce: "n1",
                        timestampStr: "not-a-number"
                    });
                } catch (err) {
                    badTsRejected = Boolean(err && err.code === PopCore.ERROR_CODES.INVALID_TIMESTAMP);
                }

                stageAndGenValidationOk =
                    wsUrlDiag.firstFailedStage === 1 &&
                    wsUrlDiag.stages[0].code === PopCore.STAGE_CODES.STAGE1_MISSING_FIELDS &&
                    wsPubDiag.firstFailedStage === 1 &&
                    wsPubDiag.stages[0].code === PopCore.STAGE_CODES.STAGE1_MISSING_PUBKEY &&
                    prefixOnlyDiag.stages[3].status === 'fail' &&
                    prefixOnlyDiag.stages[3].code === PopCore.STAGE_CODES.STAGE4_MISSING_DIGEST &&
                    diagFromGenSpaced.error === null &&
                    diagFromGenSpaced.firstFailedStage === null &&
                    badTsRejected;
            } catch (e) {
                console.log("Error in stageAndGenValidationOk:", e);
            }

            // (4) Shell tokenizer double-quoted $(...) with inner quotes, special vars ($1, $?), and \UHHHHHHHH
            try {
                const subQuoteCurl = parseCurl('curl "https://api.example.com/v1/tx" -H "X-FIDO2-Nonce: $(echo "abc")" -d \'{"a":1}\'');
                const specialVarCurl = parseCurl('curl "https://api.example.com/v1/tx?x=$1&y=$?"');
                const ansiUCurl = parseCurl("curl 'https://api.example.com/v1/tx' -d $'{\"emoji\":\"\\U0001F600\"}'");
                curlTokenizerEdgeOk =
                    subQuoteCurl.ok === false &&
                    !subQuoteCurl.unsupported.some(u => u.code === 'UNCLOSED_QUOTE') &&
                    subQuoteCurl.unsupported.some(u => u.code === 'SHELL_EXPANSION_UNSUPPORTED') &&
                    subQuoteCurl.inputs.bodyStr === '{"a":1}' &&
                    specialVarCurl.ok === false &&
                    specialVarCurl.unsupported.some(u => u.code === 'SHELL_EXPANSION_UNSUPPORTED') &&
                    ansiUCurl.ok === true &&
                    ansiUCurl.inputs.bodyStr === '{"emoji":"😀"}';
            } catch (e) {
                console.log("Error in curlTokenizerEdgeOk:", e);
            }

            // (5) JSON EOF error location fallback, nested unclosed brace/bracket hint, Unicode unquoted key, and astral surrogate width
            try {
                const eofJson = '{\n  "amount":';
                const eofLoc = PopCore.extractJsonErrorLocation(new SyntaxError('Unexpected end of JSON input'), eofJson);
                const nestedBraceHint = PopCore.detectJsonErrorHint(new SyntaxError('Unexpected end of JSON input'), '{"a": {"b": 1}');
                const nestedBracketHint = PopCore.detectJsonErrorHint(new SyntaxError('Unexpected end of JSON input'), '[[1, 2]');
                const korUnquotedKeyHint = PopCore.detectJsonErrorHint(new SyntaxError('Unexpected token'), '{이름: "홍길동"}');
                const emojiSnippet = PopUI.formatJsonErrorSnippet({
                    cleanMessage: 'Unexpected token',
                    line: 1,
                    column: 6, // '{"😀":' -> index 0:'{', 1:'"', 2..3:'😀', 4:'"', 5:':' (column 6)
                    problemLine: '{"😀": 1}'
                });
                const pointerLine = emojiSnippet.split('\n').pop();
                jsonErrorEdgeOk =
                    eofLoc.line === 2 &&
                    eofLoc.column === 12 &&
                    eofLoc.problemLine === '  "amount":' &&
                    nestedBraceHint && nestedBraceHint.hintCode === PopCore.JSON_HINT_CODES.MISSING_CLOSE_BRACE &&
                    nestedBracketHint && nestedBracketHint.hintCode === PopCore.JSON_HINT_CODES.MISSING_CLOSE_BRACKET &&
                    korUnquotedKeyHint && korUnquotedKeyHint.hintCode === PopCore.JSON_HINT_CODES.UNQUOTED_KEY &&
                    pointerLine === '     ▲'; // 1 ('{') + 1 ('"') + 2 ('😀') + 1 ('"') = 5 spaces before ▲
            } catch (e) {
                console.log("Error in jsonErrorEdgeOk:", e);
            }

            if (bfsComboIndistOk && derNegativeRejectedOk && stageAndGenValidationOk && curlTokenizerEdgeOk && jsonErrorEdgeOk) {
                passed++;
            } else {
                console.log(`[FAIL] senior-review-top5-regressions: bfsComboIndistOk=${bfsComboIndistOk}, derNegativeRejectedOk=${derNegativeRejectedOk}, stageAndGenValidationOk=${stageAndGenValidationOk}, curlTokenizerEdgeOk=${curlTokenizerEdgeOk}, jsonErrorEdgeOk=${jsonErrorEdgeOk}`);
                failed++;
            }
        }

        // 49) 5-Step Refactoring Roadmap Verification:
        // (1) Declarative hypothesis metadata (priority, targetKind) & OCP 15th hypothesis extensibility without touching diagnose.js/render.js
        // (2) MAX_INPUT_LENGTH guard (ERR_INPUT_TOO_LARGE) on diagnose() and generateTestSignature()
        // (3) Headerless Raw Base64 PKCS#8 (0x30 ... 0x02 0x01 0x00) & SEC1 (0x30 ... 0x02 0x01 0x01) Private Key ASN.1 Detection
        {
            let ocpHypothesisOk = false;
            let maxInputGuardOk = false;
            let headerlessPrivKeyOk = false;

            // (1) Declarative hypothesis metadata + 15th hypothesis OCP check
            try {
                const validTargetKinds = new Set(['canonical', 'body', 'signature']);
                const allHaveMetadata = PopCore.HYPOTHESES.every(h =>
                    h.priority &&
                    typeof h.priority.stage4 === 'number' &&
                    typeof h.priority.stage5 === 'number' &&
                    validTargetKinds.has(h.targetKind)
                );

                const custom15thHyp = {
                    id: 'custom-15th-body-prefix',
                    label: '커스텀 15번째 본문 가설 (OCP 검증)',
                    tag: '[Body]',
                    stage: 'both',
                    priority: { stage4: 1, stage5: 1 },
                    targetKind: 'body',
                    cause: '서명 당시 본문 앞에 커스텀 접두사가 포함되어 계산되었습니다.',
                    solution: '요청 본문과 서명 당시 본문 구성 방식을 일치시키세요.',
                    async apply(req) {
                        if (req.rawBody && !req.rawBody.startsWith('OCP:')) {
                            const nextBody = 'OCP:' + req.rawBody;
                            const nextHash = await PopCore.hashString(nextBody);
                            return { ...req, rawBody: nextBody, bodyHash: nextHash };
                        }
                        return req;
                    }
                };

                PopCore.HYPOTHESES.push(custom15thHyp);
                try {
                    const ocpSignedBody = 'OCP:' + baseBody;
                    const ocpSignedHash = await PopCore.hashString(ocpSignedBody);
                    const ocpCanonical = ["POST", "api.example.com", "/v1/tx", "a=1", ocpSignedHash, nonce, ts].join('\n');
                    const ocpSig = toBase64Url(await signRaw(ocpCanonical));

                    const ocpDiag = await PopCore.diagnose({
                        method: "POST",
                        urlStr: "https://api.example.com/v1/tx?a=1",
                        bodyStr: baseBody,
                        nonce,
                        timestampStr: ts,
                        signature: ocpSig,
                        pubkeyPem: dynPubkeyPem,
                        evalTime: Number(ts),
                        reqDigest: `sha256=${ocpSignedHash}`
                    });

                    const foundSet = ocpDiag.hypothesisResult &&
                        ocpDiag.hypothesisResult.type === 'found' &&
                        ocpDiag.hypothesisResult.sets &&
                        ocpDiag.hypothesisResult.sets[0];

                    let renderedBodyDiffOk = false;
                    if (foundSet) {
                        const prevDoc = global.document;
                        if (typeof window === 'undefined') {
                            global.document = createMockDocument();
                        }
                        try {
                            const hBoxDiff = createMockElement('DIV');
                            PopUI.renderSingleHypothesisSet(hBoxDiff, foundSet, ocpDiag);
                            const hBoxSame = createMockElement('DIV');
                            PopUI.renderSingleHypothesisSet(hBoxSame, foundSet, { ...ocpDiag, expectedCanonical: foundSet.canonical });
                            renderedBodyDiffOk =
                                typeof PopUI.renderSingleHypothesisSet === 'function' &&
                                hBoxDiff.textContent.includes('커스텀 15번째 본문 가설 (OCP 검증)') &&
                                hBoxSame.textContent.includes('원인은 본문(Body) 또는 다이제스트 계산 방식의 차이입니다');
                        } finally {
                            if (typeof window === 'undefined') {
                                global.document = prevDoc;
                            }
                        }
                    }

                    ocpHypothesisOk =
                        allHaveMetadata &&
                        Boolean(foundSet && foundSet.type === 'match' && foundSet.items[0].idStr === 'custom-15th-body-prefix') &&
                        Boolean(foundSet && foundSet.items[0].history[0].targetKind === 'body') &&
                        renderedBodyDiffOk;
                } finally {
                    const idx = PopCore.HYPOTHESES.indexOf(custom15thHyp);
                    if (idx !== -1) PopCore.HYPOTHESES.splice(idx, 1);
                }
            } catch (e) {
                console.log("Error in ocpHypothesisOk:", e);
            }

            // (2) MAX_INPUT_LENGTH guard on diagnose() and generateTestSignature()
            try {
                const oversizedStr = 'x'.repeat(PopCore.MAX_INPUT_LENGTH + 1);
                const diagBigBody = await PopCore.diagnose({
                    method: 'POST',
                    urlStr: 'https://api.example.com/v1/tx',
                    bodyStr: oversizedStr,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem
                });
                const diagBigUrl = await PopCore.diagnose({
                    method: 'POST',
                    urlStr: 'https://api.example.com/' + oversizedStr,
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem
                });

                let genBigBodyRejected = false;
                try {
                    await PopCore.generateTestSignature({
                        method: 'POST',
                        urlStr: 'https://api.example.com/v1/tx',
                        bodyStr: oversizedStr,
                        nonce,
                        timestampStr: ts
                    });
                } catch (err) {
                    genBigBodyRejected = Boolean(err && err.code === PopCore.ERROR_CODES.INPUT_TOO_LARGE);
                }

                let genBigUrlRejected = false;
                try {
                    await PopCore.generateTestSignature({
                        method: 'POST',
                        urlStr: 'https://api.example.com/' + oversizedStr,
                        bodyStr: baseBody,
                        nonce,
                        timestampStr: ts
                    });
                } catch (err) {
                    genBigUrlRejected = Boolean(err && err.code === PopCore.ERROR_CODES.INPUT_TOO_LARGE);
                }

                maxInputGuardOk =
                    PopCore.ERROR_CODES.INPUT_TOO_LARGE === 'ERR_INPUT_TOO_LARGE' &&
                    Boolean(diagBigBody.error && diagBigBody.error.code === 'ERR_INPUT_TOO_LARGE') &&
                    Boolean(diagBigUrl.error && diagBigUrl.error.code === 'ERR_INPUT_TOO_LARGE') &&
                    genBigBodyRejected &&
                    genBigUrlRejected;
            } catch (e) {
                console.log("Error in maxInputGuardOk:", e);
            }

            // (3) Headerless Raw Base64 PKCS#8 (0x30 ... 0x02 0x01 0x00) & SEC1 (0x30 ... 0x02 0x01 0x01) Private Key ASN.1 Detection
            try {
                const toStandardB64 = (bytes) => _btoa(PopCore.bytesToBinaryString(bytes));

                // Short-form PKCS#8 PrivateKeyInfo (SEQUENCE -> INTEGER 0 -> ...)
                const pkcs8ShortBytes = new Uint8Array([
                    0x30, 0x26,
                    0x02, 0x01, 0x00, // version 0 (PKCS#8 PrivateKeyInfo)
                    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                    0x04, 0x0c, 0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05
                ]);
                const rawPkcs8B64 = toStandardB64(pkcs8ShortBytes);

                // Long-form (> 127 bytes) PKCS#8 PrivateKeyInfo (0x30 0x81 0x85 0x02 0x01 0x00 ...)
                const pkcs8LongBytes = new Uint8Array(3 + 133);
                pkcs8LongBytes[0] = 0x30;
                pkcs8LongBytes[1] = 0x81;
                pkcs8LongBytes[2] = 133;
                pkcs8LongBytes[3] = 0x02;
                pkcs8LongBytes[4] = 0x01;
                pkcs8LongBytes[5] = 0x00;
                const rawPkcs8LongB64 = toStandardB64(pkcs8LongBytes);

                // RFC 5915 SEC1 ECPrivateKey (SEQUENCE -> INTEGER 1 -> OCTET STRING ...)
                const sec1Bytes = new Uint8Array([
                    0x30, 0x25,
                    0x02, 0x01, 0x01, // version 1 (SEC1 ECPrivateKey)
                    0x04, 0x20,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                ]);
                const rawSec1B64 = toStandardB64(sec1Bytes);

                // Strip PEM headers from valid SPKI public key to ensure no false positive
                const validHeaderlessSpki = pubkeyPem
                    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
                    .replace(/-----END PUBLIC KEY-----/g, '')
                    .trim();

                const markerChecksOk =
                    PopCore.containsPrivateKeyMarker(rawPkcs8B64) === true &&
                    PopCore.containsPrivateKeyMarker(rawPkcs8LongB64) === true &&
                    PopCore.containsPrivateKeyMarker(rawSec1B64) === true &&
                    PopCore.containsPrivateKeyMarker(validHeaderlessSpki) === false;

                const spkiPkcs8 = PopCore.extractPublicKeySpkiBytes(rawPkcs8B64);
                const spkiSec1 = PopCore.extractPublicKeySpkiBytes(rawSec1B64);
                const extractChecksOk =
                    spkiPkcs8.ok === false &&
                    spkiPkcs8.code === 'PRIVATE_KEY_REJECTED' &&
                    spkiPkcs8.warnings.some(w => w.code === 'PRIVATE_KEY_INPUT') &&
                    spkiSec1.ok === false &&
                    spkiSec1.code === 'PRIVATE_KEY_REJECTED' &&
                    spkiSec1.warnings.some(w => w.code === 'PRIVATE_KEY_INPUT');

                const inspectPkcs8 = await PopCore.inspectPublicKey(rawPkcs8B64);
                const inspectSec1 = await PopCore.inspectPublicKey(rawSec1B64);
                const inspectChecksOk =
                    inspectPkcs8.ok === false &&
                    inspectPkcs8.error && inspectPkcs8.error.code === 'PRIVATE_KEY_REJECTED' &&
                    inspectSec1.ok === false &&
                    inspectSec1.error && inspectSec1.error.code === 'PRIVATE_KEY_REJECTED';

                const diagPkcs8 = await PopCore.diagnose({
                    method: 'POST',
                    urlStr: 'https://api.example.com/v1/tx?a=1',
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem: rawPkcs8B64,
                    evalTime: Number(ts)
                });
                const diagSec1 = await PopCore.diagnose({
                    method: 'POST',
                    urlStr: 'https://api.example.com/v1/tx?a=1',
                    bodyStr: baseBody,
                    nonce,
                    timestampStr: ts,
                    signature: validSig,
                    pubkeyPem: rawSec1B64,
                    evalTime: Number(ts)
                });
                const diagChecksOk =
                    Boolean(diagPkcs8.error && diagPkcs8.error.code === PopCore.ERROR_CODES.INVALID_PUBKEY && diagPkcs8.error.causeCode === 'PRIVATE_KEY_REJECTED') &&
                    diagPkcs8.warnings.some(w => w.code === 'PRIVATE_KEY_INPUT') &&
                    Boolean(diagSec1.error && diagSec1.error.code === PopCore.ERROR_CODES.INVALID_PUBKEY && diagSec1.error.causeCode === 'PRIVATE_KEY_REJECTED') &&
                    diagSec1.warnings.some(w => w.code === 'PRIVATE_KEY_INPUT');

                headerlessPrivKeyOk = markerChecksOk && extractChecksOk && inspectChecksOk && diagChecksOk;
            } catch (e) {
                console.log("Error in headerlessPrivKeyOk:", e);
            }

            if (ocpHypothesisOk && maxInputGuardOk && headerlessPrivKeyOk) {
                passed++;
            } else {
                console.log(`[FAIL] roadmap-5step-regressions: ocpHypothesisOk=${ocpHypothesisOk}, maxInputGuardOk=${maxInputGuardOk}, headerlessPrivKeyOk=${headerlessPrivKeyOk}`);
                failed++;
            }
        }
    }

    const total = passed + failed + skipped;
    console.log(`\nTests completed. Passed: ${passed}, Failed: ${failed}, Skipped: ${skipped} (Total: ${total})`);
    if (failed > 0 && typeof process !== 'undefined') process.exitCode = 1;
}

if (typeof window !== 'undefined') {
    window.runTests = runTests;
} else {
    runTests();
}
