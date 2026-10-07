const PopCore = require('./diagnose-core.js');
const fixtures = require('./fixtures.js');

async function runTests() {
    const pubkeyPem = fixtures.public_key;
    const evalTime = fixtures.eval_time;
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
            reqDigest: c.digest,
            credentialId: "dummy-credential-id"
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
            if (c.expected.idStr && result.hypothesisResult.type === 'found') {
                const matchedSet = result.hypothesisResult.sets[0];
                if (c.expected.type === 'match' && matchedSet && matchedSet.item) {
                    if (matchedSet.item.idStr !== c.expected.idStr) {
                        console.log(`[FAIL] ${c.name}: Expected idStr ${c.expected.idStr}, got ${matchedSet.item.idStr}`);
                        ok = false;
                    }
                }
            }
        }

        if (ok) passed++; else failed++;
    }

    // Input error tests
    const inputTests = [
        { name: "empty-inputs", inputs: {}, expectError: true },
        { name: "bad-url", inputs: { method: "POST", urlStr: "not-a-url", nonce: "1", timestampStr: "1", signature: "A", pubkeyPem: "A" }, expectError: true },
        { name: "bad-pubkey", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "A", pubkeyPem: "bad-pem" }, expectError: true },
        { name: "bad-signature", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "+++", pubkeyPem: pubkeyPem }, expectError: true },
        { name: "bad-timestamp", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "abc", signature: "A", pubkeyPem: pubkeyPem }, expectError: true },
        { name: "bad-signature-length", inputs: { method: "POST", urlStr: "https://a.com/", nonce: "1", timestampStr: "1", signature: "abcde", pubkeyPem: pubkeyPem }, expectError: true },
        { name: "missing-nonce", inputs: { method: "POST", urlStr: "https://a.com/", timestampStr: "1", signature: "A", pubkeyPem: pubkeyPem }, expectError: false },
        { name: "bad-json", inputs: { method: "POST", urlStr: "https://a.com/", bodyStr: "{bad json}", nonce: "1", timestampStr: "1", signature: "A", pubkeyPem: pubkeyPem }, expectError: false },
        { name: "long-input", inputs: { method: "POST", urlStr: "https://a.com/", bodyStr: "A".repeat(100000), nonce: "1", timestampStr: "1", signature: "A", pubkeyPem: pubkeyPem }, expectError: false }
    ];

    for (let t of inputTests) {
        const result = await PopCore.diagnose(t.inputs);
        if (t.expectError && !result.error) {
            console.log(`[FAIL] ${t.name}: Expected error, got none`);
            failed++;
        } else {
            passed++;
        }
    }

    console.log(`\nTests completed. Passed: ${passed}, Failed: ${failed}`);
}

runTests();
