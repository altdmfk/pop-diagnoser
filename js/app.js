(function (root) {
    if (typeof document === 'undefined') return;

    const DEFAULT_FALLBACK_PUBKEY =
        '-----BEGIN PUBLIC KEY-----\n' +
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgHsBt/wr3i0Y+5QEk7rVWqy/WiAp\n' +
        '2BE0Fh98ukGLUupf0yKXbYwjrKKNGb+RWKp8kXdEVAYG2ExSBg3TLqgM6g==\n' +
        '-----END PUBLIC KEY-----\n';

    const FORM_FIELD_IDS = [
        'req-method',
        'req-url',
        'req-body',
        'req-nonce',
        'req-timestamp',
        'req-signature',
        'req-digest',
        'req-pubkey',
        'eval-timestamp'
    ];

    document.addEventListener('DOMContentLoaded', () => {
        const {
            showToast,
            setPlaceholder,
            setOverheadVisible,
            renderResult,
            renderMissingUrlWarning,
            renderGenerateSuccess,
            renderGenerateError,
            initMemorySlots,
            initTabs,
            initInspector,
            refreshInspector,
            initImporter
        } = root.PopUI;

        initTabs();
        initMemorySlots();
        if (typeof initInspector === 'function') {
            initInspector();
        }
        if (typeof initImporter === 'function') {
            initImporter();
        }

        const evalTimeInput = document.getElementById('eval-timestamp');
        document.getElementById('btn-now').addEventListener('click', () => {
            evalTimeInput.value = Math.floor(Date.now() / 1000);
        });
        evalTimeInput.value = Math.floor(Date.now() / 1000);

        const loadDemo = (fixtureName, showFeedback = false) => {
            if (!root.FIXTURES || !root.FIXTURES.cases) {
                showToast('⚠️ 데모 데이터를 불러오지 못했습니다. (fixtures.js 확인 필요)', true);
                return;
            }
            const fixture = root.FIXTURES.cases.find(c => c.name === fixtureName);
            if (!fixture) {
                showToast('⚠️ 해당 데모 케이스를 찾을 수 없습니다.', true);
                return;
            }

            const setVal = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.value = val;
            };

            setVal('req-method', fixture.method);
            setVal('req-url', `https://${fixture.host}${fixture.path}?${fixture.query}`);
            setVal('req-body', fixture.body);
            setVal('req-nonce', fixture.nonce);
            setVal('req-timestamp', fixture.timestamp);
            setVal('req-signature', fixture.signature);
            setVal('req-digest', fixture.digest || '');
            setVal('req-pubkey', root.FIXTURES.public_key || DEFAULT_FALLBACK_PUBKEY);

            if (evalTimeInput) evalTimeInput.value = root.FIXTURES.eval_time;
            if (typeof refreshInspector === 'function') refreshInspector();

            if (showFeedback) {
                showToast('✅ 선택하신 예시 데이터가 모든 탭에 자동 입력되었습니다.');
                const panel = document.getElementById('result-panel');
                setPlaceholder(panel, [
                    '예시 데이터가 갱신되었습니다.',
                    "확인을 위해 '진단 시작' 버튼을 눌러주세요."
                ]);
                setOverheadVisible(false);
            }
        };

        document.getElementById('btn-demo-valid').addEventListener('click', () => loadDemo('valid', true));
        document.getElementById('btn-demo-unsorted').addEventListener('click', () => loadDemo('query-sorted', true));
        document.getElementById('btn-demo-method').addEventListener('click', () => loadDemo('method-lowercase', true));
        document.getElementById('btn-demo-expired').addEventListener('click', () => loadDemo('timestamp-fail', true));

        document.getElementById('btn-clear-all').addEventListener('click', () => {
            FORM_FIELD_IDS.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
            const panel = document.getElementById('result-panel');
            setPlaceholder(panel, ["왼쪽에서 데이터를 입력하고 '진단 시작'을 눌러주세요."]);
            setOverheadVisible(false);
            if (typeof refreshInspector === 'function') refreshInspector();
        });

        loadDemo('valid');

        document.getElementById('btn-generate-test').addEventListener('click', async () => {
            const panel = document.getElementById('result-panel');
            try {
                const inputs = {
                    method: document.getElementById('req-method').value || 'POST',
                    urlStr: document.getElementById('req-url').value,
                    bodyStr: document.getElementById('req-body').value.replace(/\r\n/g, '\n'),
                    nonce: document.getElementById('req-nonce').value || 'n-test',
                    timestampStr: document.getElementById('req-timestamp').value || Math.floor(Date.now() / 1000).toString()
                };

                if (!inputs.urlStr) {
                    renderMissingUrlWarning(panel);
                    return;
                }

                const gen = await root.PopCore.generateTestSignature(inputs);

                document.getElementById('req-digest').value = gen.reqDigest;
                document.getElementById('req-signature').value = gen.signature;
                document.getElementById('req-pubkey').value = gen.pubkeyPem;

                evalTimeInput.value = inputs.timestampStr;
                document.getElementById('req-timestamp').value = inputs.timestampStr;
                document.getElementById('req-nonce').value = inputs.nonce;
                document.getElementById('req-method').value = inputs.method;

                if (typeof refreshInspector === 'function') refreshInspector();
                showToast('✨ 새로운 서명이 생성되어 적용되었습니다!');
                renderGenerateSuccess(panel);
                setOverheadVisible(false);
            } catch (e) {
                renderGenerateError(panel, e);
            }
        });

        document.getElementById('btn-diagnose').addEventListener('click', async () => {
            const panel = document.getElementById('result-panel');
            panel.classList.remove('empty');
            panel.textContent = '진단 중...';

            const spacedFields = [];
            const cleanNoSpace = (name, val) => {
                if (/\s/.test(val)) {
                    spacedFields.push(name);
                    return val.replace(/\s/g, '');
                }
                return val;
            };

            const inputs = {
                method: cleanNoSpace('HTTP 메서드', document.getElementById('req-method').value),
                urlStr: document.getElementById('req-url').value.trim(),
                bodyStr: document.getElementById('req-body').value.replace(/\r\n/g, '\n'),
                nonce: cleanNoSpace('Nonce', document.getElementById('req-nonce').value),
                timestampStr: cleanNoSpace('Timestamp', document.getElementById('req-timestamp').value),
                signature: cleanNoSpace('Signature', document.getElementById('req-signature').value),
                pubkeyPem: document.getElementById('req-pubkey').value.trim(),
                reqDigest: cleanNoSpace('Body-Digest', document.getElementById('req-digest').value),
                evalTime: parseInt(evalTimeInput.value, 10)
            };

            try {
                const result = await root.PopCore.diagnose(inputs);
                if (spacedFields.length > 0) {
                    result.warnings.push({
                        message: `다음 입력값의 앞뒤나 중간에 잘못된 공백(띄어쓰기, 줄바꿈)이 포함되어 있어 제거 후 진단했습니다: ${spacedFields.join(', ')}`
                    });
                }
                renderResult(result);

                if (!result.error && result.firstFailedStage === null) {
                    setOverheadVisible(true);
                } else {
                    setOverheadVisible(false);
                }
            } catch (e) {
                panel.textContent = `오류 발생: ${e.message}`;
            }
        });
    });
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this));
