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
            DEMO_SAMPLES,
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
            resetInspector,
            refreshInspector,
            initImporter,
            readRequestBody,
            readRequestContentType,
            setRawTextareaValue
        } = root.PopUI;

        const getBodyValue = () => {
            const bodyEl = document.getElementById('req-body');
            if (!bodyEl) return '';
            return typeof readRequestBody === 'function' ? readRequestBody(bodyEl) : bodyEl.value;
        };

        const getContentType = () => {
            const bodyEl = document.getElementById('req-body');
            if (typeof readRequestContentType === 'function') {
                return readRequestContentType(bodyEl);
            }
            return (bodyEl && typeof bodyEl._contentType === 'string') ? bodyEl._contentType : '';
        };

        initTabs();
        initMemorySlots();
        if (typeof initInspector === 'function') {
            initInspector();
        }
        if (typeof initImporter === 'function') {
            initImporter();
        }

        const reqBodyEl = document.getElementById('req-body');
        if (reqBodyEl && typeof reqBodyEl.addEventListener === 'function') {
            reqBodyEl.addEventListener('paste', (e) => {
                if (e && e.clipboardData && typeof e.clipboardData.getData === 'function') {
                    const pasted = e.clipboardData.getData('text/plain');
                    if (typeof pasted === 'string' && pasted.includes('\r\n')) {
                        reqBodyEl._rawBody = pasted;
                    }
                }
            });
        }

        const evalTimeInput = document.getElementById('eval-timestamp');
        document.getElementById('btn-now').addEventListener('click', () => {
            evalTimeInput.value = Math.floor(Date.now() / 1000);
        });
        evalTimeInput.value = Math.floor(Date.now() / 1000);

        const btnFillPubkey = document.getElementById('btn-fill-sample-pubkey');
        if (btnFillPubkey) {
            btnFillPubkey.addEventListener('click', () => {
                const pkEl = document.getElementById('req-pubkey');
                if (pkEl) {
                    pkEl.value = (DEMO_SAMPLES && DEMO_SAMPLES.public_key) || DEFAULT_FALLBACK_PUBKEY;
                    showToast('🔑 예시 공개키가 입력칸에 채워졌습니다.');
                    if (typeof resetInspector === 'function') resetInspector();
                }
            });
        }

        const loadDemo = (fixtureName, showFeedback = false) => {
            if (!DEMO_SAMPLES || !DEMO_SAMPLES.cases) {
                showToast('⚠️ 데모 데이터를 불러오지 못했습니다. (samples.js 확인 필요)', true);
                return;
            }
            const fixture = DEMO_SAMPLES.cases.find(c => c.name === fixtureName);
            if (!fixture) {
                showToast('⚠️ 해당 데모 케이스를 찾을 수 없습니다.', true);
                return;
            }

            const setVal = (id, val) => {
                const el = document.getElementById(id);
                if (!el) return;
                if (id === 'req-body' && typeof setRawTextareaValue === 'function') {
                    setRawTextareaValue(el, val);
                } else {
                    el.value = val;
                    delete el._rawBody;
                }
            };

            setVal('req-method', fixture.method);
            setVal('req-url', `https://${fixture.host}${fixture.path}?${fixture.query}`);
            setVal('req-body', fixture.body);
            setVal('req-nonce', fixture.nonce);
            setVal('req-timestamp', fixture.timestamp);
            setVal('req-signature', fixture.signature);
            setVal('req-digest', fixture.digest || '');
            setVal('req-pubkey', DEMO_SAMPLES.public_key || DEFAULT_FALLBACK_PUBKEY);

            if (evalTimeInput) evalTimeInput.value = DEMO_SAMPLES.eval_time;
            if (typeof resetInspector === 'function') resetInspector();

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

        const demoSelect = document.getElementById('demo-select');
        if (demoSelect) {
            demoSelect.addEventListener('change', () => {
                if (demoSelect.value) {
                    loadDemo(demoSelect.value, true);
                }
            });
        }

        document.getElementById('btn-clear-all').addEventListener('click', () => {
            FORM_FIELD_IDS.forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    el.value = '';
                    delete el._rawBody;
                    delete el._contentType;
                }
            });
            const curlInput = document.getElementById('curl-import-input');
            if (curlInput) {
                curlInput.value = '';
                delete curlInput._rawBody;
            }
            const statusBanner = document.getElementById('import-status-banner');
            if (statusBanner) statusBanner.classList.add('hidden');
            const applyNotice = document.getElementById('curl-apply-notice');
            if (applyNotice) applyNotice.classList.add('hidden');
            const panel = document.getElementById('result-panel');
            setPlaceholder(panel, ["왼쪽에서 데이터를 확인하고 '진단 시작'을 눌러주세요."]);
            setOverheadVisible(false);
            if (typeof resetInspector === 'function') resetInspector();
        });

        loadDemo('valid');

        const btnGenerate = document.getElementById('btn-generate-test');
        if (btnGenerate) {
            btnGenerate.addEventListener('click', async () => {
                if (btnGenerate.disabled) return;
                btnGenerate.disabled = true;
                const panel = document.getElementById('result-panel');
                try {
                    const inputs = {
                        method: document.getElementById('req-method').value || 'POST',
                        urlStr: document.getElementById('req-url').value,
                        bodyStr: getBodyValue(),
                        contentType: getContentType(),
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

                    if (typeof resetInspector === 'function') resetInspector();
                    showToast('✨ 새로운 서명이 생성되어 적용되었습니다!');
                    renderGenerateSuccess(panel, gen);
                    setOverheadVisible(false);
                } catch (e) {
                    renderGenerateError(panel, e);
                } finally {
                    btnGenerate.disabled = false;
                }
            });
        }

        const btnDiagnose = document.getElementById('btn-diagnose');
        if (btnDiagnose) {
            btnDiagnose.addEventListener('click', async () => {
                if (btnDiagnose.disabled) return;
                btnDiagnose.disabled = true;
                const panel = document.getElementById('result-panel');
                panel.classList.remove('empty');
                panel.textContent = '진단 중...';

                const inputs = {
                    method: document.getElementById('req-method').value,
                    urlStr: document.getElementById('req-url').value.trim(),
                    bodyStr: getBodyValue(),
                    contentType: getContentType(),
                    nonce: document.getElementById('req-nonce').value,
                    timestampStr: document.getElementById('req-timestamp').value,
                    signature: document.getElementById('req-signature').value,
                    pubkeyPem: document.getElementById('req-pubkey').value.trim(),
                    reqDigest: document.getElementById('req-digest').value,
                    evalTime: parseInt(evalTimeInput.value, 10)
                };

                try {
                    const result = await root.PopCore.diagnose(inputs);
                    renderResult(result);
                    if (typeof refreshInspector === 'function') {
                        await refreshInspector();
                    }

                    if (!result.error && result.firstFailedStage === null) {
                        setOverheadVisible(true);
                    } else {
                        setOverheadVisible(false);
                    }
                } catch (e) {
                    panel.textContent = `오류 발생: ${e.message}`;
                } finally {
                    btnDiagnose.disabled = false;
                }
            });
        }
    });
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this));
