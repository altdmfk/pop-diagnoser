(function (root, factory) {
    let deps;
    if (typeof module !== 'undefined' && module.exports) {
        deps = Object.assign(
            {},
            require('../core/profiles/paper.js'),
            require('../core/curlParser.js'),
            require('./render.js'),
            require('./inspector.js')
        );
    } else {
        deps = Object.assign({}, root.PopCore, root.PopUI);
    }
    const mod = factory(deps);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (deps) {
    const HDRS = (deps && deps.PaperProfile && deps.PaperProfile.headers) || {
        nonce: 'X-FIDO2-Nonce',
        timestamp: 'X-FIDO2-Timestamp',
        signature: 'X-FIDO2-Signature',
        digest: 'X-Body-Digest'
    };

    const FIELD_LABELS = {
        method: 'HTTP 메서드',
        urlStr: '요청 URL',
        bodyStr: '요청 본문(Body)',
        nonce: HDRS.nonce,
        timestampStr: HDRS.timestamp,
        signature: HDRS.signature,
        reqDigest: HDRS.digest
    };

    const TARGET_INPUT_MAP = [
        { key: 'method', id: 'req-method' },
        { key: 'urlStr', id: 'req-url' },
        { key: 'bodyStr', id: 'req-body' },
        { key: 'nonce', id: 'req-nonce' },
        { key: 'timestampStr', id: 'req-timestamp' },
        { key: 'signature', id: 'req-signature' },
        { key: 'reqDigest', id: 'req-digest' }
    ];

    function getFixturesObject() {
        if (typeof globalThis !== 'undefined' && globalThis.FIXTURES) return globalThis.FIXTURES;
        if (typeof window !== 'undefined' && window.FIXTURES) return window.FIXTURES;
        return null;
    }

    function formatFieldList(keys) {
        if (!keys || keys.length === 0) return '없음';
        return keys.map(k => FIELD_LABELS[k] || k).join(', ');
    }

    function renderImportStatus(container, parseResult) {
        if (!container || !parseResult) return;
        container.textContent = '';
        container.classList.remove('hidden');

        const box = document.createElement('div');
        box.className = parseResult.ok ? 'import-report import-report-ok' : 'import-report import-report-error';

        const title = document.createElement('strong');
        title.className = 'import-report-title';
        if (parseResult.ok) {
            const fmtLabel = parseResult.format === 'raw-http' ? 'Raw HTTP' : 'cURL';
            title.textContent = `📥 ${fmtLabel} 파싱 및 입력칸 채우기 완료`;
        } else {
            title.textContent = '❌ cURL / Raw HTTP 가져오기 중단 (지원하지 않는 옵션 또는 형식)';
        }
        box.appendChild(title);

        if (parseResult.ok) {
            const filledRow = document.createElement('div');
            filledRow.className = 'import-report-line';
            filledRow.textContent = `• 채워진 필드: ${formatFieldList(parseResult.filled)}`;
            box.appendChild(filledRow);

            if (parseResult.missing && parseResult.missing.length > 0) {
                const missingRow = document.createElement('div');
                missingRow.className = 'import-report-line import-line-warn';
                missingRow.textContent = `• 누락된 필수 항목(빈칸 처리됨): ${formatFieldList(parseResult.missing)}`;
                box.appendChild(missingRow);
            }

            const pubkeyNotice = document.createElement('div');
            pubkeyNotice.className = 'import-report-line import-line-info';
            pubkeyNotice.textContent = PUBKEY_CLEARED_NOTICE;
            box.appendChild(pubkeyNotice);
        }

        if (parseResult.warnings && parseResult.warnings.length > 0) {
            const warnSection = document.createElement('div');
            warnSection.className = 'import-report-subbox import-subbox-warn';
            parseResult.warnings.forEach((w, idx) => {
                if (idx > 0) warnSection.appendChild(document.createElement('br'));
                const msg = typeof w === 'string' ? w : (w && w.message ? w.message : String(w));
                warnSection.appendChild(document.createTextNode(`⚠️ ${msg}`));
            });
            box.appendChild(warnSection);
        }

        if (parseResult.unsupported && parseResult.unsupported.length > 0) {
            const unsupSection = document.createElement('div');
            unsupSection.className = 'import-report-subbox import-subbox-error';
            parseResult.unsupported.forEach((u, idx) => {
                if (idx > 0) unsupSection.appendChild(document.createElement('br'));
                const msg = typeof u === 'string' ? u : (u && u.message ? u.message : String(u));
                unsupSection.appendChild(document.createTextNode(`🚫 ${msg}`));
            });
            box.appendChild(unsupSection);
        }

        container.appendChild(box);
    }

    const PUBKEY_CLEARED_NOTICE = '• 안내: 공개키(Public Key)는 cURL/HTTP 요청에 포함되지 않으므로 초기화되었습니다. [예시 공개키 채우기] 버튼을 누르거나 직접 공개키(PEM)를 입력해 주세요.';

    function hasExistingRequestInput() {
        if (typeof document === 'undefined') return false;
        return TARGET_INPUT_MAP
            .filter(item => item.key !== 'method')
            .some(item => {
                const el = document.getElementById(item.id);
                return el && el.value.trim().length > 0;
            });
    }

    function applyParsedInputsToDom(parseResult) {
        if (typeof document === 'undefined' || !parseResult || !parseResult.inputs) return;
        for (const item of TARGET_INPUT_MAP) {
            const el = document.getElementById(item.id);
            if (el) {
                el.value = parseResult.inputs[item.key] ?? '';
            }
        }
        
        // Clear public key as it is not part of cURL/HTTP request
        const pubkeyEl = document.getElementById('req-pubkey');
        if (pubkeyEl) {
            pubkeyEl.value = '';
        }

        // Update eval timestamp to match request timestamp or current time
        const evalTimeEl = document.getElementById('eval-timestamp');
        if (evalTimeEl) {
            if (parseResult.inputs.timestampStr && /^\d+$/.test(parseResult.inputs.timestampStr.trim())) {
                evalTimeEl.value = parseResult.inputs.timestampStr.trim();
            } else {
                evalTimeEl.value = Math.floor(Date.now() / 1000);
            }
        }

        if (deps && typeof deps.resetInspector === 'function') {
            deps.resetInspector();
        }

        const applyNoticeEl = document.getElementById('curl-apply-notice');
        if (applyNoticeEl) {
            applyNoticeEl.textContent = '';
            const msgSpan = document.createElement('span');
            msgSpan.textContent = PUBKEY_CLEARED_NOTICE + ' ';
            applyNoticeEl.appendChild(msgSpan);

            const btnFill = document.createElement('button');
            btnFill.type = 'button';
            btnFill.className = 'btn-small btn-inline-sample';
            btnFill.textContent = '🔑 예시 공개키 채우기';
            btnFill.addEventListener('click', () => {
                const pkEl = document.getElementById('req-pubkey');
                const fix = getFixturesObject();
                const fixPubkey = (fix && fix.public_key) || '';
                if (pkEl && fixPubkey) {
                    pkEl.value = fixPubkey;
                    if (deps && typeof deps.showToast === 'function') {
                        deps.showToast('🔑 예시 공개키가 입력칸에 채워졌습니다.');
                    }
                    if (deps && typeof deps.resetInspector === 'function') {
                        deps.resetInspector();
                    }
                }
            });
            applyNoticeEl.appendChild(btnFill);
            applyNoticeEl.classList.remove('hidden');
        }

        const panel = document.getElementById('result-panel');
        if (panel && deps && typeof deps.setPlaceholder === 'function') {
            deps.setPlaceholder(panel, [
                '📥 cURL / Raw HTTP 데이터가 입력칸에 반영되었습니다.',
                PUBKEY_CLEARED_NOTICE,
                "확인을 위해 '진단 시작' 버튼을 눌러주세요."
            ]);
        }
        if (deps && typeof deps.setOverheadVisible === 'function') {
            deps.setOverheadVisible(false);
        }
        if (deps && typeof deps.showToast === 'function') {
            deps.showToast('📥 입력값 적용 완료 (공개키 초기화됨, 예시 공개키 버튼으로 채울 수 있음)');
        }
    }

    function findFixtureCase(name) {
        const fix = getFixturesObject();
        if (fix && Array.isArray(fix.cases)) {
            return fix.cases.find(c => c.name === name) || fix.cases[0] || null;
        }
        return null;
    }

    function buildImportSample(sampleType) {
        if (sampleType === 'raw-http') {
            const c = findFixtureCase('query-sorted') || findFixtureCase('valid');
            if (!c) {
                return [
                    'POST /v1/tx?c=3&a=1&b=2 HTTP/1.1',
                    'Host: api.example.com',
                    'Content-Type: application/json',
                    `${HDRS.nonce}: n-sample`,
                    `${HDRS.timestamp}: 1700000000`,
                    `${HDRS.signature}: sig-sample`,
                    `${HDRS.digest}: sha256=deadbeef`,
                    '',
                    '{"amount": 1000, "to": "alice"}'
                ].join('\n');
            }
            const pathWithQuery = c.query ? `${c.path}?${c.query}` : c.path;
            return [
                `${c.method} ${pathWithQuery} HTTP/1.1`,
                `Host: ${c.host}`,
                'Content-Type: application/json',
                `${HDRS.nonce}: ${c.nonce}`,
                `${HDRS.timestamp}: ${c.timestamp}`,
                `${HDRS.signature}: ${c.signature}`,
                `${HDRS.digest}: ${c.digest}`,
                '',
                c.body
            ].join('\n');
        }

        const caseName = sampleType === 'curl-der' ? 'sig-der' : 'valid';
        const c = findFixtureCase(caseName) || findFixtureCase('valid');
        if (!c) {
            return `curl 'https://api.example.com/v1/tx?c=3&a=1&b=2' \\\n  -H '${HDRS.nonce}: n1' \\\n  --data-raw '{"amount":1000}'`;
        }
        const url = c.query ? `https://${c.host}${c.path}?${c.query}` : `https://${c.host}${c.path}`;
        const escapedBody = String(c.body ?? '').replace(/'/g, "'\\''");
        return [
            `curl '${url}' \\`,
            `  -H 'Accept: application/json' \\`,
            `  -H 'Content-Type: application/json' \\`,
            `  -H '${HDRS.nonce}: ${c.nonce}' \\`,
            `  -H '${HDRS.timestamp}: ${c.timestamp}' \\`,
            `  -H '${HDRS.signature}: ${c.signature}' \\`,
            `  -H '${HDRS.digest}: ${c.digest}' \\`,
            `  --data-raw '${escapedBody}' \\`,
            `  --compressed`
        ].join('\n');
    }

    function initImporter() {
        if (typeof document === 'undefined') return;
        const inputEl = document.getElementById('curl-import-input');
        const btnApply = document.getElementById('btn-curl-apply');
        const confirmBar = document.getElementById('curl-confirm-bar');
        const btnConfirmYes = document.getElementById('btn-curl-confirm-yes');
        const btnConfirmNo = document.getElementById('btn-curl-confirm-no');
        const statusBanner = document.getElementById('import-status-banner');
        const btnSampleValid = document.getElementById('btn-sample-curl-valid');
        const btnSampleDer = document.getElementById('btn-sample-curl-der');
        const btnSampleRawHttp = document.getElementById('btn-sample-raw-http');

        if (!inputEl || !btnApply) return;

        let pendingParseResult = null;

        const applyNoticeEl = document.getElementById('curl-apply-notice');

        const hideConfirmBar = () => {
            pendingParseResult = null;
            if (confirmBar) confirmBar.classList.add('hidden');
        };

        const hideApplyNotice = () => {
            if (applyNoticeEl) applyNoticeEl.classList.add('hidden');
        };

        const fillSample = (type) => {
            hideConfirmBar();
            hideApplyNotice();
            inputEl.value = buildImportSample(type);
            if (typeof inputEl.focus === 'function') {
                inputEl.focus();
            }
        };

        if (btnSampleValid) btnSampleValid.addEventListener('click', () => fillSample('curl-valid'));
        if (btnSampleDer) btnSampleDer.addEventListener('click', () => fillSample('curl-der'));
        if (btnSampleRawHttp) btnSampleRawHttp.addEventListener('click', () => fillSample('raw-http'));

        const commitImport = (res) => {
            hideConfirmBar();
            applyParsedInputsToDom(res);
            if (statusBanner) {
                renderImportStatus(statusBanner, res);
            }
        };

        btnApply.addEventListener('click', () => {
            const parseFn = (deps && deps.parseCurl) || (typeof window !== 'undefined' && window.PopCore && window.PopCore.parseCurl);
            if (typeof parseFn !== 'function') return;

            hideApplyNotice();
            const res = parseFn(inputEl.value);
            if (!res.ok) {
                hideConfirmBar();
                if (statusBanner) {
                    renderImportStatus(statusBanner, res);
                }
                return;
            }

            if (hasExistingRequestInput() && confirmBar) {
                pendingParseResult = res;
                confirmBar.classList.remove('hidden');
            } else {
                commitImport(res);
            }
        });

        if (btnConfirmYes) {
            btnConfirmYes.addEventListener('click', () => {
                if (pendingParseResult) {
                    commitImport(pendingParseResult);
                }
            });
        }

        if (btnConfirmNo) {
            btnConfirmNo.addEventListener('click', () => {
                hideConfirmBar();
            });
        }
    }

    return {
        buildImportSample,
        renderImportStatus,
        applyParsedInputsToDom,
        initImporter
    };
});
