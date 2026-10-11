(function (root, factory) {
    let deps;
    if (typeof module !== 'undefined' && module.exports) {
        deps = Object.assign(
            {},
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
    const FIELD_LABELS = {
        method: 'HTTP 메서드',
        urlStr: '요청 URL',
        bodyStr: '요청 본문(Body)',
        nonce: 'X-FIDO2-Nonce',
        timestampStr: 'X-FIDO2-Timestamp',
        signature: 'X-FIDO2-Signature',
        reqDigest: 'X-Body-Digest'
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
            pubkeyNotice.textContent = PUBKEY_UNCHANGED_NOTICE;
            box.appendChild(pubkeyNotice);
        }

        if (parseResult.warnings && parseResult.warnings.length > 0) {
            const warnSection = document.createElement('div');
            warnSection.className = 'import-report-subbox import-subbox-warn';
            parseResult.warnings.forEach((w, idx) => {
                if (idx > 0) warnSection.appendChild(document.createElement('br'));
                const msg = typeof w === 'string' ? w : `[${w.code}] ${w.message}`;
                warnSection.appendChild(document.createTextNode(`⚠️ ${msg}`));
            });
            box.appendChild(warnSection);
        }

        if (parseResult.unsupported && parseResult.unsupported.length > 0) {
            const unsupSection = document.createElement('div');
            unsupSection.className = 'import-report-subbox import-subbox-error';
            parseResult.unsupported.forEach((u, idx) => {
                if (idx > 0) unsupSection.appendChild(document.createElement('br'));
                const msg = typeof u === 'string' ? u : `[${u.code}] ${u.message}`;
                unsupSection.appendChild(document.createTextNode(`🚫 ${msg}`));
            });
            box.appendChild(unsupSection);
        }

        container.appendChild(box);
    }

    const PUBKEY_UNCHANGED_NOTICE = '• 안내: 공개키(Public Key)와 평가 기준 시각은 cURL/HTTP 요청에 포함되지 않으므로 변경하지 않았습니다. (공개키는 직접 입력 필요)';

    function hasExistingRequestInput() {
        if (typeof document === 'undefined') return false;
        const checkIds = ['req-url', 'req-body', 'req-nonce', 'req-timestamp', 'req-signature', 'req-digest'];
        return checkIds.some(id => {
            const el = document.getElementById(id);
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
        // Intentionally leave #req-pubkey and #eval-timestamp untouched
        if (deps && typeof deps.resetInspector === 'function') {
            deps.resetInspector();
        }
        const applyNoticeEl = document.getElementById('curl-apply-notice');
        if (applyNoticeEl) {
            applyNoticeEl.textContent = PUBKEY_UNCHANGED_NOTICE;
            applyNoticeEl.classList.remove('hidden');
        }
        const panel = document.getElementById('result-panel');
        if (panel && deps && typeof deps.setPlaceholder === 'function') {
            deps.setPlaceholder(panel, [
                '📥 cURL / Raw HTTP 데이터가 입력칸에 반영되었습니다.',
                PUBKEY_UNCHANGED_NOTICE,
                "확인을 위해 '진단 시작' 버튼을 눌러주세요."
            ]);
        }
        if (deps && typeof deps.setOverheadVisible === 'function') {
            deps.setOverheadVisible(false);
        }
        if (deps && typeof deps.showToast === 'function') {
            deps.showToast(`📥 입력값 적용 완료 (${PUBKEY_UNCHANGED_NOTICE})`);
        }
    }

    function findFixtureCase(name) {
        const fix = (typeof globalThis !== 'undefined' && globalThis.FIXTURES)
            ? globalThis.FIXTURES
            : (typeof window !== 'undefined' && window.FIXTURES ? window.FIXTURES : null);
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
                    'X-FIDO2-Nonce: n-sample',
                    'X-FIDO2-Timestamp: 1700000000',
                    'X-FIDO2-Signature: sig-sample',
                    'X-Body-Digest: sha256=deadbeef',
                    '',
                    '{"amount": 1000, "to": "alice"}'
                ].join('\n');
            }
            const pathWithQuery = c.query ? `${c.path}?${c.query}` : c.path;
            return [
                `${c.method} ${pathWithQuery} HTTP/1.1`,
                `Host: ${c.host}`,
                'Content-Type: application/json',
                `X-FIDO2-Nonce: ${c.nonce}`,
                `X-FIDO2-Timestamp: ${c.timestamp}`,
                `X-FIDO2-Signature: ${c.signature}`,
                `X-Body-Digest: ${c.digest}`,
                '',
                c.body
            ].join('\n');
        }

        const caseName = sampleType === 'curl-der' ? 'sig-der' : 'valid';
        const c = findFixtureCase(caseName) || findFixtureCase('valid');
        if (!c) {
            return "curl 'https://api.example.com/v1/tx?c=3&a=1&b=2' \\\n  -H 'X-FIDO2-Nonce: n1' \\\n  --data-raw '{\"amount\":1000}'";
        }
        const url = c.query ? `https://${c.host}${c.path}?${c.query}` : `https://${c.host}${c.path}`;
        const escapedBody = String(c.body ?? '').replace(/'/g, "'\\''");
        return [
            `curl '${url}' \\`,
            `  -H 'Accept: application/json' \\`,
            `  -H 'Content-Type: application/json' \\`,
            `  -H 'X-FIDO2-Nonce: ${c.nonce}' \\`,
            `  -H 'X-FIDO2-Timestamp: ${c.timestamp}' \\`,
            `  -H 'X-FIDO2-Signature: ${c.signature}' \\`,
            `  -H 'X-Body-Digest: ${c.digest}' \\`,
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
