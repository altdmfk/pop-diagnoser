(function (root, factory) {
    const coreMod = (typeof module !== 'undefined' && module.exports)
        ? require('../core/inspect.js')
        : root.PopCore;
    const mod = factory(coreMod);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (coreMod) {
    const DEBOUNCE_MS = 250;

    function createRow(label, valueText, isMono = false) {
        const row = document.createElement('div');
        row.className = 'inspector-row';

        const dt = document.createElement('span');
        dt.className = 'inspector-label';
        dt.textContent = label;
        row.appendChild(dt);

        const dd = document.createElement(isMono ? 'code' : 'span');
        dd.className = isMono ? 'inspector-value inspector-hex' : 'inspector-value';
        dd.textContent = valueText;
        row.appendChild(dd);

        return row;
    }

    function renderSignatureInspect(container, sigReport) {
        if (!container || !sigReport) return;
        container.textContent = '';

        const encText = sigReport.encodingReason
            ? `${sigReport.encoding} (${sigReport.encodingReason})`
            : sigReport.encoding;
        container.appendChild(createRow('인코딩', encText));
        container.appendChild(createRow('바이트 길이', `${sigReport.byteLength} Bytes`));

        let formatText = sigReport.format;
        if (sigReport.format === 'der') {
            const rStrip = sigReport.rLeadingZeroStripped ? '제거됨(0x00)' : '없음';
            const sStrip = sigReport.sLeadingZeroStripped ? '제거됨(0x00)' : '없음';
            formatText = `der (ASN.1 DER → 64B Raw 변환 완료 | 선행 0x00: r=${rStrip}, s=${sStrip})`;
        } else if (sigReport.format === 'raw-rs(64B)') {
            formatText = 'raw-rs(64B) (IEEE P1363 64B Raw)';
        }
        container.appendChild(createRow('형식', formatText));
        container.appendChild(createRow('r (32B Hex)', sigReport.r || '-', true));
        container.appendChild(createRow('s (32B Hex)', sigReport.s || '-', true));

        if (sigReport.error) {
            const errBox = document.createElement('div');
            errBox.className = 'inspector-alert inspector-error';
            errBox.textContent = `[오류] [${sigReport.error.code}] ${sigReport.error.message}`;
            container.appendChild(errBox);
        }

        if (sigReport.warnings && sigReport.warnings.length > 0) {
            const warnBox = document.createElement('div');
            warnBox.className = 'inspector-alert inspector-warn';
            sigReport.warnings.forEach((w, idx) => {
                if (idx > 0) warnBox.appendChild(document.createElement('br'));
                warnBox.appendChild(document.createTextNode(`[경고] [${w.code}] ${w.message}`));
            });
            container.appendChild(warnBox);
        } else if (!sigReport.error) {
            const okBox = document.createElement('div');
            okBox.className = 'inspector-alert inspector-ok';
            okBox.textContent = '[정상] 서명 범위 정상 (표준 Low-S 규격 준수)';
            container.appendChild(okBox);
        }
    }

    function renderPublicKeyInspect(container, pubkeyReport) {
        if (!container || !pubkeyReport) return;
        container.textContent = '';

        const algText = pubkeyReport.algorithmName
            ? `${pubkeyReport.algorithmName} (${pubkeyReport.algorithmOid || '-'})`
            : (pubkeyReport.algorithmOid || '-');
        const curveText = pubkeyReport.curveName
            ? `${pubkeyReport.curveName} (${pubkeyReport.curveOid || '-'})`
            : (pubkeyReport.curveOid || '-');

        let onCurveText = '-';
        if (pubkeyReport.onCurve === true) {
            onCurveText = '[정상] 정상 P-256 공개키 좌표 (곡선 검증 통과)';
        } else if (pubkeyReport.onCurve === false) {
            onCurveText = '[불일치] 곡선 검증 실패 (유효하지 않은 P-256 공개키 좌표)';
        }

        container.appendChild(createRow('알고리즘', algText));
        container.appendChild(createRow('곡선 (Curve)', curveText));
        container.appendChild(createRow('점 형식', pubkeyReport.pointFormat || '-'));
        container.appendChild(createRow('X (32B Hex)', pubkeyReport.x || '-', true));
        container.appendChild(createRow('Y (32B Hex)', pubkeyReport.y || '-', true));
        container.appendChild(createRow('곡선 위 여부', onCurveText));
        container.appendChild(createRow('Fingerprint (SHA-256)', pubkeyReport.fingerprint || '-', true));

        if (pubkeyReport.error) {
            const errBox = document.createElement('div');
            errBox.className = 'inspector-alert inspector-error';
            errBox.textContent = `[오류] [${pubkeyReport.error.code}] ${pubkeyReport.error.message}`;
            container.appendChild(errBox);
        }

        if (pubkeyReport.warnings && pubkeyReport.warnings.length > 0) {
            const warnBox = document.createElement('div');
            warnBox.className = 'inspector-alert inspector-warn';
            pubkeyReport.warnings.forEach((w, idx) => {
                if (idx > 0) warnBox.appendChild(document.createElement('br'));
                warnBox.appendChild(document.createTextNode(`[경고] [${w.code}] ${w.message}`));
            });
            container.appendChild(warnBox);
        }
    }

    let isInspectorActive = false;

    function renderInspectorPlaceholder(container) {
        if (!container) return;
        container.textContent = '';
        const p = document.createElement('div');
        p.className = 'inspector-placeholder';
        p.textContent = "'진단 시작'을 실행하면 서명과 공개키의 구조 분석 결과가 표시됩니다.";
        container.appendChild(p);
    }

    function resetInspector() {
        isInspectorActive = false;
        if (typeof document === 'undefined') return;
        const detailsEl = document.getElementById('inspector-panel');
        const sigContainer = document.getElementById('inspector-sig-box');
        const pubkeyContainer = document.getElementById('inspector-pubkey-box');
        if (detailsEl) detailsEl.open = false;
        renderInspectorPlaceholder(sigContainer);
        renderInspectorPlaceholder(pubkeyContainer);
    }

    async function refreshInspector() {
        if (typeof document === 'undefined' || !coreMod) return;
        isInspectorActive = true;
        const sigInput = document.getElementById('req-signature');
        const pubkeyInput = document.getElementById('req-pubkey');
        const sigContainer = document.getElementById('inspector-sig-box');
        const pubkeyContainer = document.getElementById('inspector-pubkey-box');

        if (sigInput && sigContainer && typeof coreMod.inspectSignature === 'function') {
            const sigReport = coreMod.inspectSignature(sigInput.value);
            renderSignatureInspect(sigContainer, sigReport);
        }

        if (pubkeyInput && pubkeyContainer && typeof coreMod.inspectPublicKey === 'function') {
            const pubkeyReport = await coreMod.inspectPublicKey(pubkeyInput.value);
            renderPublicKeyInspect(pubkeyContainer, pubkeyReport);
        }
    }

    function initInspector() {
        if (typeof document === 'undefined') return;
        const sigInput = document.getElementById('req-signature');
        const pubkeyInput = document.getElementById('req-pubkey');

        let timer = null;
        const scheduleRefresh = () => {
            if (!isInspectorActive) return;
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => {
                refreshInspector();
            }, DEBOUNCE_MS);
        };

        if (sigInput) sigInput.addEventListener('input', scheduleRefresh);
        if (pubkeyInput) pubkeyInput.addEventListener('input', scheduleRefresh);

        resetInspector();
    }

    return {
        renderSignatureInspect,
        renderPublicKeyInspect,
        resetInspector,
        refreshInspector,
        initInspector
    };
});
