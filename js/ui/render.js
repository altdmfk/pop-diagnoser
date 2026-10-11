(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    const TOAST_DURATION_MS = 2500;
    const TOAST_FADE_MS = 300;

    function showToast(msg, isError = false) {
        if (typeof document === 'undefined') return;
        const t = document.createElement('div');
        t.className = isError ? 'toast toast-error' : 'toast';
        t.setAttribute('role', isError ? 'alert' : 'status');
        t.setAttribute('aria-live', isError ? 'assertive' : 'polite');
        t.textContent = msg;
        document.body.appendChild(t);

        t.offsetHeight;
        t.classList.add('toast-visible');

        setTimeout(() => {
            t.classList.remove('toast-visible');
            setTimeout(() => t.remove(), TOAST_FADE_MS);
        }, TOAST_DURATION_MS);
    }

    function appendMultilineText(parent, text) {
        const lines = String(text ?? '').split('\n');
        lines.forEach((line, idx) => {
            if (idx > 0) {
                parent.appendChild(document.createElement('br'));
            }
            parent.appendChild(document.createTextNode(line));
        });
    }

    function setPlaceholder(panel, lines) {
        if (!panel) return;
        panel.textContent = '';
        const p = document.createElement('p');
        p.className = 'placeholder-text';
        lines.forEach((line, idx) => {
            if (idx > 0) {
                p.appendChild(document.createElement('br'));
            }
            p.appendChild(document.createTextNode(line));
        });
        panel.appendChild(p);
        panel.classList.add('empty');
    }

    function setOverheadVisible(visible) {
        if (typeof document === 'undefined') return;
        const overheadEl = document.getElementById('overhead-info');
        if (!overheadEl) return;
        if (visible) {
            overheadEl.classList.remove('hidden');
        } else {
            overheadEl.classList.add('hidden');
        }
    }

    function getTagLabel(tag) {
        if (tag === 'paper-rule') return '[논문 규칙]';
        if (tag === 'common-mistake') return '[흔한 실수]';
        if (tag === 'encoding') return '[인코딩]';
        return '[기타]';
    }

    function renderWarningsBox(warnings) {
        const wDiv = document.createElement('div');
        wDiv.className = 'alert info';
        wDiv.appendChild(document.createTextNode('💡 '));
        const strong = document.createElement('strong');
        strong.textContent = '진단기 자동 교정 안내:';
        wDiv.appendChild(strong);
        wDiv.appendChild(document.createElement('br'));

        const ul = document.createElement('ul');
        ul.className = 'warning-list';
        warnings.forEach(w => {
            const li = document.createElement('li');
            li.textContent = typeof w === 'string' ? w : (w && w.message ? w.message : '');
            ul.appendChild(li);
        });
        wDiv.appendChild(ul);
        return wDiv;
    }

    function renderErrorBox(error) {
        const errDiv = document.createElement('div');
        errDiv.className = 'alert warning';
        const strong = document.createElement('strong');
        strong.textContent = '입력 오류:';
        errDiv.appendChild(strong);
        errDiv.appendChild(document.createElement('br'));

        appendMultilineText(errDiv, error.message || '');

        if (error.hint) {
            errDiv.appendChild(document.createElement('br'));
            errDiv.appendChild(document.createTextNode('💡 '));
            const hintStrong = document.createElement('strong');
            hintStrong.textContent = '힌트:';
            errDiv.appendChild(hintStrong);
            errDiv.appendChild(document.createTextNode(' ' + error.hint));
            if (error.hintExample) {
                errDiv.appendChild(document.createTextNode(' '));
                const exSpan = document.createElement('span');
                exSpan.className = 'text-muted-span';
                exSpan.textContent = error.hintExample;
                errDiv.appendChild(exSpan);
            }
        }

        if (error.detail) {
            const detailBox = document.createElement('div');
            detailBox.className = 'error-detail-box';
            detailBox.textContent = `📌 에러 상세:\n${error.detail}`;
            errDiv.appendChild(detailBox);
        }

        if (typeof error.message === 'string' && /(공개키|서명)/.test(error.message)) {
            const inspectorHint = document.createElement('div');
            inspectorHint.className = 'inspector-guide-hint';
            inspectorHint.textContent = "🔍 인스펙터 안내: 아래 '🔍 서명 · 공개키 구조 인스펙터' 패널을 열어 서명(인코딩·바이트 길이·DER/Raw 형식) 및 공개키(알고리즘·곡선·좌표) 상세 구조를 확인해 보세요.";
            errDiv.appendChild(inspectorHint);
        }
        return errDiv;
    }

    function renderStageList(stages, firstFailedStage) {
        const stageList = document.createElement('ul');
        stageList.className = 'stage-list';

        stages.forEach((s, idx) => {
            const li = document.createElement('li');
            li.className = 'stage-item';

            const iconDiv = document.createElement('div');
            iconDiv.className = 'status-icon';
            iconDiv.textContent = s.status === 'pass' ? '✅' : s.status === 'unknown' ? '❓' : '❌';

            const contentDiv = document.createElement('div');
            contentDiv.className = 'content';

            const h4 = document.createElement('h4');
            h4.textContent = s.name;
            if (firstFailedStage === (idx + 1)) {
                h4.textContent += ' (첫 실패 단계)';
                h4.className = 'failed';
            }
            contentDiv.appendChild(h4);

            if (s.reason) {
                const p = document.createElement('p');
                p.textContent = s.reason;
                if (s.status === 'fail') p.className = 'failed';
                contentDiv.appendChild(p);

                if (
                    s.status === 'fail' &&
                    typeof s.reason === 'string' &&
                    (s.reason.includes('현재 디코딩된 크기:') || s.reason.includes('서명 길이'))
                ) {
                    const inspectorHint = document.createElement('div');
                    inspectorHint.className = 'inspector-guide-hint';
                    inspectorHint.textContent = "🔍 인스펙터 안내: 아래 '🔍 서명 · 공개키 구조 인스펙터' 패널을 열어 서명의 인코딩, 바이트 길이, DER/Raw 형식을 확인해 보세요.";
                    contentDiv.appendChild(inspectorHint);
                }
            }

            li.appendChild(iconDiv);
            li.appendChild(contentDiv);
            stageList.appendChild(li);
        });

        return stageList;
    }

    function renderDiffView(expectedCanonical, actualCanonical) {
        const diffBox = document.createElement('div');
        diffBox.className = 'diff-view';

        const expLines = expectedCanonical.split('\n');
        const actLines = actualCanonical.split('\n');
        const maxLines = Math.max(expLines.length, actLines.length);

        for (let i = 0; i < maxLines; i++) {
            const hasExp = i < expLines.length;
            const hasAct = i < actLines.length;
            const el = hasExp ? expLines[i] : '';
            const al = hasAct ? actLines[i] : '';

            if (hasExp && hasAct && el === al) {
                const row = document.createElement('div');
                row.className = 'diff-row match';
                row.textContent = el === '' ? '(empty)' : el.replace(/\r/g, '\\r');
                diffBox.appendChild(row);
            } else {
                if (hasAct) {
                    const rowAct = document.createElement('div');
                    rowAct.className = 'diff-row expected';
                    rowAct.textContent = al === '' ? (hasExp ? '(empty)' : '(trailing \\n)') : al.replace(/\r/g, '\\r');
                    diffBox.appendChild(rowAct);
                }
                if (hasExp) {
                    const rowExp = document.createElement('div');
                    rowExp.className = 'diff-row actual';
                    rowExp.textContent = el === '' ? '(empty)' : el.replace(/\r/g, '\\r');
                    diffBox.appendChild(rowExp);
                }
            }
        }
        return diffBox;
    }

    function renderFoundHypothesis(hBox, set, result) {
        if (set.type === 'match') {
            const p = document.createElement('p');
            const labels = set.item.history.map(x => `${getTagLabel(x.tag)} ${x.label}`).join(' + ');
            const verifyTarget = result.firstFailedStage === 5 ? '다이제스트가' : '서명이';
            p.textContent = `이 불일치를 적용하면 ${verifyTarget} 검증됩니다: ${labels}. 서명하는 쪽 코드, 또는 요청을 가공하는 중간 계층(프록시/CDN/프레임워크)을 확인해 보세요.`;
            hBox.appendChild(p);
        } else if (set.type === 'indistinguishable') {
            const p = document.createElement('p');
            p.textContent = `다음 ${set.items.length}가지는 이 요청에서는 구분할 수 없습니다:`;
            hBox.appendChild(p);
            const ul = document.createElement('ul');
            set.items.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item.history.map(x => `${getTagLabel(x.tag)} ${x.label}`).join(' + ');
                ul.appendChild(li);
            });
            hBox.appendChild(ul);
        }

        const pExp = document.createElement('p');
        pExp.className = 'desc-label';
        pExp.textContent = "문자열 차이점 (- 클라이언트가 서명한 잘못된 값 / + 게이트웨이가 요구하는 올바른 규격):";
        hBox.appendChild(pExp);
        hBox.appendChild(renderDiffView(result.expectedCanonical, set.canonical));
    }

    function renderNoMatchHypothesis(hBox, expectedCanonical) {
        hBox.className = 'hypothesis-box error';

        const h5 = document.createElement('h5');
        h5.textContent = '원인 파악 실패 (일치하는 실수 패턴 없음)';
        hBox.appendChild(h5);

        const p = document.createElement('p');
        p.appendChild(document.createTextNode("진단기가 알고 있는 '흔한 실수 패턴'들을 모두 대입해 보았으나 유효한 서명을 찾지 못했습니다."));
        p.appendChild(document.createElement('br'));
        p.appendChild(document.createElement('br'));
        const b = document.createElement('b');
        b.textContent = '💡 예상되는 원인:';
        p.appendChild(b);
        p.appendChild(document.createElement('br'));
        appendMultilineText(
            p,
            '1. 서명할 때 사용한 비공개키(Private Key)와 입력하신 공개키(Public Key)가 서로 짝이 맞지 않음\n' +
            '2. ECDSA P-256 알고리즘이 아닌 다른 방식으로 서명됨\n' +
            '3. 진단기가 예측할 수 없는 방식으로 데이터가 변형됨'
        );
        hBox.appendChild(p);

        const pExp = document.createElement('p');
        pExp.className = 'desc-label';
        pExp.textContent = "서명 검증 시 서버(게이트웨이)가 기준값으로 기대했던 문자열은 다음과 같습니다:";
        hBox.appendChild(pExp);

        const preExp = document.createElement('pre');
        preExp.textContent = expectedCanonical.replace(/\r/g, '\\r').replace(/\n/g, '\\n\n');
        hBox.appendChild(preExp);
    }

    function renderHypothesisSection(result) {
        const hRes = result.hypothesisResult;
        if (!hRes || hRes.type === 'skipped') return null;

        const hBox = document.createElement('div');
        hBox.className = 'hypothesis-box';

        if (hRes.reduced) {
            const redMsg = document.createElement('div');
            redMsg.className = 'red-msg';
            redMsg.textContent = "탐색 범위를 줄였음 (최대 탐색 상한 도달)";
            hBox.appendChild(redMsg);
        }

        if (hRes.type === 'found' && hRes.sets.length > 0) {
            renderFoundHypothesis(hBox, hRes.sets[0], result);
        } else if (hRes.type === 'no-match') {
            renderNoMatchHypothesis(hBox, result.expectedCanonical);
        }
        return hBox;
    }

    function renderResult(result) {
        const panel = document.getElementById('result-panel');
        panel.textContent = '';

        if (result.warnings && result.warnings.length > 0) {
            panel.appendChild(renderWarningsBox(result.warnings));
        }

        if (result.error) {
            panel.appendChild(renderErrorBox(result.error));
            return;
        }

        panel.appendChild(renderStageList(result.stages, result.firstFailedStage));

        const hBox = renderHypothesisSection(result);
        if (hBox) {
            panel.appendChild(hBox);
        }
    }

    function renderMissingUrlWarning(panel) {
        panel.textContent = '';
        const warnDiv = document.createElement('div');
        warnDiv.className = 'alert warning';
        const strong = document.createElement('strong');
        strong.textContent = '생성 불가:';
        warnDiv.appendChild(strong);
        warnDiv.appendChild(document.createTextNode(' URL을 입력해 주셔야 서명을 생성할 수 있습니다.'));
        panel.appendChild(warnDiv);
    }

    function renderGenerateSuccess(panel) {
        panel.textContent = '';
        const okDiv = document.createElement('div');
        okDiv.className = 'alert success';
        okDiv.appendChild(document.createTextNode('✨ '));
        const sTitle = document.createElement('strong');
        sTitle.textContent = '테스트용 서명 자동 생성 완료:';
        okDiv.appendChild(sTitle);
        okDiv.appendChild(document.createTextNode(' 입력하신 요청 정보를 바탕으로 새로운 '));
        const sItems = document.createElement('strong');
        sItems.textContent = '공개키, 본문 해시(Digest), 전자서명';
        okDiv.appendChild(sItems);
        okDiv.appendChild(document.createTextNode('이 정상적으로 생성되어 모든 탭의 입력칸에 자동 적용되었습니다.'));
        panel.appendChild(okDiv);
        panel.classList.remove('empty');
    }

    function renderGenerateError(panel, err) {
        panel.textContent = '';
        const errDiv = document.createElement('div');
        errDiv.className = 'alert warning alert-compact';
        const strongTitle = document.createElement('strong');
        strongTitle.className = 'alert-title';
        strongTitle.textContent = '❌ 서명 생성 실패';
        errDiv.appendChild(strongTitle);
        appendMultilineText(errDiv, err && err.message ? err.message : String(err));
        if (err && err.detail) {
            const detailBox = document.createElement('div');
            detailBox.className = 'error-detail-box';
            detailBox.textContent = `📌 에러 상세:\n${err.detail}`;
            errDiv.appendChild(detailBox);
        }
        panel.appendChild(errDiv);
    }

    return {
        showToast,
        appendMultilineText,
        setPlaceholder,
        setOverheadVisible,
        getTagLabel,
        renderResult,
        renderMissingUrlWarning,
        renderGenerateSuccess,
        renderGenerateError
    };
});
