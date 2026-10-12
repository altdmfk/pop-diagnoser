(function (root, factory) {
    const jsonErrorUi = (typeof module !== 'undefined' && module.exports)
        ? require('./jsonError.js')
        : root.PopUI;
    const mod = factory(jsonErrorUi);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (jsonErrorUi) {
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

        void t.offsetHeight;
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
            if (
                w &&
                typeof w === 'object' &&
                typeof w.line === 'number' &&
                typeof w.column === 'number' &&
                typeof w.problemLine === 'string' &&
                jsonErrorUi &&
                typeof jsonErrorUi.formatJsonErrorSnippet === 'function'
            ) {
                const detailBox = document.createElement('div');
                detailBox.className = 'error-detail-box';
                detailBox.textContent = jsonErrorUi.formatJsonErrorSnippet(w);
                li.appendChild(detailBox);
            }
            ul.appendChild(li);
        });
        wDiv.appendChild(ul);
        return wDiv;
    }

    function appendErrorHintAndDetail(container, errObj) {
        if (!errObj) return;
        if (errObj.hint) {
            container.appendChild(document.createElement('br'));
            container.appendChild(document.createTextNode('💡 '));
            const hintStrong = document.createElement('strong');
            hintStrong.textContent = '힌트:';
            container.appendChild(hintStrong);
            container.appendChild(document.createTextNode(' ' + errObj.hint));
            if (errObj.hintExample) {
                container.appendChild(document.createTextNode(' '));
                const exSpan = document.createElement('span');
                exSpan.className = 'text-muted-span';
                exSpan.textContent = errObj.hintExample;
                container.appendChild(exSpan);
            }
        }

        const detailText = (
            typeof errObj.line === 'number' &&
            typeof errObj.column === 'number' &&
            typeof errObj.problemLine === 'string' &&
            jsonErrorUi &&
            typeof jsonErrorUi.formatJsonErrorSnippet === 'function'
        )
            ? jsonErrorUi.formatJsonErrorSnippet(errObj)
            : errObj.detail;
        if (detailText) {
            const detailBox = document.createElement('div');
            detailBox.className = 'error-detail-box';
            detailBox.textContent = `📌 에러 상세:\n${detailText}`;
            container.appendChild(detailBox);
        }
    }

    function renderErrorBox(error) {
        const errDiv = document.createElement('div');
        errDiv.className = 'alert warning';
        const strong = document.createElement('strong');
        strong.textContent = '입력 오류:';
        errDiv.appendChild(strong);
        errDiv.appendChild(document.createElement('br'));

        appendMultilineText(errDiv, error.message || '');
        appendErrorHintAndDetail(errDiv, error);

        if (error.code === 'ERR_INVALID_PUBKEY' || error.code === 'ERR_INVALID_SIGNATURE_ENCODING') {
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

                if (s.status === 'fail' && s.code === 'STAGE4_INVALID_SIG_LENGTH') {
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
                    rowAct.className = 'diff-row actual';
                    rowAct.textContent = al === '' ? (hasExp ? '(empty)' : '(trailing \\n)') : al.replace(/\r/g, '\\r');
                    diffBox.appendChild(rowAct);
                }
                if (hasExp) {
                    const rowExp = document.createElement('div');
                    rowExp.className = 'diff-row expected';
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

        const isCanonicalSame = result.expectedCanonical === set.canonical;
        if (isCanonicalSame) {
            const matchBox = document.createElement('div');
            matchBox.className = 'canonical-match-notice';
            const strongNotice = document.createElement('strong');
            strongNotice.textContent = '💡 서명 대상 문자열(Canonical String)은 게이트웨이 기준과 완전히 일치합니다.';
            matchBox.appendChild(strongNotice);
            matchBox.appendChild(document.createElement('br'));
            matchBox.appendChild(document.createTextNode('문자열에는 오차가 없으며, 원인은 서명 데이터 자체의 인코딩 또는 포맷 차이입니다. 아래 해결 가이드를 확인해 주세요.'));
            hBox.appendChild(matchBox);
        } else {
            const pExp = document.createElement('p');
            pExp.className = 'desc-label';
            pExp.textContent = "문자열 차이점 (- 클라이언트가 서명한 잘못된 값 / + 게이트웨이가 요구하는 올바른 규격):";
            hBox.appendChild(pExp);
            hBox.appendChild(renderDiffView(result.expectedCanonical, set.canonical));
        }

        const rawHistoryItems = (set.type === 'indistinguishable' && Array.isArray(set.items))
            ? set.items.reduce((acc, it) => acc.concat(it && Array.isArray(it.history) ? it.history : []), [])
            : (set.item && Array.isArray(set.item.history))
                ? set.item.history
                : (Array.isArray(set.items) && set.items[0] && Array.isArray(set.items[0].history))
                    ? set.items[0].history
                    : [];

        const seenGuideIds = new Set();
        const historyItems = [];
        rawHistoryItems.forEach(h => {
            if (!h) return;
            const dedupKey = h.id || `${h.tag}:${h.label}`;
            if (!seenGuideIds.has(dedupKey)) {
                seenGuideIds.add(dedupKey);
                historyItems.push(h);
            }
        });

        const hasAnyGuide = historyItems.some(h => h.cause || h.solution);
        if (hasAnyGuide) {
            const guideBox = document.createElement('div');
            guideBox.className = 'hypothesis-guide-box';
            const guideTitle = document.createElement('strong');
            guideTitle.className = 'guide-title';
            guideTitle.textContent = '🛠️ 어떻게 수정해야 하나요? (해결 가이드)';
            guideBox.appendChild(guideTitle);

            const guideList = document.createElement('ul');
            guideList.className = 'guide-list';

            historyItems.forEach(h => {
                const li = document.createElement('li');
                const hTitle = document.createElement('div');
                hTitle.className = 'guide-item-title';
                hTitle.textContent = `${getTagLabel(h.tag)} ${h.label}`;
                li.appendChild(hTitle);

                if (h.cause) {
                    const causeDiv = document.createElement('div');
                    causeDiv.className = 'guide-item-desc';
                    causeDiv.textContent = `• 원인: ${h.cause}`;
                    li.appendChild(causeDiv);
                }
                if (h.solution) {
                    const solDiv = document.createElement('div');
                    solDiv.className = 'guide-item-solution';
                    solDiv.textContent = `• 조치 방법: ${h.solution}`;
                    li.appendChild(solDiv);
                }
                guideList.appendChild(li);
            });
            guideBox.appendChild(guideList);
            hBox.appendChild(guideBox);
        }
    }

    function renderNoMatchHypothesis(hBox, expectedCanonical, markBoxError = true) {
        if (markBoxError) {
            hBox.className = 'hypothesis-box error';
        }

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
        preExp.textContent = String(expectedCanonical ?? '').replace(/\r/g, '\\r').replace(/\n/g, '\\n\n');
        hBox.appendChild(preExp);
    }

    function renderStageHypothesisContent(container, stageRes, stageContext, markContainerError = true) {
        if (stageRes.reduced) {
            const redMsg = document.createElement('div');
            redMsg.className = 'red-msg';
            redMsg.textContent = "탐색 범위를 줄였음 (최대 탐색 상한 도달)";
            container.appendChild(redMsg);
        }

        if (stageRes.type === 'found' && Array.isArray(stageRes.sets) && stageRes.sets.length > 0) {
            stageRes.sets.forEach((set) => {
                renderFoundHypothesis(container, set, stageContext);
            });
        } else if (stageRes.type === 'no-match') {
            renderNoMatchHypothesis(container, stageContext.expectedCanonical, markContainerError);
        }
    }

    function renderHypothesisSection(result) {
        const hRes = result.hypothesisResult;
        if (!hRes || hRes.type === 'skipped') return null;

        const hBox = document.createElement('div');
        hBox.className = 'hypothesis-box';

        const s4Sub = (hRes && hRes.stage4) || (result.stage4HypothesisResult && result.stage4HypothesisResult.type !== 'skipped' ? result.stage4HypothesisResult : null);
        const s5Sub = (hRes && hRes.stage5) || (result.stage5HypothesisResult && result.stage5HypothesisResult.type !== 'skipped' ? result.stage5HypothesisResult : null);
        const hasBothStages = Boolean(
            s4Sub && s4Sub.type && s4Sub.type !== 'skipped' &&
            s5Sub && s5Sub.type && s5Sub.type !== 'skipped'
        );

        if (hasBothStages) {
            if (s4Sub.type === 'no-match' && s5Sub.type === 'no-match') {
                hBox.className = 'hypothesis-box error';
            }

            const s4Section = document.createElement('div');
            s4Section.className = s4Sub.type === 'no-match' ? 'hypothesis-stage-section error' : 'hypothesis-stage-section';
            const s4Title = document.createElement('h5');
            s4Title.textContent = '4단계 (서명 검증) 가설 탐색 결과';
            s4Section.appendChild(s4Title);
            renderStageHypothesisContent(
                s4Section,
                s4Sub,
                {
                    ...result,
                    firstFailedStage: 4,
                    expectedCanonical: s4Sub.expectedCanonical || result.expectedCanonical
                },
                false
            );
            hBox.appendChild(s4Section);

            const s5Section = document.createElement('div');
            s5Section.className = s5Sub.type === 'no-match' ? 'hypothesis-stage-section error' : 'hypothesis-stage-section';
            const s5Title = document.createElement('h5');
            s5Title.textContent = '5단계 (본문 다이제스트) 가설 탐색 결과';
            s5Section.appendChild(s5Title);
            renderStageHypothesisContent(
                s5Section,
                s5Sub,
                {
                    ...result,
                    firstFailedStage: 5,
                    expectedCanonical: s5Sub.expectedCanonical || result.stage5ExpectedCanonical || result.expectedCanonical
                },
                false
            );
            hBox.appendChild(s5Section);
            return hBox;
        }

        renderStageHypothesisContent(hBox, hRes, result, true);
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
        const sTitle = document.createElement('strong');
        sTitle.textContent = '서명값 생성 완료: ';
        okDiv.appendChild(sTitle);
        okDiv.appendChild(document.createTextNode('공개키, Body-Digest, Signature가 생성되어 입력칸에 적용되었습니다.'));
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
        appendErrorHintAndDetail(errDiv, err);
        panel.appendChild(errDiv);
    }

    return {
        showToast,
        appendMultilineText,
        setPlaceholder,
        setOverheadVisible,
        getTagLabel,
        renderDiffView,
        renderFoundHypothesis,
        renderHypothesisSection,
        renderResult,
        renderMissingUrlWarning,
        renderGenerateSuccess,
        renderGenerateError
    };
});
