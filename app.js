document.addEventListener('DOMContentLoaded', () => {
    const evalTimeInput = document.getElementById('eval-timestamp');
    document.getElementById('btn-now').addEventListener('click', () => {
        evalTimeInput.value = Math.floor(Date.now() / 1000);
    });
    evalTimeInput.value = Math.floor(Date.now() / 1000);

    const loadDemo = (fixtureName) => {
        if (!window.FIXTURES || !window.FIXTURES.cases) {
            alert("데모 데이터를 불러오지 못했습니다. (fixtures.js 확인 필요)");
            return;
        }
        const fixture = window.FIXTURES.cases.find(c => c.name === fixtureName);
        if (!fixture) {
            alert("해당 데모 케이스를 찾을 수 없습니다.");
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
        setVal('req-credential-id', fixture.credentialId || 'test-cred-id');
        setVal('req-pubkey', window.FIXTURES.public_key || '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgHsBt/wr3i0Y+5QEk7rVWqy/WiAp\n2BE0Fh98ukGLUupf0yKXbYwjrKKNGb+RWKp8kXdEVAYG2ExSBg3TLqgM6g==\n-----END PUBLIC KEY-----\n');
        
        const evalTimeInput = document.getElementById('eval-timestamp');
        if (evalTimeInput) evalTimeInput.value = window.FIXTURES.eval_time;
    };

    document.getElementById('btn-demo-valid').addEventListener('click', () => loadDemo('valid'));
    document.getElementById('btn-demo-unsorted').addEventListener('click', () => loadDemo('query-sorted'));
    document.getElementById('btn-demo-method').addEventListener('click', () => loadDemo('method-lowercase'));
    document.getElementById('btn-demo-expired').addEventListener('click', () => loadDemo('timestamp-fail'));

    document.getElementById('btn-diagnose').addEventListener('click', async () => {
        const panel = document.getElementById('result-panel');
        panel.classList.remove('empty');
        panel.textContent = '진단 중...';

        const inputs = {
            method: document.getElementById('req-method').value,
            urlStr: document.getElementById('req-url').value,
            bodyStr: document.getElementById('req-body').value.replace(/\r\n/g, '\n'),
            nonce: document.getElementById('req-nonce').value,
            timestampStr: document.getElementById('req-timestamp').value,
            signature: document.getElementById('req-signature').value,
            pubkeyPem: document.getElementById('req-pubkey').value,
            reqDigest: document.getElementById('req-digest').value,
            credentialId: document.getElementById('req-credential-id').value,
            evalTime: parseInt(evalTimeInput.value, 10)
        };

        try {
            const result = await PopCore.diagnose(inputs);
            renderResult(result);
            document.getElementById('overhead-info').style.display = 'block';
        } catch (e) {
            panel.textContent = `오류 발생: ${e.message}`;
        }
    });
});

function getTagLabel(tag) {
    if (tag === 'paper-rule') return '[논문 규칙]';
    if (tag === 'common-mistake') return '[흔한 실수]';
    if (tag === 'encoding') return '[인코딩]';
    return '[기타]';
}

function renderResult(result) {
    const panel = document.getElementById('result-panel');
    panel.textContent = ''; // clear innerHTML safely

    if (result.error) {
        const errDiv = document.createElement('div');
        errDiv.className = 'alert warning';
        errDiv.textContent = `입력 오류: ${result.error.message}`;
        panel.appendChild(errDiv);
        return;
    }

    const stageList = document.createElement('ul');
    stageList.className = 'stage-list';

    result.stages.forEach((s, idx) => {
        const li = document.createElement('li');
        li.className = 'stage-item';
        
        const iconDiv = document.createElement('div');
        iconDiv.className = 'status-icon';
        iconDiv.textContent = s.status === 'pass' ? '✅' : s.status === 'unknown' ? '❓' : '❌';
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'content';
        
        const h4 = document.createElement('h4');
        h4.textContent = s.name;
        
        if (result.firstFailedStage === (idx + 1)) {
            h4.textContent += ' (첫 실패 단계)';
            h4.className = 'failed';
        }

        contentDiv.appendChild(h4);
        
        if (s.reason) {
            const p = document.createElement('p');
            p.textContent = s.reason;
            if (s.status === 'fail') p.className = 'failed';
            contentDiv.appendChild(p);
        }
        
        li.appendChild(iconDiv);
        li.appendChild(contentDiv);
        stageList.appendChild(li);
    });

    panel.appendChild(stageList);

    if (result.hypothesisResult) {
        const hRes = result.hypothesisResult;
        const hBox = document.createElement('div');
        hBox.className = 'hypothesis-box';
        
        if (hRes.reduced) {
            const redMsg = document.createElement('div');
            redMsg.className = 'red-msg';
            redMsg.textContent = "탐색 범위를 줄였음 (최대 탐색 상한 도달)";
            hBox.appendChild(redMsg);
        }

        if (hRes.type === 'found' && hRes.sets.length > 0) {
            const set = hRes.sets[0]; 
            
            if (set.type === 'match') {
                const p = document.createElement('p');
                const labels = set.item.history.map(x => `${getTagLabel(x.tag)} ${x.label}`).join(' + ');
                p.textContent = `이 불일치를 적용하면 서명이 검증됩니다: ${labels}. 서명하는 쪽 코드, 또는 요청을 가공하는 중간 계층(프록시/CDN/프레임워크)을 확인해 보세요.`;
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
            pExp.textContent = "게이트웨이가 기대한 문자열 (Failed):";
            hBox.appendChild(pExp);
            
            const preExp = document.createElement('pre');
            preExp.textContent = result.expectedCanonical.replace(/\r/g, '\\r').replace(/\n/g, '\\n\n');
            hBox.appendChild(preExp);
            
            const pAct = document.createElement('p');
            pAct.className = 'desc-label';
            pAct.textContent = "실제로 서명된 문자열 (Matched):";
            hBox.appendChild(pAct);
            
            const preAct = document.createElement('pre');
            preAct.textContent = set.canonical.replace(/\r/g, '\\r').replace(/\n/g, '\\n\n');
            hBox.appendChild(preAct);

        } else if (hRes.type === 'no-match') {
            hBox.className = 'hypothesis-box error';
            
            const h5 = document.createElement('h5');
            h5.textContent = '일치 없음';
            hBox.appendChild(h5);
            
            const p = document.createElement('p');
            p.textContent = "시험한 가설 중 서명이 검증되는 것이 없습니다. 키나 알고리즘이 다르거나, 이 앱이 모르는 서명 형식이거나, 목록에 없는 실수일 수 있습니다.";
            hBox.appendChild(p);
            
            const pExp = document.createElement('p');
            pExp.className = 'desc-label';
            pExp.textContent = "게이트웨이가 검증에 사용한 기준 문자열:";
            hBox.appendChild(pExp);
            
            const preExp = document.createElement('pre');
            preExp.textContent = result.expectedCanonical.replace(/\r/g, '\\r').replace(/\n/g, '\\n\n');
            hBox.appendChild(preExp);
        }

        if (hRes.type !== 'pass' && hRes.type !== 'skipped') {
            panel.appendChild(hBox);
        }
    }
}
