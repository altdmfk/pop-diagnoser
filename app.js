
function showToast(msg) {
    const t = document.createElement('div');
    t.textContent = msg;
    t.style.position = 'fixed';
    t.style.top = '20px';
    t.style.left = '50%';
    t.style.transform = 'translateX(-50%)';
    t.style.backgroundColor = '#10b981';
    t.style.color = 'white';
    t.style.padding = '12px 24px';
    t.style.borderRadius = '8px';
    t.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
    t.style.zIndex = '9999';
    t.style.fontWeight = 'bold';
    t.style.opacity = '0';
    t.style.transition = 'opacity 0.3s ease, top 0.3s ease';
    document.body.appendChild(t);
    
    t.offsetHeight; 
    t.style.opacity = '1';
    t.style.top = '40px';
    
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.top = '20px';
        setTimeout(() => t.remove(), 300);
    }, 2500);
}

document.addEventListener('DOMContentLoaded', () => {

    // --- Memory Functions (Multi-slot) ---
    const MAX_SLOTS = 5;
    window.renderMemorySlots = function() {
        let memory = JSON.parse(localStorage.getItem('popDiagnoserSlots') || '{}');
        const container = document.getElementById('memory-slots-container');
        if (!container) return;
        container.innerHTML = '';
        
        for (let i = 1; i <= MAX_SLOTS; i++) {
            const slotData = memory[`slot_${i}`];
            const slotDiv = document.createElement('div');
            slotDiv.className = 'memory-slot';
            
            const titleSpan = document.createElement('span');
            titleSpan.className = 'memory-slot-name';
            titleSpan.textContent = slotData ? `슬롯 ${i} (저장됨: ${slotData.time})` : `슬롯 ${i} (비어있음)`;
            slotDiv.appendChild(titleSpan);
            
            const btnSave = document.createElement('button');
            btnSave.className = 'btn-small';
            btnSave.style.color = '#2563eb';
            btnSave.style.borderColor = '#bfdbfe';
            btnSave.textContent = '💾 현재 탭 저장';
            btnSave.onclick = () => window.saveToSlot(i);
            slotDiv.appendChild(btnSave);
            
            if (slotData) {
                const btnLoad = document.createElement('button');
                btnLoad.className = 'btn-small';
                btnLoad.style.color = '#059669';
                btnLoad.style.borderColor = '#a7f3d0';
                btnLoad.textContent = '📂 불러오기';
                btnLoad.onclick = () => window.loadFromSlot(i);
                slotDiv.appendChild(btnLoad);
                
                const btnDel = document.createElement('button');
                btnDel.className = 'btn-small';
                btnDel.style.color = '#ef4444';
                btnDel.style.borderColor = '#fca5a5';
                btnDel.textContent = '🗑️ 삭제';
                btnDel.onclick = () => window.deleteSlot(i);
                slotDiv.appendChild(btnDel);
            }
            container.appendChild(slotDiv);
        }
    };

    window.saveToSlot = function(i) {
        const data = {
            time: new Date().toLocaleTimeString('ko-KR', { hour12: false }),
            method: document.getElementById('req-method').value,
            urlStr: document.getElementById('req-url').value,
            bodyStr: document.getElementById('req-body').value,
            nonce: document.getElementById('req-nonce').value,
            timestampStr: document.getElementById('req-timestamp').value,
            signature: document.getElementById('req-signature').value,
            reqDigest: document.getElementById('req-digest').value,
            pubkeyPem: document.getElementById('req-pubkey').value,
            evalTime: document.getElementById('eval-timestamp').value
        };
        let memory = JSON.parse(localStorage.getItem('popDiagnoserSlots') || '{}');
        memory[`slot_${i}`] = data;
        localStorage.setItem('popDiagnoserSlots', JSON.stringify(memory));
        showToast(`💾 슬롯 ${i}에 현재 작업이 저장되었습니다.`);
        window.renderMemorySlots();
    };

    window.loadFromSlot = function(i) {
        let memory = JSON.parse(localStorage.getItem('popDiagnoserSlots') || '{}');
        const data = memory[`slot_${i}`];
        if (data) {
            document.getElementById('req-method').value = data.method || '';
            document.getElementById('req-url').value = data.urlStr || '';
            document.getElementById('req-body').value = data.bodyStr || '';
            document.getElementById('req-nonce').value = data.nonce || '';
            document.getElementById('req-timestamp').value = data.timestampStr || '';
            document.getElementById('req-signature').value = data.signature || '';
            document.getElementById('req-digest').value = data.reqDigest || '';
            document.getElementById('req-pubkey').value = data.pubkeyPem || '';
            document.getElementById('eval-timestamp').value = data.evalTime || '';
            showToast(`📂 슬롯 ${i}의 데이터를 성공적으로 불러왔습니다.`);
            const panel = document.getElementById('result-panel');
            panel.innerHTML = `<p class="placeholder-text">데이터를 성공적으로 불러왔습니다.<br>확인을 위해 '진단 시작' 버튼을 눌러주세요.</p>`;
            panel.classList.add('empty');
            document.getElementById('overhead-info').style.display = 'none';
        }
    };

    window.deleteSlot = function(i) {
        let memory = JSON.parse(localStorage.getItem('popDiagnoserSlots') || '{}');
        delete memory[`slot_${i}`];
        localStorage.setItem('popDiagnoserSlots', JSON.stringify(memory));
        showToast(`🗑️ 슬롯 ${i}의 데이터가 삭제되었습니다.`);
        window.renderMemorySlots();
    };

    window.renderMemorySlots();



    const evalTimeInput = document.getElementById('eval-timestamp');
    document.getElementById('btn-now').addEventListener('click', () => {
        evalTimeInput.value = Math.floor(Date.now() / 1000);
    });
    evalTimeInput.value = Math.floor(Date.now() / 1000);

    const loadDemo = (fixtureName, showFeedback = false) => {
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
        setVal('req-pubkey', window.FIXTURES.public_key || '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgHsBt/wr3i0Y+5QEk7rVWqy/WiAp\n2BE0Fh98ukGLUupf0yKXbYwjrKKNGb+RWKp8kXdEVAYG2ExSBg3TLqgM6g==\n-----END PUBLIC KEY-----\n');
        
        const evalTimeInput = document.getElementById('eval-timestamp');
        if (evalTimeInput) evalTimeInput.value = window.FIXTURES.eval_time;
        
        if (showFeedback) {
            showToast('✅ 선택하신 예시 데이터가 모든 탭에 자동 입력되었습니다.');
            const panel = document.getElementById('result-panel');
            panel.innerHTML = `<p class="placeholder-text">예시 데이터가 갱신되었습니다.<br>확인을 위해 '진단 시작' 버튼을 눌러주세요.</p>`;
            panel.classList.add('empty');
            document.getElementById('overhead-info').style.display = 'none';
        }
    };

    document.getElementById('btn-demo-valid').addEventListener('click', () => loadDemo('valid', true));
    document.getElementById('btn-demo-unsorted').addEventListener('click', () => loadDemo('query-sorted', true));
    document.getElementById('btn-demo-method').addEventListener('click', () => loadDemo('method-lowercase', true));
    document.getElementById('btn-demo-expired').addEventListener('click', () => loadDemo('timestamp-fail', true));

    document.getElementById('btn-clear-all').addEventListener('click', () => {
        const fields = ['req-method', 'req-url', 'req-body', 'req-nonce', 'req-timestamp', 'req-signature', 'req-digest', 'req-pubkey', 'eval-timestamp'];
        fields.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        const panel = document.getElementById('result-panel');
        panel.innerHTML = '<p class="placeholder-text">왼쪽에서 데이터를 입력하고 \'진단 시작\'을 눌러주세요.</p>';
        panel.classList.add('empty');
        document.getElementById('overhead-info').style.display = 'none';
    });


    loadDemo('valid');

    
    // 서명 생성기
    document.getElementById('btn-generate-test').addEventListener('click', async () => {
        try {
            const inputs = {
                method: document.getElementById('req-method').value || 'POST',
                urlStr: document.getElementById('req-url').value,
                bodyStr: document.getElementById('req-body').value.replace(/\r\n/g, '\n'),
                nonce: document.getElementById('req-nonce').value || 'n-test',
                timestampStr: document.getElementById('req-timestamp').value || Math.floor(Date.now() / 1000).toString()
        };
            
            if (!inputs.urlStr) {
                const panel = document.getElementById('result-panel');
                panel.innerHTML = '<div class="alert warning"><strong>생성 불가:</strong> URL을 입력해 주셔야 서명을 생성할 수 있습니다.</div>';
                return;
            }

            const gen = await PopCore.generateTestSignature(inputs);
            
            document.getElementById('req-digest').value = gen.reqDigest;
            document.getElementById('req-signature').value = gen.signature;
            document.getElementById('req-pubkey').value = gen.pubkeyPem;
            
            // eval timestamp를 현재 timestamp로 맞춤
            document.getElementById('eval-timestamp').value = inputs.timestampStr;
            document.getElementById('req-timestamp').value = inputs.timestampStr;
            document.getElementById('req-nonce').value = inputs.nonce;
            document.getElementById('req-method').value = inputs.method;
            
            // alert 대신 곧바로 진단을 실행하여 결과를 보여줌으로써 최고의 UX 제공
            showToast('✨ 새로운 서명이 생성되어 적용되었습니다!');
            const panel = document.getElementById('result-panel');
            panel.innerHTML = `<div class="alert success">✨ <strong>테스트용 서명 자동 생성 완료:</strong> 입력하신 요청 정보를 바탕으로 새로운 <strong>공개키, 본문 해시(Digest), 전자서명</strong>이 정상적으로 생성되어 모든 탭의 입력칸에 자동 적용되었습니다.</div>`;
            panel.classList.remove('empty');
            document.getElementById('overhead-info').style.display = 'none';
            
        } catch (e) {
            const panel = document.getElementById('result-panel');
            panel.innerHTML = `<div class="alert warning alert-compact"><strong class="alert-title">❌ 서명 생성 실패</strong>${e.message.replace(/\n/g, '<br>')}</div>`;
        }
    });

    document.getElementById('btn-diagnose').addEventListener('click', async () => {
        const panel = document.getElementById('result-panel');
        panel.classList.remove('empty');
        panel.textContent = '진단 중...';

        let spacedFields = [];
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
            const result = await PopCore.diagnose(inputs);
            renderResult(result);
            
            if (spacedFields.length > 0) {
                result.warnings.push(`다음 입력값의 앞뒤나 중간에 잘못된 공백(띄어쓰기, 줄바꿈)이 포함되어 있어 제거 후 진단했습니다: ${spacedFields.join(', ')}`);
            }
            if (result.warnings && result.warnings.length > 0) {
                const wDiv = document.createElement('div');
                wDiv.className = 'alert info';
                let html = `💡 <strong>진단기 자동 교정 안내:</strong><br><ul class='warning-list'>`;
                result.warnings.forEach(w => { html += `<li>${w}</li>`; });
                html += `</ul>`;
                wDiv.innerHTML = html;
                panel.insertBefore(wDiv, panel.firstChild);
            }
            
            if (!result.error && result.firstFailedStage === null) {
                
            document.getElementById('overhead-info').style.display = 'block';
            } else {
                document.getElementById('overhead-info').style.display = 'none';
            }
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
        errDiv.innerHTML = `<strong>입력 오류:</strong><br>${result.error.message.replace(/\n/g, '<br>')}`;
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
            pExp.textContent = "문자열 차이점 (- 클라이언트가 서명한 잘못된 값 / + 게이트웨이가 요구하는 올바른 규격):";
            hBox.appendChild(pExp);

            const diffBox = document.createElement('div');
            diffBox.className = 'diff-view';
            
            const expLines = result.expectedCanonical.split('\n'); // Correct (Gateway)
            const actLines = set.canonical.split('\n'); // Wrong (Client)
            const maxLines = Math.max(expLines.length, actLines.length);
            
            for (let i = 0; i < maxLines; i++) {
                const el = expLines[i] ?? '';
                const al = actLines[i] ?? '';
                if (el === al) {
                    const row = document.createElement('div');
                    row.className = 'diff-row match';
                    row.textContent = el === '' ? '(empty)' : el.replace(/\r/g, '\\r');
                    diffBox.appendChild(row);
                } else {
                    // 클라이언트가 서명한 잘못된 값 (-)
                    const rowAct = document.createElement('div');
                    rowAct.className = 'diff-row expected'; // expected CSS is Red (-)
                    rowAct.textContent = al === '' ? '(empty)' : al.replace(/\r/g, '\\r');
                    
                    // 게이트웨이가 요구하는 올바른 값 (+)
                    const rowExp = document.createElement('div');
                    rowExp.className = 'diff-row actual'; // actual CSS is Green (+)
                    rowExp.textContent = el === '' ? '(empty)' : el.replace(/\r/g, '\\r');
                    
                    diffBox.appendChild(rowAct);
                    diffBox.appendChild(rowExp);
                }
            }
            hBox.appendChild(diffBox);

        } else if (hRes.type === 'no-match') {
            hBox.className = 'hypothesis-box error';
            
            const h5 = document.createElement('h5');
            h5.textContent = '원인 파악 실패 (일치하는 실수 패턴 없음)';
            hBox.appendChild(h5);
            
            const p = document.createElement('p');
            p.innerHTML = `진단기가 알고 있는 '흔한 실수 패턴'들을 모두 대입해 보았으나 유효한 서명을 찾지 못했습니다.<br><br><b>💡 예상되는 원인:</b><br>1. 서명할 때 사용한 비공개키(Private Key)와 입력하신 공개키(Public Key)가 서로 짝이 맞지 않음<br>2. ECDSA P-256 알고리즘이 아닌 다른 방식으로 서명됨<br>3. 진단기가 예측할 수 없는 방식으로 데이터가 변형됨`;
            hBox.appendChild(p);
            
            const pExp = document.createElement('p');
            pExp.className = 'desc-label';
            pExp.textContent = "서명 검증 시 서버(게이트웨이)가 기준값으로 기대했던 문자열은 다음과 같습니다:";
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

// 탭 전환 로직
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        
        btn.classList.add('active');
        document.getElementById(btn.dataset.target).classList.add('active');
    });
});
