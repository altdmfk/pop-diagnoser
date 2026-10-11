(function (root, factory) {
    const renderMod = (typeof module !== 'undefined' && module.exports)
        ? require('./render.js')
        : root.PopUI;
    const mod = factory(renderMod);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (renderMod) {
    const STORAGE_KEY = 'popDiagnoserSlots';
    const MAX_SLOTS = 5;

    function readMemorySlots() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return { ok: true, data: {} };
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                return { ok: false, reason: 'corrupted', data: {} };
            }
            return { ok: true, data: parsed };
        } catch (e) {
            return { ok: false, reason: 'blocked', error: e, data: {} };
        }
    }

    function writeMemorySlots(memory) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(memory));
            return { ok: true };
        } catch (e) {
            return { ok: false, error: e };
        }
    }

    function initMemorySlots() {
        if (typeof document === 'undefined') return;
        const { showToast, setPlaceholder, setOverheadVisible } = renderMod;

        function renderMemorySlots() {
            const { data: memory } = readMemorySlots();
            const container = document.getElementById('memory-slots-container');
            if (!container) return;
            container.textContent = '';

            for (let i = 1; i <= MAX_SLOTS; i++) {
                const slotData = memory[`slot_${i}`];
                const slotDiv = document.createElement('div');
                slotDiv.className = 'memory-slot';

                const titleSpan = document.createElement('span');
                titleSpan.className = 'memory-slot-name';
                titleSpan.textContent = (slotData && typeof slotData === 'object')
                    ? `슬롯 ${i} (저장됨: ${slotData.time || ''})`
                    : `슬롯 ${i} (비어있음)`;
                slotDiv.appendChild(titleSpan);

                const btnSave = document.createElement('button');
                btnSave.className = 'btn-small btn-slot-save';
                btnSave.textContent = '💾 현재 입력 저장';
                btnSave.addEventListener('click', () => saveToSlot(i));
                slotDiv.appendChild(btnSave);

                if (slotData && typeof slotData === 'object') {
                    const btnLoad = document.createElement('button');
                    btnLoad.className = 'btn-small btn-slot-load';
                    btnLoad.textContent = '📂 불러오기';
                    btnLoad.addEventListener('click', () => loadFromSlot(i));
                    slotDiv.appendChild(btnLoad);

                    const btnDel = document.createElement('button');
                    btnDel.className = 'btn-small btn-slot-delete';
                    btnDel.textContent = '🗑️ 삭제';
                    btnDel.addEventListener('click', () => deleteSlot(i));
                    slotDiv.appendChild(btnDel);
                }
                container.appendChild(slotDiv);
            }
        }

        function saveToSlot(i) {
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
            const readRes = readMemorySlots();
            const memory = readRes.data;
            memory[`slot_${i}`] = data;
            const writeRes = writeMemorySlots(memory);
            if (!writeRes.ok) {
                showToast('⚠️ 브라우저 저장소(localStorage)가 차단되었거나 용량이 부족하여 슬롯에 저장할 수 없습니다.', true);
                return;
            }
            showToast(`💾 슬롯 ${i}에 현재 작업이 저장되었습니다.`);
            renderMemorySlots();
        }

        function loadFromSlot(i) {
            const readRes = readMemorySlots();
            if (!readRes.ok) {
                showToast('⚠️ 브라우저 저장소 데이터를 읽을 수 없습니다. (저장소 차단 또는 데이터 손상)', true);
                return;
            }
            const data = readRes.data[`slot_${i}`];
            if (data && typeof data === 'object') {
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
                setPlaceholder(panel, [
                    '데이터를 성공적으로 불러왔습니다.',
                    "확인을 위해 '진단 시작' 버튼을 눌러주세요."
                ]);
                setOverheadVisible(false);
                if (typeof renderMod.resetInspector === 'function') {
                    renderMod.resetInspector();
                }
            }
        }

        function deleteSlot(i) {
            const readRes = readMemorySlots();
            if (!readRes.ok && readRes.reason === 'blocked') {
                showToast('⚠️ 브라우저 저장소(localStorage)가 차단되어 삭제할 수 없습니다.', true);
                return;
            }
            const memory = readRes.data;
            delete memory[`slot_${i}`];
            const writeRes = writeMemorySlots(memory);
            if (!writeRes.ok) {
                showToast('⚠️ 브라우저 저장소(localStorage)가 차단되어 삭제 내용을 반영할 수 없습니다.', true);
                return;
            }
            showToast(`🗑️ 슬롯 ${i}의 데이터가 삭제되었습니다.`);
            renderMemorySlots();
        }

        renderMemorySlots();
    }

    return {
        STORAGE_KEY,
        MAX_SLOTS,
        readMemorySlots,
        writeMemorySlots,
        initMemorySlots
    };
});
