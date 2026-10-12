(function (root, factory) {
    const renderMod = (typeof module !== 'undefined' && module.exports)
        ? require('./render.js')
        : root.PopUI;
    const inspectorMod = (typeof module !== 'undefined' && module.exports)
        ? require('./inspector.js')
        : root.PopUI;
    const mod = factory(renderMod, inspectorMod);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (renderMod, inspectorMod) {
    const STORAGE_KEY = 'popDiagnoserSlots';
    const MAX_SLOTS = 5;
    const SLOT_FIELD_MAP = [
        { key: 'method', id: 'req-method' },
        { key: 'urlStr', id: 'req-url' },
        { key: 'bodyStr', id: 'req-body' },
        { key: 'nonce', id: 'req-nonce' },
        { key: 'timestampStr', id: 'req-timestamp' },
        { key: 'signature', id: 'req-signature' },
        { key: 'reqDigest', id: 'req-digest' },
        { key: 'pubkeyPem', id: 'req-pubkey' },
        { key: 'evalTime', id: 'eval-timestamp' }
    ];

    function readMemorySlots(storage) {
        const targetStorage = storage !== undefined ? storage : (typeof localStorage !== 'undefined' ? localStorage : null);
        try {
            const raw = targetStorage.getItem(STORAGE_KEY);
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

    function writeMemorySlots(memory, storage) {
        const targetStorage = storage !== undefined ? storage : (typeof localStorage !== 'undefined' ? localStorage : null);
        try {
            targetStorage.setItem(STORAGE_KEY, JSON.stringify(memory));
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
                btnSave.type = 'button';
                btnSave.className = 'btn-small btn-slot-save';
                btnSave.textContent = '💾 현재 입력 저장';
                btnSave.addEventListener('click', () => saveToSlot(i));
                slotDiv.appendChild(btnSave);

                if (slotData && typeof slotData === 'object') {
                    const btnLoad = document.createElement('button');
                    btnLoad.type = 'button';
                    btnLoad.className = 'btn-small btn-slot-load';
                    btnLoad.textContent = '📂 불러오기';
                    btnLoad.addEventListener('click', () => loadFromSlot(i));
                    slotDiv.appendChild(btnLoad);

                    const btnDel = document.createElement('button');
                    btnDel.type = 'button';
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
                time: new Date().toLocaleTimeString('ko-KR', { hour12: false })
            };
            for (const item of SLOT_FIELD_MAP) {
                const el = document.getElementById(item.id);
                if (!el) {
                    data[item.key] = '';
                } else if (
                    item.key === 'bodyStr' &&
                    typeof el._rawBody === 'string' &&
                    (el._rawBody === el.value || el._rawBody.replace(/\r\n/g, '\n') === el.value)
                ) {
                    data[item.key] = el._rawBody;
                } else {
                    data[item.key] = el.value;
                }
            }
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
                for (const item of SLOT_FIELD_MAP) {
                    const el = document.getElementById(item.id);
                    if (el) {
                        const val = data[item.key] || '';
                        el.value = val;
                        if (item.key === 'bodyStr') {
                            el._rawBody = val;
                        }
                    }
                }
                showToast(`📂 슬롯 ${i}의 데이터를 성공적으로 불러왔습니다.`);
                const panel = document.getElementById('result-panel');
                setPlaceholder(panel, [
                    '데이터를 성공적으로 불러왔습니다.',
                    "확인을 위해 '진단 시작' 버튼을 눌러주세요."
                ]);
                setOverheadVisible(false);
                if (inspectorMod && typeof inspectorMod.resetInspector === 'function') {
                    inspectorMod.resetInspector();
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
