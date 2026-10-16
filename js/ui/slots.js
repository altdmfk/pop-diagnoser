(function (root, factory) {
    const renderMod = (typeof module !== 'undefined' && module.exports)
        ? require('./render.js')
        : root.PopUI;
    const inspectorMod = (typeof module !== 'undefined' && module.exports)
        ? require('./inspector.js')
        : root.PopUI;
    const importerMod = (typeof module !== 'undefined' && module.exports)
        ? require('./importer.js')
        : root.PopUI;
    const mod = factory(renderMod, inspectorMod, importerMod);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (renderMod, inspectorMod, importerMod) {
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

    function extractSlotPath(urlStr) {
        if (!urlStr || typeof urlStr !== 'string' || !urlStr.trim()) return '(URL 없음)';
        const trimmed = urlStr.trim();
        try {
            if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
                const u = new URL(trimmed);
                return u.pathname || '/';
            }
            const dummy = new URL(trimmed.startsWith('/') ? trimmed : '/' + trimmed, 'http://localhost');
            return dummy.pathname || '/';
        } catch (e) {
            return '(URL 없음)';
        }
    }

    function deriveDefaultLabel(slotData) {
        if (!slotData || typeof slotData !== 'object') return '';
        const method = (slotData.method || '').trim().toUpperCase();
        const path = extractSlotPath(slotData.urlStr);
        if (method && path) {
            return `${method} ${path}`;
        }
        if (method) return method;
        if (path) return path;
        return '(URL 없음)';
    }

    function getUtf8ByteLength(str) {
        if (!str || typeof str !== 'string') return 0;
        if (typeof TextEncoder !== 'undefined') {
            return new TextEncoder().encode(str).length;
        }
        try {
            return unescape(encodeURIComponent(str)).length;
        } catch (e) {
            return str.length;
        }
    }

    function formatSavedTime(savedAt, fallbackTime, now) {
        if (typeof savedAt === 'number' && Number.isFinite(savedAt)) {
            const d = new Date(savedAt);
            const refNow = (now instanceof Date) ? now : new Date();
            const isToday = d.getFullYear() === refNow.getFullYear() &&
                            d.getMonth() === refNow.getMonth() &&
                            d.getDate() === refNow.getDate();
            const pad = (n) => String(n).padStart(2, '0');
            if (isToday) {
                return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
            }
            return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
        }
        return fallbackTime || '';
    }

    function formatSlotPreview(slotData) {
        if (!slotData || typeof slotData !== 'object') return '';
        const fullUrl = (slotData.urlStr && typeof slotData.urlStr === 'string' && slotData.urlStr.trim())
            ? slotData.urlStr.trim()
            : '(URL 없음)';

        let bodyPreview = '(본문 없음)';
        if (slotData.bodyStr && typeof slotData.bodyStr === 'string' && slotData.bodyStr.trim()) {
            const rawLines = slotData.bodyStr.split(/\r?\n/).slice(0, 2).join(' ');
            const trimmed = rawLines.trim();
            bodyPreview = trimmed.length > 120 ? trimmed.slice(0, 120) + '…' : trimmed;
        }

        let sigPreview = '(서명 없음)';
        if (slotData.signature && typeof slotData.signature === 'string' && slotData.signature.trim()) {
            const trimmedSig = slotData.signature.trim();
            sigPreview = trimmedSig.length > 16
                ? trimmedSig.slice(0, 16) + '…'
                : trimmedSig;
        }

        return `URL: ${fullUrl}\n본문: ${bodyPreview}\n서명: ${sigPreview}`;
    }

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
                const isFilled = Boolean(slotData && typeof slotData === 'object');
                const slotDiv = document.createElement('div');
                slotDiv.className = 'memory-slot';

                const titleContainer = document.createElement('div');
                titleContainer.className = 'slot-title-container';

                if (!isFilled) {
                    const emptyTitle = document.createElement('span');
                    emptyTitle.className = 'slot-empty-title';
                    emptyTitle.textContent = `슬롯 ${i}: 비어 있음`;
                    titleContainer.appendChild(emptyTitle);
                    slotDiv.appendChild(titleContainer);

                    const btnSave = document.createElement('button');
                    btnSave.type = 'button';
                    btnSave.className = 'btn-small btn-slot-save';
                    btnSave.textContent = '저장';
                    btnSave.setAttribute('aria-label', `슬롯 ${i} 저장`);
                    btnSave.addEventListener('click', () => saveToSlot(i));
                    slotDiv.appendChild(btnSave);
                } else {
                    slotDiv.setAttribute('title', formatSlotPreview(slotData));

                    const currentLabel = (slotData.label && typeof slotData.label === 'string' && slotData.label.trim())
                        ? slotData.label.trim()
                        : deriveDefaultLabel(slotData);

                    const slotPrefix = document.createElement('span');
                    slotPrefix.className = 'slot-prefix';
                    slotPrefix.textContent = `슬롯 ${i}: `;
                    titleContainer.appendChild(slotPrefix);

                    const labelSpan = document.createElement('span');
                    labelSpan.className = 'slot-label-text';
                    labelSpan.textContent = currentLabel;
                    labelSpan.setAttribute('role', 'button');
                    labelSpan.setAttribute('tabindex', '0');
                    labelSpan.setAttribute('aria-label', `슬롯 ${i} 이름 변경`);
                    titleContainer.appendChild(labelSpan);

                    let isRenaming = false;
                    function startRename() {
                        if (isRenaming) return;
                        isRenaming = true;
                        labelSpan.classList.add('hidden');

                        const input = document.createElement('input');
                        input.type = 'text';
                        input.className = 'slot-rename-input';
                        input.maxLength = 40;
                        input.value = (slotData.label && typeof slotData.label === 'string' && slotData.label.trim())
                            ? slotData.label.trim()
                            : currentLabel;
                        input.setAttribute('aria-label', `슬롯 ${i} 이름 수정`);

                        let committed = false;
                        function commitRename(saveValue) {
                            if (committed) return;
                            committed = true;
                            if (saveValue !== null) {
                                const newLabel = saveValue.trim();
                                slotData.label = newLabel;
                                const readRes = readMemorySlots();
                                const currentMemory = readRes.data || {};
                                currentMemory[`slot_${i}`] = slotData;
                                const writeRes = writeMemorySlots(currentMemory);
                                if (!writeRes.ok) {
                                    showToast('브라우저 저장소(localStorage)가 차단되었거나 용량이 부족하여 슬롯 이름을 변경할 수 없습니다.', true);
                                    return;
                                }
                                showToast(`슬롯 ${i}의 이름이 변경되었습니다.`);
                            }
                            renderMemorySlots();
                        }

                        input.addEventListener('keydown', (e) => {
                            if (e.key === 'Enter') {
                                e.preventDefault();
                                commitRename(input.value);
                            } else if (e.key === 'Escape') {
                                e.preventDefault();
                                commitRename(null);
                            }
                        });
                        input.addEventListener('blur', () => {
                            commitRename(input.value);
                        });

                        titleContainer.appendChild(input);
                        input.focus();
                        input.select();
                    }

                    labelSpan.addEventListener('dblclick', () => startRename());
                    labelSpan.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            startRename();
                        }
                    });

                    slotDiv.appendChild(titleContainer);

                    const btnRename = document.createElement('button');
                    btnRename.type = 'button';
                    btnRename.className = 'btn-small btn-slot-rename';
                    btnRename.textContent = '이름 변경';
                    btnRename.setAttribute('aria-label', `슬롯 ${i} 이름 변경`);
                    btnRename.addEventListener('click', () => startRename());
                    slotDiv.appendChild(btnRename);

                    const btnOverwrite = document.createElement('button');
                    btnOverwrite.type = 'button';
                    btnOverwrite.className = 'btn-small btn-slot-save btn-slot-overwrite';
                    btnOverwrite.textContent = '덮어쓰기';
                    btnOverwrite.setAttribute('aria-label', `슬롯 ${i} 덮어쓰기`);

                    const confirmBar = document.createElement('span');
                    confirmBar.className = 'slot-confirm-bar hidden';

                    const confirmMsg = document.createElement('span');
                    confirmMsg.className = 'slot-confirm-msg';
                    confirmMsg.textContent = '덮어쓰시겠습니까?';
                    confirmBar.appendChild(confirmMsg);

                    const btnYes = document.createElement('button');
                    btnYes.type = 'button';
                    btnYes.className = 'btn-small btn-confirm-yes';
                    btnYes.textContent = '확인';
                    btnYes.addEventListener('click', () => {
                        saveToSlot(i);
                    });
                    confirmBar.appendChild(btnYes);

                    const btnNo = document.createElement('button');
                    btnNo.type = 'button';
                    btnNo.className = 'btn-small btn-confirm-no';
                    btnNo.textContent = '취소';
                    btnNo.addEventListener('click', () => {
                        confirmBar.classList.add('hidden');
                        btnOverwrite.classList.remove('hidden');
                    });
                    confirmBar.appendChild(btnNo);

                    btnOverwrite.addEventListener('click', () => {
                        btnOverwrite.classList.add('hidden');
                        confirmBar.classList.remove('hidden');
                    });

                    slotDiv.appendChild(btnOverwrite);
                    slotDiv.appendChild(confirmBar);

                    const btnLoad = document.createElement('button');
                    btnLoad.type = 'button';
                    btnLoad.className = 'btn-small btn-slot-load';
                    btnLoad.textContent = '불러오기';
                    btnLoad.setAttribute('aria-label', `슬롯 ${i} 불러오기`);
                    btnLoad.addEventListener('click', () => loadFromSlot(i));
                    slotDiv.appendChild(btnLoad);

                    const btnDel = document.createElement('button');
                    btnDel.type = 'button';
                    btnDel.className = 'btn-small btn-slot-delete';
                    btnDel.textContent = '삭제';
                    btnDel.setAttribute('aria-label', `슬롯 ${i} 삭제`);
                    btnDel.addEventListener('click', () => deleteSlot(i));
                    slotDiv.appendChild(btnDel);

                    const metaRow = document.createElement('div');
                    metaRow.className = 'slot-meta-row';

                    const methodTag = document.createElement('span');
                    methodTag.className = 'slot-method-tag';
                    methodTag.textContent = (slotData.method && slotData.method.trim())
                        ? slotData.method.trim().toUpperCase()
                        : 'METHOD';
                    metaRow.appendChild(methodTag);

                    const path = extractSlotPath(slotData.urlStr);
                    const bodyBytes = getUtf8ByteLength(slotData.bodyStr);
                    const bodyText = bodyBytes > 0 ? `본문 ${bodyBytes}B` : '본문 없음';
                    const hasSig = Boolean(slotData.signature && slotData.signature.trim().length > 0);
                    const sigText = hasSig ? '서명 헤더 있음' : '서명 헤더 없음';
                    const timeText = formatSavedTime(slotData.savedAt, slotData.time);

                    const metaItems = [path, bodyText, sigText];
                    if (timeText) metaItems.push(timeText);

                    const metaDetails = document.createElement('span');
                    metaDetails.className = 'slot-meta-details';
                    metaDetails.textContent = metaItems.join(' · ');
                    metaRow.appendChild(metaDetails);

                    slotDiv.appendChild(metaRow);
                }

                container.appendChild(slotDiv);
            }
        }

        function getSetRawTextareaValue() {
            if (importerMod && typeof importerMod.setRawTextareaValue === 'function') {
                return importerMod.setRawTextareaValue;
            }
            if (typeof globalThis !== 'undefined' && globalThis.PopUI && typeof globalThis.PopUI.setRawTextareaValue === 'function') {
                return globalThis.PopUI.setRawTextareaValue;
            }
            return null;
        }

        function getReadRequestContentType() {
            if (importerMod && typeof importerMod.readRequestContentType === 'function') {
                return importerMod.readRequestContentType;
            }
            if (typeof globalThis !== 'undefined' && globalThis.PopUI && typeof globalThis.PopUI.readRequestContentType === 'function') {
                return globalThis.PopUI.readRequestContentType;
            }
            return null;
        }

        function saveToSlot(i) {
            const now = new Date();
            const data = {
                time: now.toLocaleTimeString('ko-KR', { hour12: false }),
                savedAt: now.getTime()
            };
            const readExisting = readMemorySlots();
            const existingSlot = (readExisting.data || {})[`slot_${i}`];
            if (existingSlot && typeof existingSlot.label === 'string') {
                data.label = existingSlot.label;
            }

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
            const bodyEl = document.getElementById('req-body');
            const readCt = getReadRequestContentType();
            data.contentType = typeof readCt === 'function'
                ? readCt(bodyEl)
                : ((bodyEl && typeof bodyEl._contentType === 'string') ? bodyEl._contentType : '');

            const readRes = readMemorySlots();
            const memory = readRes.data || {};
            memory[`slot_${i}`] = data;
            const writeRes = writeMemorySlots(memory);
            if (!writeRes.ok) {
                showToast('브라우저 저장소(localStorage)가 차단되었거나 용량이 부족하여 슬롯에 저장할 수 없습니다.', true);
                return;
            }
            showToast(`슬롯 ${i}에 현재 작업이 저장되었습니다.`);
            renderMemorySlots();
        }

        function loadFromSlot(i) {
            const readRes = readMemorySlots();
            if (!readRes.ok) {
                showToast('브라우저 저장소 데이터를 읽을 수 없습니다. (저장소 차단 또는 데이터 손상)', true);
                return;
            }
            const data = readRes.data[`slot_${i}`];
            if (data && typeof data === 'object') {
                const setRaw = getSetRawTextareaValue();
                for (const item of SLOT_FIELD_MAP) {
                    const el = document.getElementById(item.id);
                    if (el) {
                        const val = data[item.key] || '';
                        el.value = val;
                        if (item.key === 'bodyStr') {
                            if (typeof setRaw === 'function') {
                                setRaw(el, val, data.contentType || '');
                            } else {
                                el._rawBody = val;
                                if (data.contentType) {
                                    el._contentType = String(data.contentType);
                                } else {
                                    delete el._contentType;
                                }
                            }
                        }
                    }
                }
                showToast(`슬롯 ${i}의 데이터를 성공적으로 불러왔습니다.`);
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
                showToast('브라우저 저장소(localStorage)가 차단되어 삭제할 수 없습니다.', true);
                return;
            }
            const memory = readRes.data || {};
            delete memory[`slot_${i}`];
            const writeRes = writeMemorySlots(memory);
            if (!writeRes.ok) {
                showToast('브라우저 저장소(localStorage)가 차단되어 삭제 내용을 반영할 수 없습니다.', true);
                return;
            }
            showToast(`슬롯 ${i}의 데이터가 삭제되었습니다.`);
            renderMemorySlots();
        }

        renderMemorySlots();
    }

    return {
        STORAGE_KEY,
        MAX_SLOTS,
        readMemorySlots,
        writeMemorySlots,
        initMemorySlots,
        extractSlotPath,
        deriveDefaultLabel,
        getUtf8ByteLength,
        formatSavedTime,
        formatSlotPreview
    };
});
