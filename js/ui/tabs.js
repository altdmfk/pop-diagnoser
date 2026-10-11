(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    function getNextTabIndex(currentIndex, key, totalTabs) {
        if (!Number.isInteger(totalTabs) || totalTabs <= 0) return null;
        if (!Number.isInteger(currentIndex) || currentIndex < 0 || currentIndex >= totalTabs) return null;
        switch (key) {
            case 'ArrowRight':
                return (currentIndex + 1) % totalTabs;
            case 'ArrowLeft':
                return (currentIndex - 1 + totalTabs) % totalTabs;
            case 'Home':
                return 0;
            case 'End':
                return totalTabs - 1;
            default:
                return null;
        }
    }

    function activateTab(tabButtons, tabPanes, index, shouldFocus = false) {
        const btnArray = Array.from(tabButtons);
        const targetBtn = btnArray[index];
        if (!targetBtn) return;

        btnArray.forEach((b, idx) => {
            const isSelected = idx === index;
            b.classList.toggle('active', isSelected);
            b.setAttribute('aria-selected', isSelected ? 'true' : 'false');
            b.setAttribute('tabindex', isSelected ? '0' : '-1');
        });

        tabPanes.forEach(p => {
            p.classList.toggle('active', p.id === targetBtn.dataset.target);
        });

        if (shouldFocus && typeof targetBtn.focus === 'function') {
            targetBtn.focus();
        }
    }

    function initTabs() {
        if (typeof document === 'undefined') return;
        const tabButtons = document.querySelectorAll('.tab-btn');
        const tabPanes = document.querySelectorAll('.tab-pane');
        const btnArray = Array.from(tabButtons);

        btnArray.forEach((btn, idx) => {
            btn.addEventListener('click', () => {
                activateTab(tabButtons, tabPanes, idx, false);
            });

            btn.addEventListener('keydown', (e) => {
                const nextIdx = getNextTabIndex(idx, e.key, btnArray.length);
                if (nextIdx !== null) {
                    e.preventDefault();
                    activateTab(tabButtons, tabPanes, nextIdx, true);
                }
            });
        });
    }

    return { getNextTabIndex, initTabs };
});

