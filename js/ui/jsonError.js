(function (root, factory) {
    const coreJsonError = (typeof module !== 'undefined' && module.exports)
        ? require('../core/jsonError.js')
        : root.PopCore;
    const mod = factory(coreJsonError);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (coreJsonError) {
    function isFullWidthChar(ch) {
        if (ch === undefined || ch === null || ch === '') return false;
        const code = typeof ch === 'number' ? ch : String(ch).charCodeAt(0);
        return (
            (code >= 0x1100 && code <= 0x11FF) ||
            (code >= 0x2E80 && code <= 0x9FFF) ||
            (code >= 0xAC00 && code <= 0xD7A3) ||
            (code >= 0xF900 && code <= 0xFAFF) ||
            (code >= 0xFE30 && code <= 0xFE6F) ||
            (code >= 0xFF01 && code <= 0xFF60) ||
            (code >= 0xFFE0 && code <= 0xFFE6)
        );
    }

    /**
     * UI presentation helper: builds a visual code snippet with a full-width
     * compensated pointer (`▲`) from structured location data (`line`, `column`, `problemLine`, `cleanMessage`).
     */
    function formatJsonErrorSnippet(loc) {
        if (!loc || typeof loc !== 'object') return '';
        if (typeof loc.line !== 'number' || typeof loc.column !== 'number' || typeof loc.problemLine !== 'string') {
            return typeof loc.detail === 'string'
                ? loc.detail
                : (typeof loc.cleanMessage === 'string' ? loc.cleanMessage : (loc.message ? String(loc.message) : ''));
        }

        const problemLine = loc.problemLine;
        let pointer = '';
        const limit = Math.max(0, Math.min(loc.column - 1, problemLine.length));
        for (let i = 0; i < limit; i++) {
            const ch = problemLine[i];
            if (ch === '\t') {
                pointer += '\t';
            } else if (isFullWidthChar(ch)) {
                pointer += '  ';
            } else {
                pointer += ' ';
            }
        }
        pointer += '▲';

        const headerMsg = loc.cleanMessage || loc.message || '';
        return `${headerMsg}\n\n[문제 발생 위치: ${loc.line}번째 줄, ${loc.column}번째 칸]\n${problemLine}\n${pointer}`;
    }

    function getJsonErrorSnippet(e, jsonStr) {
        const loc = coreJsonError && typeof coreJsonError.extractJsonErrorLocation === 'function'
            ? coreJsonError.extractJsonErrorLocation(e, jsonStr)
            : { message: e && e.message ? e.message : String(e ?? ''), line: null, column: null, problemLine: null };
        if (loc.line !== null && loc.column !== null && loc.problemLine !== null) {
            return formatJsonErrorSnippet(loc);
        }
        return loc.message;
    }

    return {
        isFullWidthChar,
        formatJsonErrorSnippet,
        getJsonErrorSnippet
    };
});
