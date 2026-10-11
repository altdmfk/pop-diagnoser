(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    function isFullWidthChar(ch) {
        if (!ch) return false;
        const code = ch.charCodeAt(0);
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

    function getJsonErrorSnippet(e, jsonStr) {
        let msg = e && e.message ? e.message : String(e);
        try {
            const lineColMatch = msg.match(/line\s+(\d+)\s+column\s+(\d+)/i);
            const posMatch = msg.match(/position\s+(\d+)/i);
            if ((lineColMatch || posMatch) && jsonStr) {
                let lineNum = 1, colNum = 1;

                if (lineColMatch) {
                    lineNum = parseInt(lineColMatch[1], 10);
                    colNum = parseInt(lineColMatch[2], 10);
                } else if (posMatch) {
                    const pos = parseInt(posMatch[1], 10);
                    const upToPos = jsonStr.substring(0, pos);
                    const upToLines = upToPos.split(/\r?\n/);
                    lineNum = upToLines.length;
                    colNum = upToLines[upToLines.length - 1].length + 1;
                }

                const lines = jsonStr.split(/\r?\n/);
                if (lineNum > 0 && lineNum <= lines.length) {
                    const problemLine = lines[lineNum - 1];
                    let pointer = '';
                    const limit = Math.min(colNum - 1, problemLine.length);
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

                    msg = msg.replace(/in JSON at position.*$/, '').replace(/at line \d+ column \d+.*$/, '').trim();
                    return `${msg}\n\n[문제 발생 위치: ${lineNum}번째 줄, ${colNum}번째 칸]\n${problemLine}\n${pointer}`;
                }
            }
        } catch (err) {}
        return msg;
    }

    return { isFullWidthChar, getJsonErrorSnippet };
});
