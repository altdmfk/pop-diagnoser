(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    const JSON_HINT_CODES = {
        MISSING_OPEN_BRACE: 'ERR_JSON_MISSING_OPEN_BRACE',
        MISSING_OPEN_BRACKET: 'ERR_JSON_MISSING_OPEN_BRACKET',
        MISSING_CLOSE_BRACE: 'ERR_JSON_MISSING_CLOSE_BRACE',
        MISSING_CLOSE_BRACKET: 'ERR_JSON_MISSING_CLOSE_BRACKET',
        TRAILING_COMMA: 'ERR_JSON_TRAILING_COMMA',
        SINGLE_QUOTE: 'ERR_JSON_SINGLE_QUOTE',
        UNQUOTED_KEY: 'ERR_JSON_UNQUOTED_KEY',
        UNQUOTED_VALUE: 'ERR_JSON_UNQUOTED_VALUE',
        SYNTAX_ERROR: 'ERR_JSON_SYNTAX_ERROR'
    };

    function detectJsonErrorHint(e, jsonStr) {
        if (!jsonStr || typeof jsonStr !== 'string') return null;
        const trimmed = jsonStr.trim();
        if (!trimmed) return null;

        const startsWithBrace = trimmed.startsWith('{') || trimmed.startsWith('[');
        if (!startsWithBrace) {
            if (trimmed.endsWith('}') || /"[^"\\\r\n]+"\s*:/.test(trimmed)) {
                const startsWithQuote = trimmed.startsWith('"');
                const reason = startsWithQuote
                    ? "첫 번째 키-값 쌍이 단일 문자열로 처리되어 뒤따르는 콜론(:)에서 문법 오류가 감지되었습니다."
                    : "객체 형식을 시작하려면 맨 앞에 '{'가 있어야 합니다.";
                return {
                    hintCode: JSON_HINT_CODES.MISSING_OPEN_BRACE,
                    hint: `맨 앞의 여는 중괄호('{')가 누락된 것으로 보입니다. ${reason}`,
                    hintExample: '(예: { "key": "value" })'
                };
            }
            if (trimmed.endsWith(']')) {
                return {
                    hintCode: JSON_HINT_CODES.MISSING_OPEN_BRACKET,
                    hint: "맨 앞의 여는 대괄호('[')가 누락된 것으로 보입니다.",
                    hintExample: '(예: [ "item1", "item2" ])'
                };
            }
        }

        if (trimmed.startsWith('{') && !trimmed.endsWith('}')) {
            return {
                hintCode: JSON_HINT_CODES.MISSING_CLOSE_BRACE,
                hint: "맨 끝의 닫는 중괄호('}')가 누락되었거나 본문 끝이 잘려 있는지 확인해 주세요.",
                hintExample: '(예: { ... })'
            };
        }
        if (trimmed.startsWith('[') && !trimmed.endsWith(']')) {
            return {
                hintCode: JSON_HINT_CODES.MISSING_CLOSE_BRACKET,
                hint: "맨 끝의 닫는 대괄호(']')가 누락되었거나 본문 끝이 잘려 있는지 확인해 주세요.",
                hintExample: '(예: [ ... ])'
            };
        }

        if (/,\s*[}\]]/.test(trimmed)) {
            return {
                hintCode: JSON_HINT_CODES.TRAILING_COMMA,
                hint: "마지막 항목 뒤에 불필요한 쉼표(',')가 붙어 있습니다. JSON 표준에서는 마지막 쉼표(Trailing Comma)를 허용하지 않습니다.",
                hintExample: '(예: {"a": 1,} ➔ {"a": 1})'
            };
        }

        if (/'[^'\\\r\n]*'\s*:/.test(trimmed) || /:\s*'[^'\\\r\n]*'/.test(trimmed)) {
            return {
                hintCode: JSON_HINT_CODES.SINGLE_QUOTE,
                hint: "JSON에서는 작은따옴표(')를 사용할 수 없으며, 키와 문자열 값은 반드시 큰따옴표(\")로 감싸야 합니다.",
                hintExample: '(예: {\'key\': \'val\'} ➔ {"key": "val"})'
            };
        }

        const unquotedKeyMatch = trimmed.match(/(?:[{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$-]*)\s*:/);
        if (unquotedKeyMatch && !unquotedKeyMatch[1].startsWith('"')) {
            return {
                hintCode: JSON_HINT_CODES.UNQUOTED_KEY,
                hint: `JSON의 키(속성명) '${unquotedKeyMatch[1]}'는 반드시 큰따옴표(\")로 감싸야 합니다.`,
                hintExample: `(예: "${unquotedKeyMatch[1]}": ...)`
            };
        }

        const unquotedValMatch = trimmed.match(/:\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[,}\]]/);
        if (unquotedValMatch) {
            const val = unquotedValMatch[1];
            if (!['true', 'false', 'null'].includes(val)) {
                return {
                    hintCode: JSON_HINT_CODES.UNQUOTED_VALUE,
                    hint: `값 '${val}'이(가) 큰따옴표(\")로 감싸져 있지 않거나 유효하지 않은 JSON 값입니다.`,
                    hintExample: `(예: "${val}")`
                };
            }
        }

        return {
            hintCode: JSON_HINT_CODES.SYNTAX_ERROR,
            hint: "중괄호({, })나 대괄호([, ]), 쉼표(,), 큰따옴표(\")의 짝이 올바르게 맞는지 확인해 주세요.",
            hintExample: '(예: {"key": "value"})'
        };
    }

    /**
     * Pure Core helper: extracts 1-based line/column, raw problem line, and smart hint
     * without constructing any UI/terminal visual pointer strings (`▲`).
     * Supports both `extractJsonErrorLocation(e, jsonStr)` and `extractJsonErrorLocation(jsonStr, errMsg)`.
     */
    function extractJsonErrorLocation(arg1, arg2) {
        let e = arg1;
        let jsonStr = arg2;
        if (
            typeof arg1 === 'string' &&
            typeof arg2 === 'string' &&
            /position\s+\d+|line\s+\d+\s+column\s+\d+|^Unexpected|^JSON\.parse/i.test(arg2) &&
            !/position\s+\d+|line\s+\d+\s+column\s+\d+/i.test(arg1)
        ) {
            jsonStr = arg1;
            e = arg2;
        }
        const msg = e && e.message ? e.message : String(e ?? '');
        let lineNum = null;
        let colNum = null;
        let problemLine = null;
        let cleanMsg = msg;

        try {
            const lineColMatch = msg.match(/line\s+(\d+)\s+column\s+(\d+)/i);
            const posMatch = msg.match(/position\s+(\d+)/i);
            if ((lineColMatch || posMatch) && typeof jsonStr === 'string' && jsonStr.length > 0) {
                let l = 1;
                let c = 1;

                if (lineColMatch) {
                    l = parseInt(lineColMatch[1], 10);
                    c = parseInt(lineColMatch[2], 10);
                } else if (posMatch) {
                    const pos = parseInt(posMatch[1], 10);
                    const upToPos = jsonStr.substring(0, pos);
                    const upToLines = upToPos.split(/\r?\n/);
                    l = upToLines.length;
                    c = upToLines[upToLines.length - 1].length + 1;
                }

                const lines = jsonStr.split(/\r?\n/);
                if (l > 0 && l <= lines.length) {
                    lineNum = l;
                    colNum = c;
                    problemLine = lines[l - 1];
                    cleanMsg = msg
                        .replace(/\s+in\s+JSON\s+at\s+position\s+\d+.*$/i, '')
                        .replace(/\s+at\s+position\s+\d+.*$/i, '')
                        .replace(/\s*\(line\s+\d+\s+column\s+\d+\).*$/i, '')
                        .replace(/\s+at\s+line\s+\d+\s+column\s+\d+.*$/i, '')
                        .trim();
                }
            }
        } catch (err) {}

        const hintInfo = detectJsonErrorHint(e, jsonStr);
        return {
            message: msg,
            cleanMessage: cleanMsg,
            line: lineNum,
            column: colNum,
            problemLine,
            hintCode: hintInfo ? hintInfo.hintCode : undefined,
            hint: hintInfo ? hintInfo.hint : undefined,
            hintExample: hintInfo ? hintInfo.hintExample : undefined
        };
    }

    return {
        JSON_HINT_CODES,
        detectJsonErrorHint,
        extractJsonErrorLocation
    };
});
