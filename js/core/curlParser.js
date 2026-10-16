(function (root, factory) {
    const profileMod = (typeof module !== 'undefined' && module.exports)
        ? require('./profiles/paper.js')
        : root.PopCore;
    const mod = factory(profileMod);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (profileMod) {
    const defaultProfile = (profileMod && profileMod.PaperProfile) ? profileMod.PaperProfile : {
        headers: {
            nonce: 'X-FIDO2-Nonce',
            timestamp: 'X-FIDO2-Timestamp',
            signature: 'X-FIDO2-Signature',
            digest: 'X-Body-Digest'
        }
    };

    const MAX_INPUT_LENGTH = 512 * 1024; // 512 KB safety limit
    const ALL_INPUT_KEYS = ['method', 'urlStr', 'bodyStr', 'nonce', 'timestampStr', 'signature', 'reqDigest'];
    const REQUIRED_POP_FIELDS = ['urlStr', 'nonce', 'timestampStr', 'signature', 'reqDigest'];

    function createEmptyInputs() {
        const inputs = {};
        for (const k of ALL_INPUT_KEYS) {
            inputs[k] = '';
        }
        inputs.contentType = '';
        return inputs;
    }

    function computeFilledAndMissing(inputs) {
        const filled = [];
        for (const k of ALL_INPUT_KEYS) {
            if (typeof inputs[k] === 'string' && inputs[k].length > 0) {
                filled.push(k);
            }
        }
        const missing = [];
        for (const reqKey of REQUIRED_POP_FIELDS) {
            if (!inputs[reqKey] || inputs[reqKey].trim().length === 0) {
                missing.push(reqKey);
            }
        }
        return { filled, missing };
    }

    function getHeaderConfig(profile) {
        const hdrs = (profile && profile.headers) ? profile.headers : defaultProfile.headers;
        return {
            nonce: (hdrs.nonce || defaultProfile.headers.nonce).toLowerCase(),
            timestamp: (hdrs.timestamp || defaultProfile.headers.timestamp).toLowerCase(),
            signature: (hdrs.signature || defaultProfile.headers.signature).toLowerCase(),
            digest: (hdrs.digest || defaultProfile.headers.digest).toLowerCase()
        };
    }

    function recordHeaderEntry(headerStr, seenHeaders, rawHeaders, warnings, invalidMsgPrefix) {
        const colonIdx = headerStr.indexOf(':');
        if (colonIdx <= 0) {
            warnings.push({
                code: 'MALFORMED_HEADER',
                message: `${invalidMsgPrefix}: ${headerStr}`
            });
            return;
        }
        const hName = headerStr.slice(0, colonIdx).trim();
        const hVal = headerStr.slice(colonIdx + 1).trim();
        const hKey = hName.toLowerCase();
        if (seenHeaders[hKey]) {
            warnings.push({
                code: 'DUPLICATE_HEADER',
                message: `중복된 헤더('${hName}')가 감지되어 마지막 값을 사용했습니다.`
            });
        }
        seenHeaders[hKey] = (seenHeaders[hKey] || 0) + 1;
        rawHeaders[hKey] = hVal;
    }

    function assignPopHeadersToInputs(inputs, rawHeaders, profile) {
        const hdrConfig = getHeaderConfig(profile);
        inputs.nonce = rawHeaders[hdrConfig.nonce] || '';
        inputs.timestampStr = rawHeaders[hdrConfig.timestamp] || '';
        inputs.signature = rawHeaders[hdrConfig.signature] || '';
        inputs.reqDigest = rawHeaders[hdrConfig.digest] || '';
        inputs.contentType = rawHeaders['content-type'] || '';
    }

    // Tokenize a bash-style cURL command without ever executing or evaluating shell syntax
    function tokenizeShellCommand(src) {
        const tokens = [];
        const unsupported = [];
        let current = '';
        let hasTokenContent = false;
        let i = 0;
        const len = src.length;

        const pushUniqueUnsupported = (code, message) => {
            if (!unsupported.some(u => u.code === code && u.message === message)) {
                unsupported.push({ code, message });
            }
        };

        while (i < len) {
            const ch = src[i];

            // Unquoted whitespace
            if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
                if (hasTokenContent) {
                    tokens.push(current);
                    current = '';
                    hasTokenContent = false;
                }
                i++;
                continue;
            }

            // Windows cmd.exe caret (^) line continuation check outside quotes
            if (ch === '^' && (src[i + 1] === '\n' || (src[i + 1] === '\r' && src[i + 2] === '\n'))) {
                pushUniqueUnsupported(
                    'CMD_CARET_CONTINUATION',
                    'Windows cmd 형식의 줄 이음(^ + 개행)은 지원하지 않습니다. Bash 형식(Copy as cURL (bash))을 사용해 주세요.'
                );
                i += (src[i + 1] === '\r') ? 3 : 2;
                continue;
            }

            // Unquoted pipe, command separator, backgrounding, or redirection
            if (ch === '|' || ch === ';' || ch === '&' || ch === '>' || ch === '<') {
                pushUniqueUnsupported(
                    'PIPE_OR_REDIRECTION_UNSUPPORTED',
                    `보안상 셸 파이프·다중 명령·리다이렉션 구문('${ch}')은 지원하지 않습니다.`
                );
                i++;
                continue;
            }

            // Unquoted backtick command substitution
            if (ch === '`') {
                pushUniqueUnsupported(
                    'SHELL_EXPANSION_UNSUPPORTED',
                    '보안상 백틱(`...`) 명령어 치환 구문은 실행하거나 지원하지 않습니다.'
                );
                i++;
                while (i < len && src[i] !== '`') i++;
                if (i < len) i++;
                continue;
            }

            // Unquoted $ (check ANSI-C $'...' vs unsupported $VAR / $(...) / ${...})
            if (ch === '$') {
                if (src[i + 1] === "'") {
                    // ANSI-C quoting $'...' used by Chrome/Firefox DevTools Copy as cURL (bash)
                    hasTokenContent = true;
                    i += 2;
                    let closed = false;
                    while (i < len) {
                        const c = src[i];
                        if (c === "'") {
                            closed = true;
                            i++;
                            break;
                        }
                        if (c === '\\' && i + 1 < len) {
                            const next = src[i + 1];
                            if (next === 'n') { current += '\n'; i += 2; }
                            else if (next === 'r') { current += '\r'; i += 2; }
                            else if (next === 't') { current += '\t'; i += 2; }
                            else if (next === '\\') { current += '\\'; i += 2; }
                            else if (next === "'") { current += "'"; i += 2; }
                            else if (next === '"') { current += '"'; i += 2; }
                            else if (next === 'x' && /^[0-9a-fA-F]{2}/.test(src.slice(i + 2, i + 4))) {
                                const byteList = [];

                                while (i + 3 < len && src[i] === '\\' && src[i + 1] === 'x' && /^[0-9a-fA-F]{2}/.test(src.slice(i + 2, i + 4))) {
                                    byteList.push(parseInt(src.slice(i + 2, i + 4), 16));
                                    i += 4;
                                }
                                
                                current += new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(byteList));
                            } else if (next === 'u' && /^[0-9a-fA-F]{4}/.test(src.slice(i + 2, i + 6))) {
                                current += String.fromCharCode(parseInt(src.slice(i + 2, i + 6), 16));
                                i += 6;
                            } else if (next === 'U' && /^[0-9a-fA-F]{1,8}/.test(src.slice(i + 2, i + 10))) {
                                const hexMatch = src.slice(i + 2, i + 10).match(/^[0-9a-fA-F]{1,8}/)[0];
                                const cp = parseInt(hexMatch, 16);
                                current += cp <= 0x10FFFF ? String.fromCodePoint(cp) : '\uFFFD';
                                i += 2 + hexMatch.length;
                            } else {
                                current += next;
                                i += 2;
                            }
                        } else {
                            current += c;
                            i++;
                        }
                    }
                    if (!closed) {
                        pushUniqueUnsupported('UNCLOSED_QUOTE', "닫히지 않은 따옴표($'...')가 있습니다.");
                    }
                    continue;
                } else {
                    pushUniqueUnsupported(
                        'SHELL_EXPANSION_UNSUPPORTED',
                        '보안상 셸 변수 치환($VAR, ${...}) 및 명령어 치환($(...))은 실행하거나 지원하지 않습니다.'
                    );
                    if (src[i + 1] === '(') {
                        let depth = 1;
                        i += 2;
                        while (i < len && depth > 0) {
                            if (src[i] === '\\' && i + 1 < len) {
                                i += 2;
                                continue;
                            }
                            if (src[i] === "'" || src[i] === '"') {
                                const q = src[i++];
                                while (i < len && src[i] !== q) {
                                    if (q === '"' && src[i] === '\\' && i + 1 < len) i += 2;
                                    else i++;
                                }
                                if (i < len) i++;
                                continue;
                            }
                            if (src[i] === '(') depth++;
                            else if (src[i] === ')') depth--;
                            i++;
                        }
                    } else if (src[i + 1] === '{') {
                        i += 2;
                        while (i < len && src[i] !== '}') i++;
                        if (i < len) i++;
                    } else if (i + 1 < len && /[?@$!#*0-9-]/.test(src[i + 1])) {
                        i += 2;
                    } else {
                        i++;
                        while (i < len && /[A-Za-z0-9_]/.test(src[i])) i++;
                    }
                    continue;
                }
            }

            // Unquoted backslash
            if (ch === '\\') {
                if (src[i + 1] === '\n') {
                    i += 2;
                    continue;
                }
                if (src[i + 1] === '\r' && src[i + 2] === '\n') {
                    i += 3;
                    continue;
                }
                hasTokenContent = true;
                if (i + 1 < len) {
                    current += src[i + 1];
                    i += 2;
                } else {
                    current += '\\';
                    i++;
                }
                continue;
            }

            // Single-quoted string '...'
            if (ch === "'") {
                hasTokenContent = true;
                i++;
                let closed = false;
                while (i < len) {
                    if (src[i] === "'") {
                        closed = true;
                        i++;
                        break;
                    }
                    current += src[i];
                    i++;
                }
                if (!closed) {
                    pushUniqueUnsupported('UNCLOSED_QUOTE', "닫히지 않은 작은따옴표(')가 있습니다.");
                }
                continue;
            }

            // Double-quoted string "..."
            if (ch === '"') {
                hasTokenContent = true;
                i++;
                let closed = false;
                while (i < len) {
                    const c = src[i];
                    if (c === '"') {
                        closed = true;
                        i++;
                        break;
                    }
                    if (c === '\\') {
                        if (src[i + 1] === '\n') {
                            i += 2;
                            continue;
                        }
                        if (src[i + 1] === '\r' && src[i + 2] === '\n') {
                            i += 3;
                            continue;
                        }
                        if (i + 1 < len) {
                            const next = src[i + 1];
                            if (next === '"' || next === '\\' || next === '$' || next === '`') {
                                current += next;
                            } else {
                                current += '\\' + next;
                            }
                            i += 2;
                            continue;
                        }
                    }
                    if (c === '`') {
                        pushUniqueUnsupported(
                            'SHELL_EXPANSION_UNSUPPORTED',
                            '보안상 큰따옴표 내부의 백틱(`...`) 명령어 치환은 지원하지 않습니다.'
                        );
                    } else if (c === '$' && i + 1 < len && (src[i + 1] === '(' || src[i + 1] === '{' || /[A-Za-z0-9_?@$!#*-]/.test(src[i + 1]))) {
                        pushUniqueUnsupported(
                            'SHELL_EXPANSION_UNSUPPORTED',
                            '보안상 큰따옴표 내부의 셸 변수/명령어 치환($VAR, $(...))은 지원하지 않습니다.'
                        );
                        if (src[i + 1] === '(') {
                            let depth = 1;
                            current += '$(';
                            i += 2;
                            while (i < len && depth > 0) {
                                if (src[i] === '\\' && i + 1 < len) {
                                    current += src[i] + src[i + 1];
                                    i += 2;
                                    continue;
                                }
                                if (src[i] === "'" || src[i] === '"') {
                                    const q = src[i];
                                    current += q;
                                    i++;
                                    while (i < len && src[i] !== q) {
                                        if (q === '"' && src[i] === '\\' && i + 1 < len) {
                                            current += src[i] + src[i + 1];
                                            i += 2;
                                        } else {
                                            current += src[i];
                                            i++;
                                        }
                                    }
                                    if (i < len) {
                                        current += src[i];
                                        i++;
                                    }
                                    continue;
                                }
                                if (src[i] === '(') depth++;
                                else if (src[i] === ')') depth--;
                                current += src[i];
                                i++;
                            }
                            continue;
                        }
                    }
                    current += c;
                    i++;
                }
                if (!closed) {
                    pushUniqueUnsupported('UNCLOSED_QUOTE', '닫히지 않은 큰따옴표(")가 있습니다.');
                }
                continue;
            }

            // Regular character
            hasTokenContent = true;
            current += ch;
            i++;
        }

        if (hasTokenContent) {
            tokens.push(current);
        }

        return { tokens, unsupported };
    }

    function parseRawHttp(text, profile = defaultProfile) {
        try {
            const inputs = createEmptyInputs();
            const warnings = [];
            const unsupported = [];

            if (typeof text !== 'string') {
                unsupported.push({ code: 'INVALID_INPUT', message: '입력값이 문자열이 아닙니다.' });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'raw-http', inputs, filled, missing, warnings, unsupported };
            }

            if (text.length > MAX_INPUT_LENGTH) {
                unsupported.push({
                    code: 'INPUT_TOO_LARGE',
                    message: `입력 크기(${text.length}자)가 최대 허용 한도(${MAX_INPUT_LENGTH}자)를 초과했습니다.`
                });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'raw-http', inputs, filled, missing, warnings, unsupported };
            }

            const trimmedLeading = text.replace(/^(?:\r?\n)+/, '');
            if (!trimmedLeading.trim()) {
                unsupported.push({ code: 'EMPTY_INPUT', message: '입력값이 비어 있습니다.' });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'raw-http', inputs, filled, missing, warnings, unsupported };
            }

            // Split header block and body on first empty line (\r\n\r\n or \n\n)
            const sepMatch = /\r?\n\r?\n/.exec(trimmedLeading);
            let headPart = trimmedLeading;
            let bodyPart = '';
            if (sepMatch) {
                headPart = trimmedLeading.slice(0, sepMatch.index);
                bodyPart = trimmedLeading.slice(sepMatch.index + sepMatch[0].length);
            }

            const headLines = headPart.split(/\r?\n/);
            const reqLine = headLines[0].trim();
            const reqMatch = /^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/(\d(?:\.\d)?))?\s*$/i.exec(reqLine);
            if (!reqMatch) {
                unsupported.push({
                    code: 'INVALID_HTTP_REQUEST_LINE',
                    message: '유효한 HTTP 요청 시작 줄(예: POST /v1/tx HTTP/1.1)을 찾을 수 없습니다.'
                });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'raw-http', inputs, filled, missing, warnings, unsupported };
            }

            inputs.method = reqMatch[1].toUpperCase();
            const requestTarget = reqMatch[2];
            inputs.bodyStr = bodyPart;

            const seenHeaders = {};
            const rawHeaders = {};
            for (let i = 1; i < headLines.length; i++) {
                const line = headLines[i];
                if (!line.trim()) continue;
                recordHeaderEntry(line, seenHeaders, rawHeaders, warnings, '형식이 올바르지 않은 헤더 줄을 무시했습니다');
            }

            if (/^https?:\/\//i.test(requestTarget)) {
                inputs.urlStr = requestTarget;
            } else if (rawHeaders['host']) {
                const normalizedPath = requestTarget.startsWith('/') ? requestTarget : '/' + requestTarget;
                inputs.urlStr = `https://${rawHeaders['host']}${normalizedPath}`;
                warnings.push({
                    code: 'DEFAULT_HTTPS_SCHEME',
                    message: "Raw HTTP 요청에는 스킴이 명시되지 않아 Host 헤더와 결합해 기본 'https://' URL로 재구성했습니다."
                });
            }

            assignPopHeadersToInputs(inputs, rawHeaders, profile);

            const { filled, missing } = computeFilledAndMissing(inputs);
            return {
                ok: unsupported.length === 0,
                format: 'raw-http',
                inputs,
                filled,
                missing,
                warnings,
                unsupported
            };
        } catch (e) {
            const inputs = createEmptyInputs();
            const { filled, missing } = computeFilledAndMissing(inputs);
            return {
                ok: false,
                format: 'raw-http',
                inputs,
                filled,
                missing,
                warnings: [],
                unsupported: [{ code: 'PARSER_EXCEPTION', message: e && e.message ? e.message : String(e) }]
            };
        }
    }

    function parseCurl(text, profile = defaultProfile) {
        try {
            const inputs = createEmptyInputs();
            const warnings = [];
            const unsupported = [];

            if (typeof text !== 'string') {
                unsupported.push({ code: 'INVALID_INPUT', message: '입력값이 문자열이 아닙니다.' });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'unknown', inputs, filled, missing, warnings, unsupported };
            }

            if (text.length > MAX_INPUT_LENGTH) {
                unsupported.push({
                    code: 'INPUT_TOO_LARGE',
                    message: `입력 크기(${text.length}자)가 최대 허용 한도(${MAX_INPUT_LENGTH}자)를 초과하여 안전하게 중단했습니다.`
                });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'unknown', inputs, filled, missing, warnings, unsupported };
            }

            const trimmed = text.trim();
            if (!trimmed) {
                unsupported.push({ code: 'EMPTY_INPUT', message: '입력값이 비어 있습니다.' });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'unknown', inputs, filled, missing, warnings, unsupported };
            }

            // Auto-detect Raw HTTP format if input starts with an HTTP request line
            const firstLine = trimmed.split(/\r?\n/)[0].trim();
            if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d(?:\.\d)?$/i.test(firstLine)) {
                return parseRawHttp(text, profile);
            }

            const tokenized = tokenizeShellCommand(trimmed);
            for (const u of tokenized.unsupported) {
                unsupported.push(u);
            }

            const tokens = tokenized.tokens;
            if (tokens.length === 0 || !/^curl(?:\.exe)?$/i.test(tokens[0])) {
                unsupported.push({
                    code: 'NOT_CURL_COMMAND',
                    message: "유효한 'curl' 명령어 또는 Raw HTTP 요청 형식이 아닙니다."
                });
                const { filled, missing } = computeFilledAndMissing(inputs);
                return { ok: false, format: 'unknown', inputs, filled, missing, warnings, unsupported };
            }

            let explicitMethod = null;
            let hasDataOption = false;
            const dataParts = [];
            const urlCandidates = [];
            const seenHeaders = {};
            const rawHeaders = {};

            const addHeaderString = (headerStr) => {
                recordHeaderEntry(headerStr, seenHeaders, rawHeaders, warnings, '형식이 올바르지 않은 -H 헤더 인자를 무시했습니다');
            };

            const addDataValue = (optName, val) => {
                if (val.startsWith('@')) {
                    unsupported.push({
                        code: 'FILE_READ_UNSUPPORTED',
                        message: `파일에서 본문을 읽는 옵션(${optName} ${val})은 지원하지 않습니다. 본문 문자열을 직접 포함해 주세요.`
                    });
                    return;
                }
                hasDataOption = true;
                dataParts.push(val);
            };

            let idx = 1;
            while (idx < tokens.length) {
                const tok = tokens[idx];

                // Options taking a method argument: -X, --request
                if (tok === '-X' || tok === '--request') {
                    if (idx + 1 >= tokens.length) {
                        unsupported.push({ code: 'MISSING_OPTION_ARG', message: `${tok} 옵션의 메서드 인자가 누락되었습니다.` });
                        break;
                    }
                    explicitMethod = tokens[idx + 1].trim().toUpperCase();
                    idx += 2;
                    continue;
                }
                if (tok.startsWith('-X') && tok.length > 2) {
                    explicitMethod = tok.slice(2).trim().toUpperCase();
                    idx++;
                    continue;
                }
                if (tok.startsWith('--request=')) {
                    explicitMethod = tok.slice('--request='.length).trim().toUpperCase();
                    idx++;
                    continue;
                }

                // Options taking a header argument: -H, --header
                if (tok === '-H' || tok === '--header') {
                    if (idx + 1 >= tokens.length) {
                        unsupported.push({ code: 'MISSING_OPTION_ARG', message: `${tok} 옵션의 헤더 인자가 누락되었습니다.` });
                        break;
                    }
                    addHeaderString(tokens[idx + 1]);
                    idx += 2;
                    continue;
                }
                if (tok.startsWith('-H') && tok.length > 2) {
                    addHeaderString(tok.slice(2));
                    idx++;
                    continue;
                }
                if (tok.startsWith('--header=')) {
                    addHeaderString(tok.slice('--header='.length));
                    idx++;
                    continue;
                }

                // Options taking a body argument: -d, --data, --data-raw, --data-binary
                if (tok === '-d' || tok === '--data' || tok === '--data-raw' || tok === '--data-binary') {
                    if (idx + 1 >= tokens.length) {
                        unsupported.push({ code: 'MISSING_OPTION_ARG', message: `${tok} 옵션의 본문 인자가 누락되었습니다.` });
                        break;
                    }
                    addDataValue(tok, tokens[idx + 1]);
                    idx += 2;
                    continue;
                }
                if (tok.startsWith('-d') && tok.length > 2) {
                    addDataValue('-d', tok.slice(2));
                    idx++;
                    continue;
                }
                if (tok.startsWith('--data=') || tok.startsWith('--data-raw=') || tok.startsWith('--data-binary=')) {
                    const eqIdx = tok.indexOf('=');
                    addDataValue(tok.slice(0, eqIdx), tok.slice(eqIdx + 1));
                    idx++;
                    continue;
                }

                // --url option
                if (tok === '--url') {
                    if (idx + 1 >= tokens.length) {
                        unsupported.push({ code: 'MISSING_OPTION_ARG', message: '--url 옵션의 URL 인자가 누락되었습니다.' });
                        break;
                    }
                    urlCandidates.push(tokens[idx + 1]);
                    idx += 2;
                    continue;
                }
                if (tok.startsWith('--url=')) {
                    urlCandidates.push(tok.slice('--url='.length));
                    idx++;
                    continue;
                }

                // Harmless DevTools response/transport flags (do not alter signed request payload)
                if (
                    tok === '--compressed' ||
                    tok === '-s' || tok === '--silent' ||
                    tok === '-S' || tok === '--show-error' ||
                    tok === '-v' || tok === '--verbose' ||
                    tok === '-i' || tok === '--include' ||
                    tok === '-k' || tok === '--insecure' ||
                    tok === '-L' || tok === '--location'
                ) {
                    warnings.push({
                        code: 'IGNORED_FLAG',
                        message: `서명 생성에 영향을 주지 않는 부가 옵션('${tok}')은 무시되었습니다.`
                    });
                    idx++;
                    continue;
                }

                // Harmless flags taking a single argument
                if (
                    tok === '-A' || tok === '--user-agent' ||
                    tok === '-b' || tok === '--cookie' ||
                    tok === '-e' || tok === '--referer' ||
                    tok === '-m' || tok === '--max-time' ||
                    tok === '--connect-timeout'
                ) {
                    warnings.push({
                        code: 'IGNORED_FLAG',
                        message: `서명 생성에 영향을 주지 않는 부가 옵션('${tok}')은 무시되었습니다.`
                    });
                    idx += (idx + 1 < tokens.length) ? 2 : 1;
                    continue;
                }

                if (
                    tok.startsWith('--user-agent=') ||
                    tok.startsWith('--cookie=') ||
                    tok.startsWith('--referer=') ||
                    tok.startsWith('--max-time=') ||
                    tok.startsWith('--connect-timeout=') ||
                    (tok.startsWith('-A') && tok.length > 2) ||
                    (tok.startsWith('-b') && tok.length > 2) ||
                    (tok.startsWith('-e') && tok.length > 2) ||
                    (tok.startsWith('-m') && tok.length > 2)
                ) {
                    warnings.push({
                        code: 'IGNORED_FLAG',
                        message: `서명 생성에 영향을 주지 않는 부가 옵션('${tok}')은 무시되었습니다.`
                    });
                    idx++;
                    continue;
                }

                // Explicitly unsupported request-transforming options
                if (tok === '--data-urlencode' || tok.startsWith('--data-urlencode=')) {
                    unsupported.push({
                        code: 'UNSUPPORTED_OPTION',
                        message: "'--data-urlencode' 옵션은 본문을 인코딩 변환하므로 바이트 보존 진단을 위해 지원하지 않습니다."
                    });
                    idx += tok === '--data-urlencode' ? 2 : 1;
                    continue;
                }
                if (tok === '-F' || tok === '--form' || tok.startsWith('--form=')) {
                    unsupported.push({
                        code: 'UNSUPPORTED_OPTION',
                        message: `멀티파트 폼 옵션('${tok}')은 지원하지 않습니다.`
                    });
                    idx += (tok === '-F' || tok === '--form') ? 2 : 1;
                    continue;
                }
                if (tok === '-G' || tok === '--get') {
                    unsupported.push({
                        code: 'UNSUPPORTED_OPTION',
                        message: `본문 데이터를 쿼리 스트링으로 변환하는 옵션('${tok}')은 지원하지 않습니다.`
                    });
                    idx++;
                    continue;
                }
                if (tok === '--json' || tok.startsWith('--json=')) {
                    unsupported.push({
                        code: 'UNSUPPORTED_OPTION',
                        message: "'--json' 단축 옵션은 지원 범위에 포함되지 않습니다. -H와 -d/--data-raw를 사용해 주세요."
                    });
                    idx += tok === '--json' ? 2 : 1;
                    continue;
                }

                // Any other option starting with '-'
                if (tok.startsWith('-')) {
                    unsupported.push({
                        code: 'UNSUPPORTED_OPTION',
                        message: `지원하지 않는 cURL 옵션('${tok}')이 포함되어 있습니다.`
                    });
                    idx++;
                    continue;
                }

                // Positional URL argument
                urlCandidates.push(tok);
                idx++;
            }

            if (urlCandidates.length > 0) {
                const httpCandidates = urlCandidates.filter(c => /^https?:\/\//i.test(c));
                if (httpCandidates.length > 0) {
                    inputs.urlStr = httpCandidates[httpCandidates.length - 1];
                } else {
                    inputs.urlStr = urlCandidates[urlCandidates.length - 1];
                }
            }

            if (dataParts.length === 1) {
                inputs.bodyStr = dataParts[0];
            } else if (dataParts.length > 1) {
                inputs.bodyStr = dataParts.join('&');
                warnings.push({
                    code: 'MULTIPLE_DATA_ARGS',
                    message: `데이터 옵션(-d/--data)이 ${dataParts.length}개 입력되어 curl 동작과 동일하게 '&'로 연결했습니다.`
                });
            }

            if (explicitMethod) {
                inputs.method = explicitMethod;
            } else if (hasDataOption) {
                inputs.method = 'POST';
            } else {
                inputs.method = 'GET';
            }

            assignPopHeadersToInputs(inputs, rawHeaders, profile);

            const { filled, missing } = computeFilledAndMissing(inputs);
            return {
                ok: unsupported.length === 0,
                format: 'curl',
                inputs,
                filled,
                missing,
                warnings,
                unsupported
            };
        } catch (e) {
            const inputs = createEmptyInputs();
            const { filled, missing } = computeFilledAndMissing(inputs);
            return {
                ok: false,
                format: 'unknown',
                inputs,
                filled,
                missing,
                warnings: [],
                unsupported: [{ code: 'PARSER_EXCEPTION', message: e && e.message ? e.message : String(e) }]
            };
        }
    }

    return {
        MAX_INPUT_LENGTH,
        createEmptyInputs,
        parseCurl,
        parseRawHttp
    };
});
