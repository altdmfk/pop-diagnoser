(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    const _atob = typeof atob !== 'undefined' ? atob : (str) => Buffer.from(str, 'base64').toString('binary');
    const _btoa = typeof btoa !== 'undefined' ? btoa : (str) => Buffer.from(str, 'binary').toString('base64');
    const _crypto = typeof crypto !== 'undefined' ? crypto : require('crypto').webcrypto;

    function base64UrlDecode(base64url) {
        if (typeof base64url !== 'string' || !/^[A-Za-z0-9\-_]+={0,2}$/.test(base64url)) {
            throw new Error("Invalid base64url format");
        }
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
        if (base64.length % 4 === 1) {
            throw new Error("Invalid base64url length");
        }
        while (base64.length % 4) base64 += '=';
        const rawData = _atob(base64);
        const output = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; i++) {
            output[i] = rawData.charCodeAt(i);
        }
        return output.buffer;
    }

    function base64StandardDecode(b64Str) {
        if (typeof b64Str !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64Str)) {
            throw new Error("Invalid standard base64 format");
        }
        let clean = b64Str.replace(/=+$/, '');
        if (clean.length === 0 || clean.length % 4 === 1) {
            throw new Error("Invalid base64 length");
        }
        while (clean.length % 4) clean += '=';
        const rawData = _atob(clean);
        const output = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; i++) {
            output[i] = rawData.charCodeAt(i);
        }
        return output.buffer;
    }

    function base64UrlEncodeBytes(buffer) {
        return _btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    async function hashString(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await _crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function hashStringToBase64Url(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await _crypto.subtle.digest('SHA-256', data);
        return base64UrlEncodeBytes(hashBuffer);
    }

    function bytesToHex(buffer) {
        return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    return {
        _atob,
        _btoa,
        _crypto,
        base64UrlDecode,
        base64StandardDecode,
        base64UrlEncodeBytes,
        hashString,
        hashStringToBase64Url,
        bytesToHex
    };
});
