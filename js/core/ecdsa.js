(function (root, factory) {
    const encoding = (typeof module !== 'undefined' && module.exports)
        ? require('./encoding.js')
        : root.PopCore;
    const mod = factory(encoding);
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function (encoding) {
    const { _atob, _btoa, _crypto, binaryStringToBytes, bytesToBinaryString } = encoding;
    const RAW_SIGNATURE_BYTES = 64;
    const HALF_SIGNATURE_BYTES = 32;
    const MIN_DER_BYTES = 8;
    const PEM_PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    const PEM_PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";

    async function importPublicKey(pem) {
        const hasHeader = pem.includes(PEM_PUBLIC_KEY_HEADER);
        const hasFooter = pem.includes(PEM_PUBLIC_KEY_FOOTER);
        let pemContents = "";

        if (hasHeader && hasFooter) {
            pemContents = pem.substring(pem.indexOf(PEM_PUBLIC_KEY_HEADER) + PEM_PUBLIC_KEY_HEADER.length, pem.indexOf(PEM_PUBLIC_KEY_FOOTER)).replace(/\s/g, '');
        } else if (!hasHeader && !hasFooter) {
            pemContents = pem.replace(/\s/g, '');
        } else {
            const missing = !hasHeader ? `시작 태그(${PEM_PUBLIC_KEY_HEADER})` : `종료 태그(${PEM_PUBLIC_KEY_FOOTER})`;
            throw new Error(`공개키 형식이 올바르지 않습니다. ${missing}가 잘려나갔습니다.\n아예 태그 없이 중간 값(Base64)만 넣으시거나, 양쪽 태그를 모두 포함해 주세요.`);
        }

        if (pemContents.length === 0) {
            throw new Error("공개키 내부에 실제 키 데이터(Base64)가 비어 있습니다.");
        }

        let binaryDer;
        try {
            binaryDer = binaryStringToBytes(_atob(pemContents));
        } catch (e) {
            throw new Error("공개키 내부 데이터(Base64) 디코딩에 실패했습니다.\n공백 외의 잘못된 문자(한글, 특수기호 등)가 섞여 있는지 확인하세요.");
        }

        try {
            return await _crypto.subtle.importKey(
                "spki",
                binaryDer.buffer,
                { name: "ECDSA", namedCurve: "P-256" },
                true,
                ["verify"]
            );
        } catch (e) {
            throw new Error("공개키 데이터 분석(Import)에 실패했습니다. 키가 손상되었거나 유효한 ECDSA P-256 공개키가 아닐 수 있습니다. (상세 에러: " + e.message + ")");
        }
    }

    function derToRaw(derBytes) {
        if (!derBytes) return null;
        const view = new Uint8Array(derBytes);
        if (view.length < MIN_DER_BYTES) return null;
        if (view[0] !== 0x30) return null;

        let offset = 2;
        let seqLen = view[1];
        if (seqLen === 0x80) return null;
        if (seqLen > 0x80) {
            const numLenBytes = seqLen & 0x7f;
            if (numLenBytes === 0 || numLenBytes > 2 || 2 + numLenBytes > view.length) return null;
            seqLen = 0;
            for (let i = 0; i < numLenBytes; i++) {
                seqLen = (seqLen << 8) | view[2 + i];
            }
            offset = 2 + numLenBytes;
        }
        if (offset + seqLen !== view.length) return null;

        if (offset + 2 > view.length || view[offset] !== 0x02) return null;
        let rLen = view[offset + 1];
        let rStart = offset + 2;
        if (rLen === 0 || rStart + rLen > view.length) return null;
        const sOffset = rStart + rLen;
        if (view[rStart] === 0x00 && rLen > 1) {
            rStart++;
            rLen--;
        }
        if (rLen === 0 || rLen > HALF_SIGNATURE_BYTES || view[rStart] === 0x00) return null;
        const r = view.slice(rStart, rStart + rLen);

        offset = sOffset;
        if (offset + 2 > view.length || view[offset] !== 0x02) return null;
        let sLen = view[offset + 1];
        let sStart = offset + 2;
        if (sLen === 0 || sStart + sLen !== view.length) return null;
        if (view[sStart] === 0x00 && sLen > 1) {
            sStart++;
            sLen--;
        }
        if (sLen === 0 || sLen > HALF_SIGNATURE_BYTES || view[sStart] === 0x00) return null;
        const s = view.slice(sStart, sStart + sLen);

        const raw = new Uint8Array(RAW_SIGNATURE_BYTES);
        raw.set(r, HALF_SIGNATURE_BYTES - rLen);
        raw.set(s, HALF_SIGNATURE_BYTES + (HALF_SIGNATURE_BYTES - sLen));
        return raw.buffer;
    }

    async function verifySig(key, sigBytes, canonicalStr) {
        const encoder = new TextEncoder();
        const data = encoder.encode(canonicalStr);
        try {
            return await _crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, key, sigBytes, data);
        } catch (e) {
            return false;
        }
    }

    async function generateKeyPairAndSign(canonicalStr) {
        const keyPair = await _crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
        );
        const spki = await _crypto.subtle.exportKey("spki", keyPair.publicKey);
        const spkiBase64 = _btoa(bytesToBinaryString(spki));
        const pubkeyPem = `${PEM_PUBLIC_KEY_HEADER}\n${spkiBase64.match(/.{1,64}/g).join('\n')}\n${PEM_PUBLIC_KEY_FOOTER}`;

        const data = new TextEncoder().encode(canonicalStr);
        const signatureBytes = await _crypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            keyPair.privateKey,
            data
        );

        return { pubkeyPem, signatureBytes };
    }

    return {
        PEM_PUBLIC_KEY_HEADER,
        PEM_PUBLIC_KEY_FOOTER,
        importPublicKey,
        derToRaw,
        verifySig,
        generateKeyPairAndSign
    };
});
