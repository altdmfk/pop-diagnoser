(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopCore = Object.assign(root.PopCore || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    const PaperProfile = {
        id: 'fido2-pop-gateway-v1',
        name: 'FIDO2 PoP Gateway (Paper & Reference Implementation)',
        delimiter: '\n',
        trailingNewline: false,
        canonicalFields: ['method', 'host', 'path', 'query', 'bodyHash', 'nonce', 'timestamp'],
        queryOrder: 'raw',
        methodCase: 'UPPER',
        digestPrefix: /^sha256=/i,
        digestFormat: 'hex-lower',
        signatureEncoding: 'base64url',
        signatureFormat: 'raw-p256',
        signatureByteLength: 64,
        timestampToleranceSec: 60,
        maxSearchNodes: 2000,
        maxComboDepth: 3,
        headers: {
            nonce: 'X-FIDO2-Nonce',
            timestamp: 'X-FIDO2-Timestamp',
            signature: 'X-FIDO2-Signature',
            digest: 'X-Body-Digest'
        },
        stages: {
            1: {
                id: 1,
                name: '1단계: 필수 데이터 서식 검사 (Offline)',
                passReason: '서명 검증에 필요한 모든 항목이 입력되었습니다. (주의: 본 도구는 오프라인 환경이므로 실제 URL 접속 여부나 JWT 토큰 유효성 검증은 생략하고 즉시 서명을 검증합니다.)',
                failReason: 'Method, URL, Nonce, Timestamp, 서명 중 누락된 항목이 있습니다.'
            },
            2: {
                id: 2,
                name: '2단계: 타임스탬프 허용 오차(60초) 검증',
                passReason: '기준 시간 허용 오차 이내',
                failReason: (diff) => `기준 시간과 ${diff}초 차이납니다. (만료)`
            },
            3: {
                id: 3,
                name: '3단계: Nonce 검증',
                unknownReason: "Nonce 값이 입력되었습니다. (안내: Nonce는 해킹(재전송 공격)을 막기 위한 1회용 값입니다. 본 진단기는 오프라인 도구이므로 실제 서버의 DB를 조회하여 '이미 사용된 Nonce인지' 판단하는 과정은 생략됩니다.)",
                failReason: 'Nonce 값이 비어 있습니다.'
            },
            4: {
                id: 4,
                name: '4단계: 타원곡선 서명 검증 (ECDSA Math)',
                passReason: 'ECDSA 검증 성공',
                mismatchReason: '서명 검증 실패 (문자열 또는 키 불일치)',
                missingDigestReason: 'X-Body-Digest 헤더 누락 (게이트웨이는 서명 검증 전 400 반환)',
                lengthFailReason: (actualBytes, expectedBytes) =>
                    `형식 불일치 (현재 디코딩된 크기: ${actualBytes}바이트. ECDSA P-256 서명은 r, s 각각 32바이트씩 총 ${expectedBytes}바이트여야 합니다.)`
            },
            5: {
                id: 5,
                name: '5단계: 다이제스트 스트리밍 대조 (상태: 400)',
                passReason: '본문 해시가 헤더와 일치함',
                missingDigestReason: '입력된 X-Body-Digest 헤더가 없습니다.',
                mismatchReason: (expected, actual) => `본문 해시 불일치 (기대: ${expected}, 실제: ${actual})`
            }
        }
    };

    return { PaperProfile };
});
