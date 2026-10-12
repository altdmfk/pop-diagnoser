(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    }
    root.PopUI = Object.assign(root.PopUI || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    const DEMO_SAMPLES = {
        eval_time: 1791356800,
        public_key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgHsBt/wr3i0Y+5QEk7rVWqy/WiAp\n2BE0Fh98ukGLUupf0yKXbYwjrKKNGb+RWKp8kXdEVAYG2ExSBg3TLqgM6g==\n-----END PUBLIC KEY-----\n",
        cases: [
            {
                name: "valid",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "a=1",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356800,
                digest: "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
                signature: "6fIrakhUx5Sud5XtALkbNpooVDjF_HPSmQV2V6UbGvzhhw9P5PjIF5XAmV7___fSH9-A2R_qfGGF0ZaG5O_xdA",
                evalTime: 1791356800
            },
            {
                name: "query-sorted",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "c=3&a=1&b=2",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356800,
                digest: "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
                signature: "-2M3ebL7X2gWy_XhoePc8igyBlGZDYBbo8hcLztVnhfz-38OER3tW1RrooCSk_ybQ5O-c4DoLeWyaaQjc4Q_Yw",
                evalTime: 1791356800
            },
            {
                name: "method-lowercase",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "a=1",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356800,
                digest: "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
                signature: "M63h0JXneqDWqwJ_Xro3D9qx-9QWgWkEpZdQc4d8XTFtZFMCVyl8O7Bx0t9xYe7pH-UBQxIPCn5i58afBU6eIA",
                evalTime: 1791356800
            },
            {
                name: "digest-base64url",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "a=1",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356800,
                digest: "sha256=Eavx6PTwwdBh8FDbYjViUDOitV9IYCfJLIiwJUJAjhg",
                signature: "-VoB_hy_XBmzRL9W8hyHeBWlYvovYImbhuLRfY9OIkXP513nDzFnThNf5YmqQCl2Vsa3P_EbU0hA25i219-5vw",
                evalTime: 1791356800
            },
            {
                name: "sig-der",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "a=1",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356800,
                digest: "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
                signature: "MEUCIAxMh8WXvFxihHq3g9jgj_T0wF7YXtQNssCufZQRmItDAiEAoySdSo8jRh2RG9L4MKOTPgadNcPBYDNzsEiq5dn5E0E",
                evalTime: 1791356800
            },
            {
                name: "combo-2",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "c=3&a=1&b=2",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356800,
                digest: "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
                signature: "TGzR9bAje-PlHb7f69Ol_L2MZk-5ykUia182BVxroDTuqnlmxk1Yzib9wTR2WpGJ1UnEraDV6t36IVPPZRIgjw",
                evalTime: 1791356800
            },
            {
                name: "timestamp-fail",
                method: "POST",
                host: "api.example.com",
                path: "/v1/tx",
                query: "a=1",
                body: "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
                nonce: "n-123456789",
                timestamp: 1791356700,
                digest: "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
                signature: "Y7RczdFGNg8V7xkMTfYJYFhRSHesn6-f2jZYCqEBtOQLAd-tks1p6kR8j-gfkg4ACd-bMsm0eESP4P0tGPEAiA",
                evalTime: 1791356800
            }
        ]
    };

    return { DEMO_SAMPLES };
});
