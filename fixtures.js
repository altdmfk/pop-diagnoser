const FIXTURES = { 'eval_time': 1791356800, 'public_key': "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgHsBt/wr3i0Y+5QEk7rVWqy/WiAp\n2BE0Fh98ukGLUupf0yKXbYwjrKKNGb+RWKp8kXdEVAYG2ExSBg3TLqgM6g==\n-----END PUBLIC KEY-----\n", 'cases': [
  {
    "name": "valid",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "6fIrakhUx5Sud5XtALkbNpooVDjF_HPSmQV2V6UbGvzhhw9P5PjIF5XAmV7___fSH9-A2R_qfGGF0ZaG5O_xdA",
    "expected": {
      "firstFailedStage": null,
      "type": "skipped"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "query-sorted",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "c=3&a=1&b=2",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "-2M3ebL7X2gWy_XhoePc8igyBlGZDYBbo8hcLztVnhfz-38OER3tW1RrooCSk_ybQ5O-c4DoLeWyaaQjc4Q_Yw",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "query-sorted"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "method-lowercase",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "M63h0JXneqDWqwJ_Xro3D9qx-9QWgWkEpZdQc4d8XTFtZFMCVyl8O7Bx0t9xYe7pH-UBQxIPCn5i58afBU6eIA",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "method-lowercase"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "path-trailing-slash-add",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "K8W3f-CP-tFuiVvLwZO2N3dTp-E0KLOywd4wjUlM6nQqUm18MAGJ3xtRhq9_eZ0nVLwvQW1RBbSYKtt6Vw8iSQ",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "path-trailing-slash-add"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "digest-base64url",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=Eavx6PTwwdBh8FDbYjViUDOitV9IYCfJLIiwJUJAjhg",
    "signature": "-VoB_hy_XBmzRL9W8hyHeBWlYvovYImbhuLRfY9OIkXP513nDzFnThNf5YmqQCl2Vsa3P_EbU0hA25i219-5vw",
    "expected": {
      "firstFailedStage": 5,
      "type": "match",
      "idStr": "digest-base64url"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "newline-crlf",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=6b0421c956fbb12b58aa984ca6338c9f9210ffc0ccde60d5e5cab9117d0a6088",
    "signature": "kammircROaY1XVJ-eJrYjXww2BcHfL2HM2vaYGhfjZSQJcAQLdkbUUG3959510uwVK8eplSjtTl3tCln3JEPBA",
    "expected": {
      "firstFailedStage": 5,
      "type": "match",
      "idStr": "newline-crlf"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "sig-der",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "MEUCIAxMh8WXvFxihHq3g9jgj_T0wF7YXtQNssCufZQRmItDAiEAoySdSo8jRh2RG9L4MKOTPgadNcPBYDNzsEiq5dn5E0E",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "sig-der"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "combo-2",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "c=3&a=1&b=2",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "TGzR9bAje-PlHb7f69Ol_L2MZk-5ykUia182BVxroDTuqnlmxk1Yzib9wTR2WpGJ1UnEraDV6t36IVPPZRIgjw",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "method-lowercase,query-sorted"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "combo-2-2",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "c=3&a=1&b=2",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=6b0421c956fbb12b58aa984ca6338c9f9210ffc0ccde60d5e5cab9117d0a6088",
    "signature": "oHjuCM1vLOq956lZQbhsFpTy91j2WWNsl5fWl4seuYKxaODV_n2PH4LBWYV78Jp22rdreY43LDsOOVMHfBEgYA",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "query-sorted"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "outside-catalog",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "5tzBzqmfW1KWqDIPo4g9V5k1T3YeUZ7NqMYvB0aESM6-kjah4mmKZhHwj9Q_9r4og6JDym8xGfB2QFUEJgc6LQ",
    "expected": {
      "firstFailedStage": 4,
      "type": "no-match"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "wrong-key",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "MEUCIH5p6kp1c4T78MCTtcJWkA883nptQLZ4f3UM6_ulTjw7AiEA1GNQr6w9stwTD9o4a0XfHi4p1hSQj-WoHZptiK5P4Dc",
    "expected": {
      "firstFailedStage": 4,
      "type": "no-match"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "indistinguishable",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "b=2&a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "7IOotQERpIx8wh7cmFc08jx-ro4Ygb9wKVPs_TmSmztvjwAWlZgnD6ubNtV_CS6tupYe1tofsZhKOjFczwDbAQ",
    "expected": {
      "firstFailedStage": 4,
      "type": "indistinguishable"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "timestamp-fail",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356700,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "Y7RczdFGNg8V7xkMTfYJYFhRSHesn6-f2jZYCqEBtOQLAd-tks1p6kR8j-gfkg4ACd-bMsm0eESP4P0tGPEAiA",
    "expected": {
      "firstFailedStage": 2,
      "type": "skipped"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "digest-fail",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=8810ad581e59f2bc3928b261707a71308f7e139eb04820366dc4d5c18d980225",
    "signature": "qCh2FRan8Z_A7Thvqum4hDEpHSmy3Gd0pz4GRKboMQCylfvkJe2R8leausnA97BspqbstZfAELxHDHe789I83w",
    "expected": {
      "firstFailedStage": 5,
      "type": "no-match"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "host-rewritten",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "TL9fek_lczAJj1Y2CjsFmirROidqjsvoSLmY2hGMSGguRVAY7iVAqk5VRuP7Yr9cr-lU7fkQUMx3EC5g-Kw2fA",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "host-rewritten"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  },
  {
    "name": "both-fail",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791356800,
    "digest": "sha256=8810ad581e59f2bc3928b261707a71308f7e139eb04820366dc4d5c18d980225",
    "signature": "UW6c_Xq1Rw8Ng8j58PJmVMaDOlyfiN6vvjYNYy3xav0-970PTolgPXEuaXbdk8FQi7wwP2tihSWcD_bkWxHQnQ",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "host-rewritten"
    },
    "evalTime": 1791356800,
    "credentialId": "test-user-credential-id"
  }
] };
if (typeof window !== 'undefined') window.FIXTURES = FIXTURES;
if (typeof module !== 'undefined') module.exports = FIXTURES;