(function (root, factory) {
    const mod = factory();
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = mod;
    } else {
        root.PopTestFixtures = mod;
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
    return { 'eval_time': 1791789617, 'public_key': "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESoiANNXLhReCXxipEkpkf6tQJadb\n13oK0EVVFRIcgLghW8Kg/vKh/uAoLhpKjUJAgpm5cS89N8lX51584PoqtQ==\n-----END PUBLIC KEY-----\n", 'cases': [
  {
    "name": "valid",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "Osut4tSP29t9Jg5fcsLUHVuywnByv14u4x5B-ORMp1ZAoroaYmNQaTBJwzv_9N33XCzwCpR8cPdC4-gPbLOQAw",
    "expected": {
      "firstFailedStage": null,
      "type": "skipped"
    },
    "evalTime": 1791789617
  },
  {
    "name": "query-sorted",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "c=3&a=1&b=2",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "VahT4k9om7pPXSqPWAR2cFcHkbi4FIq2d82PUvW3NHuTHHq7n5WI7Ch-ZvHLlVj8zNdCPIYH9oiW-vB6wAPfLw",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "query-sorted"
    },
    "evalTime": 1791789617
  },
  {
    "name": "method-lowercase",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "NYFTWJF-mFakILAnSzj5RCskURG5cLVRxEtgpbmGDJH4JG0oXv6-05X7VTCNKSKFs2eeYSCkP2ADGsP0Ohpg1g",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "method-lowercase"
    },
    "evalTime": 1791789617
  },
  {
    "name": "path-trailing-slash-add",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "vt1RYc-43NVFFxAMebdHo7ViyCwFUZN9glZQZR8yt8_hLa-ze1BwTW16G-tuyosHXYVnlruwRegkCgcSj4moGA",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "path-trailing-slash-add"
    },
    "evalTime": 1791789617
  },
  {
    "name": "digest-base64url",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=Eavx6PTwwdBh8FDbYjViUDOitV9IYCfJLIiwJUJAjhg",
    "signature": "D4exR6p07Egq5W1d7B85xTEoiLqThUqgfNmc0r4y7UejRzFK89ILxjLV_CMhnHpUJ3jfH2UNaGcTioRPaYthUg",
    "expected": {
      "firstFailedStage": 5,
      "type": "match",
      "idStr": "digest-base64url"
    },
    "evalTime": 1791789617
  },
  {
    "name": "newline-crlf",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=6b0421c956fbb12b58aa984ca6338c9f9210ffc0ccde60d5e5cab9117d0a6088",
    "signature": "eXswOB2qNadubwDLG1Iv2vT6dh2-Apt7pTenCF60npwLimQl2OcYZ3AJiSDVAjn2l8wwfrSgvN2T2nFiYkLnCA",
    "expected": {
      "firstFailedStage": 5,
      "type": "match",
      "idStr": "newline-crlf"
    },
    "evalTime": 1791789617
  },
  {
    "name": "sig-der",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "MEQCIGHrB2NTGFrrRIrybEcfxOyU2ireXbEI7STKter370yhAiAaMV9dUxWnNi5nfpimOzhZge5vLsz3D_G3bKWpucyOnw",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "sig-der"
    },
    "evalTime": 1791789617
  },
  {
    "name": "combo-2",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "c=3&a=1&b=2",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "0607Pm6ZcPajgk_sSCpBBkB-hNiWTatlWSbNTkxWKancpo3arR78XvItqFpeYzLZTiWKGU6vRbF2KiKdqRj2Qg",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "method-lowercase,query-sorted"
    },
    "evalTime": 1791789617
  },
  {
    "name": "combo-2-2",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "c=3&a=1&b=2",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=6b0421c956fbb12b58aa984ca6338c9f9210ffc0ccde60d5e5cab9117d0a6088",
    "signature": "1n56NnpN61CYXI7LCN4FPpXoEy5SYj87_8kqzsOs5FlZQ0B_vDhPeNa-W52ApsrnR244WpVLBl_1PhVR6GcwHA",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "newline-crlf,query-sorted"
    },
    "evalTime": 1791789617
  },
  {
    "name": "outside-catalog",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "ZrOSrWykecY3utxLr9N89n5n99SBGeYjkerM3vZ7i1HMEfejCPeH7jH-v4Y-8Ph7boddEowPuWXUYh8Zq3S-Bg",
    "expected": {
      "firstFailedStage": 4,
      "type": "no-match"
    },
    "evalTime": 1791789617
  },
  {
    "name": "wrong-key",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "sC32D6TMBGZ4PUxz_kpZa1QtyjiF7dJRA2IUaMLdLhdWlV5XylViPrGBzT3xXzEcGrjoflBg-lwL64XN37NjSw",
    "expected": {
      "firstFailedStage": 4,
      "type": "no-match"
    },
    "evalTime": 1791789617
  },
  {
    "name": "indistinguishable",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "b=2&a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "lDHGodMJXR4nJfq8HJzmByCaqzSfCp3iKr9TIstNQ60wPuln3kytLoyzLNGlBov1xwlnuqgP2oysiBy5RAJReQ",
    "expected": {
      "firstFailedStage": 4,
      "type": "indistinguishable"
    },
    "evalTime": 1791789617
  },
  {
    "name": "timestamp-fail",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789517,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "_WHYQNK-PUBv5LNG_IUI5nqx2s3nrK9uk-lB3LHBmIwxjhOPfTf4F6gCRarPEl3GE__X0SZT5-AHGnrUT1qrvQ",
    "expected": {
      "firstFailedStage": 2,
      "type": "skipped"
    },
    "evalTime": 1791789617
  },
  {
    "name": "digest-fail",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=8810ad581e59f2bc3928b261707a71308f7e139eb04820366dc4d5c18d980225",
    "signature": "8tu-BlYZQ-zE_TIYh9voSeS7BVVKtEVTOWH5VIyp586xgel3HTdCT15HotPBhK9DwNbWy3SxJwvOpcFwbhM-Mw",
    "expected": {
      "firstFailedStage": 5,
      "type": "no-match"
    },
    "evalTime": 1791789617
  },
  {
    "name": "host-rewritten",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=11abf1e8f4f0c1d061f050db6235625033a2b55f486027c92c88b02542408e18",
    "signature": "wsbVy_aHiJ2JB-cMnw6OLRIOSmyNuE_De6o1ScK_h7cQSqi6GqxBCet83UvLDa3JS_8Hf7S4c2S9itAgHMROxA",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "host-rewritten"
    },
    "evalTime": 1791789617
  },
  {
    "name": "both-fail",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/tx",
    "query": "a=1",
    "body": "{\n  \"amount\": 1000,\n  \"to\": \"alice\"\n}",
    "nonce": "n-123456789",
    "timestamp": 1791789617,
    "digest": "sha256=8810ad581e59f2bc3928b261707a71308f7e139eb04820366dc4d5c18d980225",
    "signature": "mO1IrH7d8wb-QNSf5nuDiCDdQUHDgyN-bogKSuFS7vyF4AuWSbCzRqIk3toHayTb6ZLLom-4NMmX3Jhy-syR_g",
    "expected": {
      "firstFailedStage": 4,
      "type": "match",
      "idStr": "host-rewritten"
    },
    "evalTime": 1791789617
  }
] };
});
