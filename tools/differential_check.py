import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import sys
import os
import json
import time
import subprocess

gw_path = os.environ.get('GATEWAY_PATH', '../fido2-pop-gateway-main')
sys.path.append(gw_path)

from fastapi.testclient import TestClient
from app.main import app
from app.core.credential_store import add_credential
from app.core.security import create_access_token
from app.core.nonce_store import nonce_store
from client_simulator.fido2_signer import FIDO2ClientSimulator

client = TestClient(app)
sim = FIDO2ClientSimulator()
user_id = "test-user"
add_credential(user_id, sim.credential_id, sim.get_public_key_pem())
token = create_access_token(data={"sub": user_id, "cnf": {"kid": sim.credential_id}})

import httpx
class MockResponse:
    status_code = 200
    headers = {}
    async def aiter_raw(self):
        yield b'{"status":"ok"}'
    async def aclose(self):
        pass
async def mock_send(self, *args, **kwargs):
    return MockResponse()
httpx.AsyncClient.send = mock_send

last_nonce = None

def run_test(case_name, desc, method, path, query, body, mod_header=None, mod_body=None, client=None, sign_query=None, reuse_nonce=False):
    global last_nonce
    if reuse_nonce and last_nonce is not None:
        nonce = last_nonce
    else:
        nonce = nonce_store.issue_nonce()
        last_nonce = nonce

    actual_sign_query = sign_query if sign_query is not None else query
    headers, _ = sim.sign_request(method, "testserver", path, query=actual_sign_query, body=body, nonce=nonce)
    headers["Authorization"] = f"Bearer {token}"
    if mod_header:
        for k, v in mod_header.items():
            if v is None:
                if k in headers: del headers[k]
            else:
                headers[k] = v
    
    send_body = mod_body if mod_body is not None else body
    url = f"{path}?{query}" if query else path
    req_kwargs = {"headers": headers}
    if method == "POST":
        req_kwargs["content"] = send_body
        
    res = client.request(method, url, **req_kwargs)
    status = res.status_code
    detail = res.json().get("detail", "")
    
    gw_stage = None
    if status == 200 or status == 502: gw_stage = "Pass"
    elif status == 401:
        if "timestamp" in detail.lower() or "nonce" in detail.lower(): gw_stage = 2 if "timestamp" in detail.lower() else 3
        else: gw_stage = 1
    elif status == 400 and "Body digest mismatch" in detail: gw_stage = 5
    elif status == 403 and "Invalid FIDO2 PoP signature" in detail: gw_stage = 4
    elif status == 400 and "Missing or invalid X-Body-Digest header" in detail: gw_stage = 4
    else: gw_stage = 1 # Default 401/400 errors early
    
    inputs = {
        "method": method,
        "urlStr": f"https://testserver{url}",
        "bodyStr": send_body.decode('utf-8') if send_body else "",
        "nonce": headers.get("X-FIDO2-Nonce", ""),
        "timestampStr": headers.get("X-FIDO2-Timestamp", ""),
        "signature": headers.get("X-FIDO2-Signature", ""),
        "pubkeyPem": sim.get_public_key_pem(),
        "reqDigest": headers.get("X-Body-Digest", ""),
        "credentialId": headers.get("X-FIDO2-Credential-ID", ""),
        "evalTime": int(time.time())
    }
    
    script = f"""
const PopCore = require('./diagnose-core.js');
const inputs = {json.dumps(inputs)};
PopCore.diagnose(inputs).then(r => {{
    if (r.error) console.log("Error: " + r.error.message);
    else console.log(r.firstFailedStage === null ? 'Pass' : r.firstFailedStage);
}});
"""
    with open('temp_run.js', 'w', encoding='utf-8') as f:
        f.write(script)
    app_stage = subprocess.check_output(['node', 'temp_run.js']).decode('utf-8').strip()
    if app_stage == "Pass": app_stage = "Pass"
    else: 
        try: app_stage = int(app_stage)
        except: pass
    
    return {
        "case": case_name,
        "desc": desc,
        "status": status,
        "detail": detail,
        "gw_stage": gw_stage,
        "app_stage": app_stage,
        "inputs": inputs
    }

cases_data = [
    ("정상", "변경 없음", "POST", "/api/v1/resource", "a=1", b"hello", None, None, None, False),
    ("Nonce 재사용", "직전 요청의 Nonce를 다시 사용", "POST", "/api/v1/resource", "a=1", b"hello", None, None, None, True),
    ("쿼리 변조", "요청 시 쿼리를 a=2로 변조 (서명은 a=1)", "POST", "/api/v1/resource", "a=2", b"hello", None, None, "a=1", False),
    ("서명 교체", "다른 서명 문자열로 교체", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Signature": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="}, None, None, False),
    ("본문 변조 (digest 헤더 원본 유지)", "요청 시 본문을 hallo로 변조", "POST", "/api/v1/resource", "a=1", b"hello", None, b"hallo", None, False),
    ("타임스탬프 오프셋", "헤더의 Timestamp를 과거(100)로 변조", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Timestamp": "100"}, None, None, False),
    ("서명 통과+digest 헤더만 틀림", "헤더의 Body-Digest만 변조", "POST", "/api/v1/resource", "a=1", b"hello", {"X-Body-Digest": "sha256=wrong"}, None, None, False),
    ("서명과 digest 둘 다 틀림", "서명과 Body-Digest 모두 변조", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Signature": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==", "X-Body-Digest": "sha256=wrong"}, None, None, False),
    ("digest 헤더 누락", "X-Body-Digest 헤더 삭제", "POST", "/api/v1/resource", "a=1", b"hello", {"X-Body-Digest": None}, None, None, False),
    ("Credential-ID 누락", "X-FIDO2-Credential-ID 헤더 삭제", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Credential-ID": None}, None, None, False),
    ("복합: Timestamp 만료 + Digest 누락", "과거 Timestamp + X-Body-Digest 헤더 삭제", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Timestamp": "100", "X-Body-Digest": None}, None, None, False),
    ("복합: Credential-ID 누락 + 서명 오류", "X-FIDO2-Credential-ID 헤더 삭제 + 서명 변조", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Credential-ID": None, "X-FIDO2-Signature": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="}, None, None, False),
    ("복합: 서명 오류 + 본문 변조", "서명 변조 + 본문 변조", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Signature": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="}, b"hallo", None, False),
    ("복합: 서명 오류 + Digest 누락", "서명 변조 + X-Body-Digest 헤더 삭제", "POST", "/api/v1/resource", "a=1", b"hello", {"X-FIDO2-Signature": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==", "X-Body-Digest": None}, None, None, False)
]

results_list = []
with TestClient(app) as client:
    for data in cases_data:
        res = run_test(data[0], data[1], data[2], data[3], data[4], data[5], mod_header=data[6], mod_body=data[7], client=client, sign_query=data[8], reuse_nonce=data[9])
        results_list.append(res)

        
if os.path.exists('temp_run.js'):
    os.remove('temp_run.js')

print("Case | Input Change | GW HTTP + Msg | GW Stage | App Stage | Match")
print("---|---|---|---|---|---")
for r in results_list:
    match = "O" if str(r['gw_stage']) == str(r['app_stage']) else "X"
    if r['case'] == "Nonce 재사용":
        r['app_stage'] = "판단 불가"
        match = "N/A(서버 상태 필요)"
    print(f"{r['case']} | {r['desc']} | {r['status']} {r['detail']} | {r['gw_stage']} | {r['app_stage']} | {match}")

with open('tools/differential_fixtures.json', 'w', encoding='utf-8') as f:
    json.dump({"public_key": sim.get_public_key_pem(), "cases": results_list}, f, ensure_ascii=False, indent=2)
