from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import sys
sys.path.append('../fido2-pop-gateway-main')
from client_simulator.fido2_signer import FIDO2ClientSimulator
import hashlib
import json
import base64
import time

sim = FIDO2ClientSimulator()

def make_fixture(name, method, host, path, query, body, nonce, timestamp, sign_method=None, sign_host=None, sign_path=None, sign_query=None, sign_body_hash=None, delimiter='\n', expected=None, eval_time=None):
    if sign_method is None: sign_method = method
    if sign_host is None: sign_host = host
    if sign_path is None: sign_path = path
    if sign_query is None: sign_query = query
    
    if sign_body_hash is None:
        sign_body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()
    
    components = [sign_method, sign_host, sign_path, sign_query, sign_body_hash, nonce, str(timestamp)]
    canonical_payload = delimiter.join(components)
    
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    
    signature = sim.private_key.sign(canonical_payload.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
    
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(signature)
    raw_sig = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
    signature_b64 = base64.urlsafe_b64encode(raw_sig).decode('utf-8').rstrip("=")
    
    return {
        "name": name,
        "method": method,
        "host": host,
        "path": path,
        "query": query,
        "body": body,
        "nonce": nonce,
        "timestamp": timestamp,
        "digest": f"sha256={hashlib.sha256(body.encode('utf-8')).hexdigest()}",
        "signature": signature_b64,
        "expected": expected or {},
        "evalTime": eval_time if eval_time is not None else timestamp,
        "credentialId": "test-user-credential-id"
    }

cases = []
host = "api.example.com"
body = '{\n  "amount": 1000,\n  "to": "alice"\n}'
nonce = "n-123456789"
timestamp = int(time.time())

# 1. valid
cases.append(make_fixture("valid", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, expected={"firstFailedStage": None, "type": "skipped"}))

# 2. query-sorted
cases.append(make_fixture("query-sorted", "POST", host, "/v1/tx", "c=3&a=1&b=2", body, nonce, timestamp, sign_query="a=1&b=2&c=3", expected={"firstFailedStage": 4, "type": "match", "idStr": "query-sorted"}))

# 3. method-lowercase
cases.append(make_fixture("method-lowercase", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, sign_method="post", expected={"firstFailedStage": 4, "type": "match", "idStr": "method-lowercase"}))

# 4. path-trailing-slash-add
cases.append(make_fixture("path-trailing-slash-add", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, sign_path="/v1/tx/", expected={"firstFailedStage": 4, "type": "match", "idStr": "path-trailing-slash-add"}))

# 5. digest-base64url
bh_b64 = base64.urlsafe_b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode('utf-8').rstrip("=")
cases.append(make_fixture("digest-base64url", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, sign_body_hash=bh_b64, expected={"firstFailedStage": 5, "type": "match", "idStr": "digest-base64url"}))
cases[-1]["digest"] = f"sha256={bh_b64}"

# 6. newline-crlf
bh_crlf = hashlib.sha256(body.replace("\n", "\r\n").encode('utf-8')).hexdigest()
cases.append(make_fixture("newline-crlf", "POST", host, "/v1/tx", "a=1", body.replace("\n", "\r\n"), nonce, timestamp, sign_body_hash=bh_crlf, expected={"firstFailedStage": 5, "type": "match", "idStr": "newline-crlf"}))
cases[-1]["body"] = body # Send original body, but signed CRLF body
cases[-1]["digest"] = f"sha256={bh_crlf}" # Header contains CRLF hash!

# 7. sig-der
cases.append(make_fixture("sig-der", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, expected={"firstFailedStage": 4, "type": "match", "idStr": "sig-der"}))
der_sig = sim.private_key.sign('\n'.join(["POST", host, "/v1/tx", "a=1", hashlib.sha256(body.encode('utf-8')).hexdigest(), nonce, str(timestamp)]).encode('utf-8'), ec.ECDSA(hashes.SHA256()))
cases[-1]["signature"] = base64.urlsafe_b64encode(der_sig).decode('utf-8').rstrip("=")

# 8. combo-2 (query-sorted + method-lowercase)
cases.append(make_fixture("combo-2", "POST", host, "/v1/tx", "c=3&a=1&b=2", body, nonce, timestamp, sign_method="post", sign_query="a=1&b=2&c=3", expected={"firstFailedStage": 4, "type": "match", "idStr": "method-lowercase,query-sorted"}))

# 9. combo-2-2 (query-sorted + newline-crlf)
cases.append(make_fixture("combo-2-2", "POST", host, "/v1/tx", "c=3&a=1&b=2", body.replace("\n", "\r\n"), nonce, timestamp, sign_query="a=1&b=2&c=3", sign_body_hash=bh_crlf, expected={"firstFailedStage": 4, "type": "match", "idStr": "query-sorted"}))
cases[-1]["body"] = body
cases[-1]["digest"] = f"sha256={bh_crlf}"

# 10. outside-catalog
cases.append(make_fixture("outside-catalog", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, sign_path="/api/v1/tx", expected={"firstFailedStage": 4, "type": "no-match"}))

# 11. wrong-key
sim2 = FIDO2ClientSimulator()
cases.append(make_fixture("wrong-key", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, expected={"firstFailedStage": 4, "type": "no-match"}))
cases[-1]["signature"] = base64.urlsafe_b64encode(sim2.private_key.sign(
    '\\n'.join(["POST", host, "/v1/tx", "a=1", hashlib.sha256(body.encode('utf-8')).hexdigest(), nonce, str(timestamp)]).encode('utf-8'),
    ec.ECDSA(hashes.SHA256())
)).decode().rstrip("=")

# 12. indistinguishable
cases.append(make_fixture("indistinguishable", "POST", host, "/v1/tx", "b=2&a=1", body, nonce, timestamp, sign_query="a=1&b=2", expected={"firstFailedStage": 4, "type": "indistinguishable"}))

# 13. timestamp-fail
cases.append(make_fixture("timestamp-fail", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp-100, expected={"firstFailedStage": 2, "type": "skipped"}, eval_time=timestamp))

# 14. digest-fail
bh_wrong = hashlib.sha256(b"wrong").hexdigest()
cases.append(make_fixture("digest-fail", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, sign_body_hash=bh_wrong, expected={"firstFailedStage": 5, "type": "no-match"}))
cases[-1]["digest"] = f"sha256={bh_wrong}"

# 15. host-rewritten
cases.append(make_fixture("host-rewritten", "POST", "api.example.com", "/v1/tx", "a=1", body, nonce, timestamp, sign_host="api.example.com:443", expected={"firstFailedStage": 4, "type": "match", "idStr": "host-rewritten"}))

# 16. both-fail
cases.append(make_fixture("both-fail", "POST", host, "/v1/tx", "a=1", body, nonce, timestamp, sign_host="api.example.com:443", sign_body_hash=bh_wrong, expected={"firstFailedStage": 4, "type": "match", "idStr": "host-rewritten"}))
cases[-1]["digest"] = f"sha256={bh_wrong}"

out = f"const FIXTURES = {{ 'eval_time': {timestamp}, 'public_key': {json.dumps(sim.get_public_key_pem())}, 'cases': {json.dumps(cases, indent=2)} }};\nif (typeof window !== 'undefined') window.FIXTURES = FIXTURES;\nif (typeof module !== 'undefined') module.exports = FIXTURES;"

with open('fixtures.js', 'w', encoding='utf-8') as f:
    f.write(out)
