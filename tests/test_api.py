"""Smoke tests for the detection API. All values are synthetic test data.

Run against a running API. URL and token come from the environment or the
repo's .env and secrets/ (see tests/_config.py):
    python tests/test_api.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _config import API_TOKEN as TOKEN, API_URL as API  # noqa: E402

# Verhoeff tables, used only to generate a checksum-valid synthetic Aadhaar number.
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def synthetic_aadhaar(base11: str = "23456789012") -> str:
    c = 0
    for i, d in enumerate(reversed(base11)):
        c = _D[c][_P[(i + 1) % 8][int(d)]]
    full = base11 + str(_INV[c])
    return f"{full[:4]} {full[4:8]} {full[8:]}"


def post(path: str, body: dict) -> dict:
    req = urllib.request.Request(
        API + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-Gov-Token": TOKEN},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


AADHAAR = synthetic_aadhaar()

CASES = [
    # (name, endpoint, body, expected decision, entity that must be found or None)
    ("clean prompt", "/v1/scan", {"text": "Refactor the loan EMI calculator to use Decimal.", "channel": "prompt"}, "allow", None),
    ("aadhaar blocks", "/v1/scan", {"text": f"Customer Aadhaar number is {AADHAAR}, verify KYC.", "channel": "prompt"}, "block", "IN_AADHAAR"),
    ("card blocks", "/v1/scan", {"text": "Test charge on card 4111 1111 1111 1111 failed.", "channel": "prompt"}, "block", "CREDIT_CARD"),
    ("aws key blocks", "/v1/scan", {"text": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "channel": "prompt"}, "block", "SECRET"),
    ("db uri blocks", "/v1/scan", {"text": "DATABASE_URL=postgresql://loan_app:S3cretPass@db.internal:5432/loans", "channel": "prompt"}, "block", "CONNECTION_STRING"),
    ("private key blocks", "/v1/scan", {"text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...", "channel": "prompt"}, "block", "PRIVATE_KEY"),
    ("pan pseudonymized", "/v1/scan", {"text": "Borrower PAN ABCPE1234F needs re-check.", "channel": "prompt"}, "pseudonymize", "IN_PAN"),
    ("ifsc masked", "/v1/scan", {"text": "Send NEFT to IFSC HDFC0001234 today.", "channel": "prompt"}, "mask", "IN_IFSC"),
    ("upi masked", "/v1/scan", {"text": "Collect EMI via UPI ID rahul.sharma@okhdfcbank", "channel": "prompt"}, "mask", "IN_UPI_ID"),
    ("mobile masked", "/v1/scan", {"text": "Borrower mobile: +91 98765 43210", "channel": "prompt"}, "mask", "IN_MOBILE"),
    ("bank account masked", "/v1/scan", {"text": "Disburse to savings account number 50100123456788", "channel": "prompt"}, "mask", "IN_BANK_ACCOUNT"),
    # A Luhn-valid account number is indistinguishable from a card number, so it is
    # classified as CREDIT_CARD and blocked. This is the intended (safe) direction.
    ("luhn-valid account blocks", "/v1/scan", {"text": "Disburse to savings account number 50100123456789", "channel": "prompt"}, "block", "CREDIT_CARD"),
    ("email needs justification", "/v1/scan", {"text": "Email the statement to priya.k@example.com", "channel": "prompt"}, "warn", "EMAIL_ADDRESS"),
    ("justified email allowed", "/v1/scan", {"text": "Email the statement to priya.k@example.com", "channel": "prompt", "justification": "test fixture address"}, "warn_allow", "EMAIL_ADDRESS"),
    ("email in tool output logged", "/v1/scan", {"text": "owner: priya.k@example.com", "channel": "tool_output"}, "warn_allow", "EMAIL_ADDRESS"),
    ("env path blocked", "/v1/scan-file", {"file_path": "/repo/.env", "content_b64": base64.b64encode(b"X=1").decode()}, "block", None),
    ("env example allowed", "/v1/scan-file", {"file_path": "/repo/.env.example", "content_b64": base64.b64encode(b"DB_HOST=localhost").decode()}, "allow", None),
    ("csv with mobiles masked", "/v1/scan-file", {"file_path": "/repo/data/sample.csv", "content_b64": base64.b64encode(
        b"name,mobile,city\nA,+91 98765 43210,Pune\nB,+91 91234 56789,Mumbai\n").decode()}, "mask", "IN_MOBILE"),
    ("marker blocks", "/v1/scan-file", {"file_path": "/repo/docs/plan.md", "content_b64": base64.b64encode(
        b"# Pricing strategy\nSTRICTLY CONFIDENTIAL - do not distribute").decode()}, "block", "CLASSIFICATION_MARKER"),
]


def main() -> int:
    failures = 0
    for name, path, body, expected, entity in CASES:
        res = post(path, {"user": "test.user@example.com", "agent": "test", **body})
        entities = {f["entity"] for f in res["findings"]}
        ok = res["decision"] == expected and (entity is None or entity in entities)
        failures += not ok
        flag = "PASS" if ok else "FAIL"
        print(f"{flag}  {name:28s} decision={res['decision']:12s} entities={sorted(entities)} {res['latency_ms']}ms")
        if not ok:
            print("      reason:", res["reason"], "| redacted:", (res.get("redacted_text") or "")[:120])
    pan = post("/v1/scan", {"text": "PAN ABCPE1234F", "channel": "prompt"})
    print("      sample redaction:", pan["redacted_text"])
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
