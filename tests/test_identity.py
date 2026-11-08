"""Verified user identity (GOV_AUTH_MODE=token+oidc), end to end, without a real IdP.

The test plays the identity provider: it creates an RSA signing key, publishes
the public key as a JWKS file, and signs access tokens with it. It then starts
its own server on port 8099 in token+oidc mode and checks:

  * requests without, or with a bad/expired/wrong-audience/foreign-key access
    token are refused (401)
  * a valid token is accepted, and the audit event records the verified user,
    the desktop user as user.claimed, and whether they match
  * GOV_IDENTITY_MISMATCH=block refuses a desktop user that isn't the account
  * the hook fetches the token with GOV_ID_TOKEN_COMMAND and caches it

Needs the server's packages (the no-Docker route). Run from the project root:
    python3 tests/test_identity.py
"""
from __future__ import annotations

import functools
import http.server
import json
import os
import subprocess
import threading
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = 8099
JWKS_PORT = 8098        # the test's stand-in for the identity provider's key endpoint
API = f"http://127.0.0.1:{PORT}"
ISSUER = "https://login.example.test/tenant-0000/v2.0"
AUDIENCE = "api://ai-governance-test"
results: list[bool] = []

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("SKIP  PyJWT[crypto] not installed (pip install 'PyJWT[crypto]')")
    sys.exit(0)


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(("PASS" if ok else "FAIL"), f" {name}" + (f"  -> {detail}" if detail and not ok else ""))


def make_key(kid: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, use="sig", alg="RS256")
    return key, jwk


def sign(key, kid: str, user="deepak@corp.example", aud=AUDIENCE, iss=ISSUER, exp_in=3600) -> str:
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "iat": now, "nbf": now, "exp": now + exp_in,
              "preferred_username": user, "oid": "00000000-1111-2222-3333-444444444444", "ver": "2.0"}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def post(body: dict, token: str | None, gov_token: str) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json", "X-Gov-Token": gov_token}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(API + "/v1/scan", data=json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def start_server(tmp: Path, extra_env: dict) -> subprocess.Popen:
    env = {**os.environ, "GOV_ENV_FILE": "", "GOV_HOST": "127.0.0.1", "GOV_PORT": str(PORT),
           "GOV_WORKERS": "1", "GOV_NLP_MODEL": os.getenv("GOV_NLP_MODEL", "en_core_web_sm"),
           "GOV_API_TOKEN": "identity-test-token-0123456789", "GOV_HASH_KEY": "identity-test-hash-key-0123456789",
           "GOV_AUDIT_FILE": str(tmp / "audit.jsonl"), "GOV_AUTH_MODE": "token+oidc",
           "GOV_OIDC_ISSUER": ISSUER, "GOV_OIDC_AUDIENCE": AUDIENCE,
           "GOV_OIDC_JWKS_URL": f"http://127.0.0.1:{JWKS_PORT}/jwks.json", **extra_env}
    for k in ("GOV_API_TOKEN_FILE", "GOV_HASH_KEY_FILE", "GOV_AWS_SECRET_ID"):
        env.pop(k, None)
    proc = subprocess.Popen([sys.executable, "-m", "app.serve"], cwd=ROOT / "detection_api", env=env,
                            stdout=open(tmp / "server.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            urllib.request.urlopen(API + "/healthz", timeout=2)
            return proc
        except Exception:  # noqa: BLE001
            if proc.poll() is not None:
                print((tmp / "server.log").read_text()[-2000:])
                sys.exit("server failed to start")
            time.sleep(1)
    proc.kill()
    sys.exit("server did not become ready")


def last_event(tmp: Path) -> dict:
    lines = (tmp / "audit.jsonl").read_text().strip().splitlines()
    return json.loads(lines[-1])["governance"]


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gov-identity-"))
    key, jwk = make_key("test-key-1")
    other_key, _ = make_key("test-key-1")          # same kid, different key: a forgery
    (tmp / "jwks.json").write_text(json.dumps({"keys": [jwk]}))
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = functools.partial(Quiet, directory=str(tmp))
    idp = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), handler)
    threading.Thread(target=idp.serve_forever, daemon=True).start()
    gov = "identity-test-token-0123456789"
    body = {"text": "Borrower PAN ABCPE1234F needs re-check", "channel": "prompt", "user": "deepak"}

    proc = start_server(tmp, {})
    try:
        info = json.load(urllib.request.urlopen(API + "/healthz"))
        check("server reports auth mode token+oidc", info.get("auth") == "token+oidc", str(info.get("auth")))
        code, _ = post(body, None, gov)
        check("no access token -> 401", code == 401, str(code))
        code, _ = post(body, sign(key, "test-key-1"), "wrong-shared-token-000000")
        check("valid access token but wrong shared token -> 401", code == 401, str(code))
        code, r = post(body, sign(key, "test-key-1", exp_in=-600), gov)
        check("expired access token -> 401", code == 401 and "expired" in r.get("detail", ""), f"{code} {r}")
        code, r = post(body, sign(key, "test-key-1", aud="api://someone-else"), gov)
        check("wrong audience -> 401", code == 401, f"{code} {r}")
        code, r = post(body, sign(key, "test-key-1", iss="https://evil.example/v2.0"), gov)
        check("wrong issuer -> 401", code == 401, f"{code} {r}")
        code, r = post(body, sign(other_key, "test-key-1"), gov)
        check("token signed with a foreign key -> 401", code == 401, f"{code} {r}")
        unsigned = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 600,
                               "preferred_username": "x@corp.example"}, key="", algorithm="none")
        code, _ = post(body, unsigned, gov)
        check("unsigned token (alg none) -> 401", code == 401, str(code))

        code, r = post(body, sign(key, "test-key-1"), gov)
        check("valid access token -> scanned", code == 200 and r.get("decision") == "pseudonymize", f"{code} {r}")
        ev = last_event(tmp)
        check("audit: user_id is the verified account", ev.get("user_id") == "deepak@corp.example", str(ev))
        check("audit: desktop user kept as user_claimed", ev.get("user_claimed") == "deepak", str(ev))
        check("audit: user_verified true, no mismatch",
              ev.get("user_verified") is True and ev.get("identity_mismatch") is False, str(ev))
        check("audit: immutable subject ID recorded", ev.get("user_subject_id", "").startswith("00000000-"), str(ev))

        code, r = post({**body, "user": "someone.else"}, sign(key, "test-key-1"), gov)
        ev = last_event(tmp)
        check("mismatch logged (log mode) but scan allowed",
              code == 200 and ev.get("identity_mismatch") is True, f"{code} {ev}")

        # The hook: token from GOV_ID_TOKEN_COMMAND, cached per user
        home = tmp / "home"
        home.mkdir()
        tokfile = tmp / "token.txt"
        tokfile.write_text(sign(key, "test-key-1"))
        counter = tmp / "count.txt"
        cmd = f'{sys.executable} -c "import pathlib;p=pathlib.Path(r\'{counter}\');' \
              f'p.write_text(str(int(p.read_text() or 0)+1) if p.exists() else \'1\');' \
              f'print(pathlib.Path(r\'{tokfile}\').read_text())"'
        henv = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "GOV_ENV_FILE": "",
                "GOV_API_URL": API, "GOV_API_TOKEN": gov, "GOV_USER": "deepak", "GOV_ID_TOKEN_COMMAND": cmd,
                "GOV_TIMEOUT": "10"}
        henv.pop("GOV_API_TOKEN_FILE", None)
        payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "Summarise the loan policy",
                              "session_id": "id-test", "cwd": str(tmp)})
        outs = []
        for _ in range(2):
            p = subprocess.run([sys.executable, str(ROOT / "clients" / "governance_hook.py"), "--agent", "claude",
                                "--event", "prompt"], input=payload, capture_output=True, text=True, env=henv,
                               cwd=tmp, timeout=60)
            outs.append(p)
        check("hook: prompt allowed with a fetched access token",
              all(p.returncode == 0 and '"block"' not in p.stdout for p in outs), outs[0].stdout + outs[0].stderr)
        check("hook: token cached (command ran once for two prompts)",
              counter.read_text().strip() == "1", counter.read_text() if counter.exists() else "never ran")
        cache = home / ".ai-governance" / "id_token.cache"
        check("hook: cache file is owner-only", cache.exists() and (os.name == "nt" or (cache.stat().st_mode & 0o077) == 0))
        check("audit: hook call recorded as verified", last_event(tmp).get("user_verified") is True)

        henv["GOV_ID_TOKEN_COMMAND"] = f'{sys.executable} -c "import sys; sys.exit(\'please run az login\')"'
        cache.unlink()
        p = subprocess.run([sys.executable, str(ROOT / "clients" / "governance_hook.py"), "--agent", "claude",
                            "--event", "prompt"], input=payload, capture_output=True, text=True, env=henv,
                           cwd=tmp, timeout=60)
        check("hook: no sign-in -> blocked with a clear reason",
              '"block"' in p.stdout and "sign-in token" in p.stdout, p.stdout + p.stderr)
    finally:
        proc.terminate()
        proc.wait(10)

    proc = start_server(tmp, {"GOV_IDENTITY_MISMATCH": "block"})
    try:
        code, r = post({**body, "user": "someone.else"}, sign(key, "test-key-1"), gov)
        check("GOV_IDENTITY_MISMATCH=block -> 403 for another desktop user", code == 403, f"{code} {r}")
        code, _ = post({**body, "user": "CORP\\deepak"}, sign(key, "test-key-1"), gov)
        check("domain\\user form of the same person accepted", code == 200, str(code))
    finally:
        proc.terminate()
        proc.wait(10)

    idp.shutdown()
    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
