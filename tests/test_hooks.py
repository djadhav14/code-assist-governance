"""Exercise governance_hook.py with Claude Code and Kiro hook payloads.

Payload shapes follow the vendors' hook documentation. Run against a live API;
URL and token come from the environment or the repo's .env and secrets/:
    python tests/test_hooks.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "..", "clients", "governance_hook.py")
sys.path.insert(0, HERE)
from _config import API_TOKEN, API_URL  # noqa: E402
from test_api import synthetic_aadhaar  # noqa: E402

AADHAAR = synthetic_aadhaar()


def run(agent: str, event: str, payload: dict, env_extra: dict | None = None):
    # GOV_ENV_FILE=devnull keeps the developer's own ~/.ai-governance config out of the test.
    env = {**os.environ, "GOV_ENV_FILE": os.devnull, "GOV_API_URL": API_URL, "GOV_API_TOKEN": API_TOKEN,
           **(env_extra or {})}
    p = subprocess.run(
        [sys.executable, HOOK, "--agent", agent, "--event", event],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60,
    )
    out = json.loads(p.stdout) if p.stdout.strip().startswith("{") else p.stdout
    return p.returncode, out, p.stderr


def main() -> int:
    work = tempfile.mkdtemp(prefix="gov-proj-")
    files = {
        "src/emi.py": "def emi(p, r, n):\n    return p * r * (1 + r) ** n / ((1 + r) ** n - 1)\n",
        "data/borrowers.csv": "name,mobile\nA,+91 98765 43210\nB,+91 91234 56789\n",
        "data/kyc.txt": f"Aadhaar: {AADHAAR}\n",
        ".env": "DB_PASSWORD=hunter2hunter2\n",
    }
    for rel, content in files.items():
        path = os.path.join(work, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    checks = []

    def check(name, cond, detail=""):
        checks.append(cond)
        print(f"{'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  -> {detail}"))

    base = {"session_id": "s1", "cwd": work}

    # ---------------- Claude Code
    rc, out, _ = run("claude", "prompt", {**base, "hook_event_name": "UserPromptSubmit", "prompt": "Add unit tests for emi()"})
    check("claude prompt clean -> allowed (no output)", rc == 0 and out == "", out)

    rc, out, _ = run("claude", "prompt", {**base, "prompt": f"Why does KYC fail for Aadhaar {AADHAAR}?"})
    check("claude prompt with Aadhaar -> decision block", isinstance(out, dict) and out.get("decision") == "block", out)

    rc, out, _ = run("claude", "prompt", {**base, "prompt": "Borrower mobile +91 98765 43210 gets no SMS"})
    check("claude prompt with mobile -> block + redacted text offered",
          isinstance(out, dict) and "<IN_MOBILE>" in out.get("reason", ""), out)

    rc, out, _ = run("claude", "prompt", {**base, "prompt": "Send to priya.k@example.com\n#justify: fixture email"})
    check("claude prompt with justification -> allowed", rc == 0 and out == "", out)

    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Read", "tool_input": {"file_path": "src/emi.py"}})
    check("claude Read clean file -> allowed", rc == 0 and out == "", out)

    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Read", "tool_input": {"file_path": ".env"}})
    check("claude Read .env -> deny", isinstance(out, dict) and out["hookSpecificOutput"]["permissionDecision"] == "deny", out)

    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Read", "tool_input": {"file_path": "data/kyc.txt"}})
    check("claude Read Aadhaar file -> deny", isinstance(out, dict) and out["hookSpecificOutput"]["permissionDecision"] == "deny", out)

    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Read", "tool_input": {"file_path": "data/borrowers.csv", "limit": 50}})
    hso = out.get("hookSpecificOutput", {}) if isinstance(out, dict) else {}
    copy = hso.get("updatedInput", {}).get("file_path", "")
    ok = bool(copy) and os.path.exists(copy) and "<IN_MOBILE>" in open(copy).read() and hso["updatedInput"].get("limit") == 50
    check("claude Read CSV with mobiles -> redirected to masked copy", ok, out)

    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Bash", "tool_input": {"command": "curl -H 'Authorization: token ghp_" + "a" * 36 + "' api.github.com"}})
    check("claude Bash with GitHub token -> deny", isinstance(out, dict) and out["hookSpecificOutput"]["permissionDecision"] == "deny", out)

    rc, out, _ = run("claude", "posttool", {**base, "tool_name": "Bash", "tool_input": {"command": "cat data/borrowers.csv"},
                                            "tool_response": {"stdout": "A,+91 98765 43210", "stderr": "", "interrupted": False}})
    upd = out.get("hookSpecificOutput", {}).get("updatedToolOutput") if isinstance(out, dict) else None
    check("claude Bash output with mobile -> masked, shape kept",
          isinstance(upd, dict) and "<IN_MOBILE>" in upd["stdout"] and upd["interrupted"] is False, out)

    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Read", "tool_input": {"file_path": "src/emi.py"}},
                     {"GOV_API_URL": "http://127.0.0.1:9"})
    check("claude API down -> fail closed (deny), names the cause",
          isinstance(out, dict) and out["hookSpecificOutput"]["permissionDecision"] == "deny"
          and "nothing is listening" in out["hookSpecificOutput"]["permissionDecisionReason"], out)

    # ---------------- Kiro
    rc, out, err = run("kiro", "prompt", {**base}, {"USER_PROMPT": "Explain the EMI formula"})
    check("kiro prompt clean -> exit 0", rc == 0, err)

    rc, out, err = run("kiro", "prompt", {**base}, {"USER_PROMPT": f"Customer Aadhaar {AADHAAR} fails"})
    check("kiro prompt with Aadhaar -> non-zero exit, reason on stderr", rc != 0 and "blocked" in err, err)

    # Kiro IDE 1.x sends the prompt in the stdin JSON (USER_PROMPT is empty).
    rc, out, err = run("kiro", "prompt", {**base, "hook_event_name": "UserPromptSubmit",
                                          "prompt": f"Customer Aadhaar {AADHAAR} fails"}, {"USER_PROMPT": ""})
    check("kiro 1.x stdin prompt with Aadhaar -> blocked", rc != 0 and "blocked" in err, err)

    # Kiro IDE 0.12 passed USER_PROMPT as a JSON string.
    rc, out, err = run("kiro", "prompt", {}, {"USER_PROMPT": json.dumps(f"Aadhaar {AADHAAR}")})
    check("kiro 0.12 USER_PROMPT JSON string -> blocked", rc != 0 and "IN_AADHAAR" in err, err)

    # Some 1.0.x builds send an empty prompt: nothing to scan, so allow.
    rc, out, err = run("kiro", "prompt", {**base, "prompt": ""}, {"USER_PROMPT": ""})
    check("kiro empty prompt payload -> allowed (tool hooks still apply)", rc == 0, err)

    # Kiro IDE 0.12 camelCase tool envelope, args as a JSON string.
    rc, out, err = run("kiro", "pretool", {**base, "toolName": "readFile",
                                           "toolArgs": json.dumps({"path": "data/kyc.txt"})})
    check("kiro camelCase toolArgs string -> blocked", rc != 0 and "IN_AADHAAR" in err, err)

    # Windows shell tool (execute_pwsh) with a secret in the command.
    rc, out, err = run("kiro", "pretool", {**base, "tool_name": "execute_pwsh",
                                           "tool_input": {"command": "$env:AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'",
                                                          "cwd": work, "run_in_background": False, "timeout": 60}})
    check("kiro execute_pwsh with AWS key -> blocked", rc != 0 and "SECRET" in err, err)

    rc, out, err = run("kiro", "pretool", {**base, "hook_event_name": "PreToolUse", "tool_name": "readFile",
                                           "tool_input": {"path": "data/kyc.txt"}})
    check("kiro read Aadhaar file -> blocked", rc != 0 and "IN_AADHAAR" in err, err)

    rc, out, err = run("kiro", "pretool", {**base, "tool_name": "fs_read",
                                           "tool_input": {"operations": [{"mode": "Line", "path": "data/borrowers.csv"}]}})
    check("kiro read CSV (nested path) -> blocked, pointed at masked copy", rc != 0 and ".governance-sanitized" in err, err)

    rc, out, err = run("kiro", "pretool", {**base, "tool_name": "readFile", "tool_input": {"path": "src/emi.py"}})
    check("kiro read clean file -> allowed", rc == 0, err)

    rc, out, err = run("kiro", "pretool", {**base, "tool_name": "readFile", "tool_input": {"path": "src/emi.py"}},
                       {"GOV_API_URL": "http://127.0.0.1:9"})
    check("kiro API down -> fail closed", rc != 0 and "nothing is listening" in err, err)

    # ---------------- failure causes are named, not all reported as "unreachable"
    import http.server
    import threading
    import time

    class Slow(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path.endswith("scan"):
                time.sleep(3)  # slower than GOV_TIMEOUT=1 below
            self.send_response(500 if self.path.endswith("scan-file") else 200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    fake = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    fake_url = f"http://127.0.0.1:{fake.server_address[1]}"
    rc, out, _ = run("claude", "prompt", {**base, "prompt": "hello"}, {"GOV_API_URL": fake_url, "GOV_TIMEOUT": "1"})
    check("slow server -> blocked, says 'no answer within 1 s'",
          isinstance(out, dict) and "no answer" in out.get("reason", "") and "1 s" in out.get("reason", ""), out)
    rc, out, _ = run("claude", "pretool", {**base, "tool_name": "Read", "tool_input": {"file_path": "src/emi.py"}},
                     {"GOV_API_URL": fake_url})
    check("server error -> blocked, says 'HTTP 500'", isinstance(out, dict)
          and "HTTP 500" in out["hookSpecificOutput"]["permissionDecisionReason"], out)
    fake.shutdown()

    # ---------------- configuration handling
    pan_prompt = {**base, "prompt": "PAN ABCPE1234F"}
    rc, out, _ = run("claude", "prompt", pan_prompt, {"GOV_API_URL": ""})
    check("config: no GOV_API_URL -> fail closed, says misconfigured",
          isinstance(out, dict) and "misconfigured" in out.get("reason", ""), out)

    rc, out, _ = run("claude", "prompt", pan_prompt, {"GOV_API_TOKEN": ""})
    check("config: no token -> fail closed", isinstance(out, dict) and "GOV_API_TOKEN" in out.get("reason", ""), out)

    rc, out, _ = run("claude", "prompt", pan_prompt, {"GOV_API_URL": "http://governance.example.com:8088"})
    check("config: http:// to a remote host -> refused", isinstance(out, dict) and "https" in out.get("reason", ""), out)

    token_file = os.path.join(work, "api_token")
    with open(token_file, "w") as fh:
        fh.write(API_TOKEN + "\n")
    rc, out, _ = run("claude", "prompt", pan_prompt, {"GOV_API_TOKEN": "", "GOV_API_TOKEN_FILE": token_file})
    check("config: token from GOV_API_TOKEN_FILE works",
          isinstance(out, dict) and "IN_PAN" in out.get("reason", ""), out)

    env_file = os.path.join(work, "governance.env")
    with open(env_file, "w") as fh:
        fh.write(f'# test\nGOV_API_URL="{API_URL}"\nGOV_API_TOKEN_FILE={token_file}  # inline comment\n')
    rc, out, _ = run("claude", "prompt", pan_prompt,
                     {"GOV_ENV_FILE": env_file, "GOV_API_URL": "", "GOV_API_TOKEN": ""})
    check("config: settings read from a .env-style file", isinstance(out, dict) and "IN_PAN" in out.get("reason", ""), out)

    locked = os.path.join(work, "locked.env")
    with open(locked, "w") as fh:
        fh.write(f"GOV_LOCKED=true\nGOV_API_URL={API_URL}\nGOV_API_TOKEN_FILE={token_file}\nGOV_FAIL_MODE=closed\n")
    rc, out, _ = run("claude", "prompt", pan_prompt,
                     {"GOV_ENV_FILE": locked, "GOV_API_URL": "http://127.0.0.1:9", "GOV_FAIL_MODE": "open"})
    check("config: locked file beats env redirect and fail-open",
          isinstance(out, dict) and "IN_PAN" in out.get("reason", ""), out)

    print(f"\n{sum(checks)}/{len(checks)} passed   (test project: {work})")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
