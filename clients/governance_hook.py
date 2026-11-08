#!/usr/bin/env python3
"""Governance hook for Claude Code and Kiro IDE.

Standard library only, so it runs on any developer machine with Python 3.9+
(Ubuntu or Windows) without installing packages.

Usage (wired up by install_hooks.py):
    governance_hook.py --agent claude --event prompt|pretool|posttool
    governance_hook.py --agent kiro   --event prompt|pretool|posttool

Configuration (no built-in API address or token: the hook fails closed until set)
  Read from, highest priority first:
    1. A *locked* file: governance.env next to this script containing GOV_LOCKED=true.
       Machine-wide installs write it into an admin-only folder, and its values
       cannot be overridden by the user's environment variables.
    2. Environment variables.
    3. An env file: GOV_ENV_FILE, else governance.env next to this script,
       else ~/.ai-governance/governance.env  (KEY=VALUE lines, # comments).
    4. Legacy config.json in the same locations (read for backward compatibility).

  Required:
    GOV_API_URL         detection API base URL, e.g. https://governance.internal:8088
    GOV_API_TOKEN       API token, or one of:
      GOV_API_TOKEN_FILE  path to a file holding the token
      GOV_TOKEN_SOURCE=keyring  read it from the OS credential store
                          (Windows Credential Manager, macOS Keychain, Linux Secret
                          Service; needs the optional 'keyring' package)
  Optional:
    GOV_TIMEOUT          seconds per API call            (default 3)
    GOV_FAIL_MODE        closed | open                   (default closed)
    GOV_MAX_FILE_MB      largest file sent for scanning  (default 10)
    GOV_CA_BUNDLE        PEM file with the CA that signed the API's TLS certificate
    GOV_ALLOW_INSECURE_HTTP=true  permit http:// to a non-loopback host (testing only)
    GOV_USER, GOV_DEVICE_ID       identity overrides for the audit log
    GOV_ID_TOKEN_COMMAND command that prints the signed-in user's access token, for
                         servers with GOV_AUTH_MODE=token+oidc or oidc, e.g.
                         az account get-access-token --scope api://<app-id>/.default --query accessToken -o tsv
                         The token is cached per user (~/.ai-governance/id_token.cache,
                         owner-only) until 2 minutes before it expires.
    GOV_ID_TOKEN_TIMEOUT seconds allowed for that command (default 8)
    GOV_SANITIZED_DIR    where redacted copies go        (default <cwd>/.governance-sanitized)
    GOV_HOOK_LOG         local debug log file
    GOV_JUSTIFY_MARKER   prompt marker for justifications (default "#justify:")

Protocol summary
  Claude Code: reads hook JSON on stdin; answers with JSON on stdout
    (decision/permissionDecision/updatedInput/updatedToolOutput) and exit 0.
  Kiro: prompt text arrives in USER_PROMPT (and/or stdin JSON); a non-zero
    exit blocks Prompt Submit and Pre Tool Use, and stderr is shown to the agent.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_HOME_DIR = os.path.join(os.path.expanduser("~"), ".ai-governance")
_TRUE = {"1", "true", "yes", "on"}
KEYRING_SERVICE = "ai-governance"


def parse_env_file(path: str) -> dict:
    """Minimal .env parser: KEY=VALUE, optional 'export ', quotes, # comments."""
    values = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return {k: str(v) for k, v in json.load(fh).items()}
    except (OSError, ValueError, AttributeError):
        return {}


def _load_file_config() -> dict:
    explicit = os.getenv("GOV_ENV_FILE")
    if explicit:
        return parse_env_file(explicit)
    for folder in (_HERE, _HOME_DIR):
        env_path = os.path.join(folder, "governance.env")
        if os.path.exists(env_path):
            return parse_env_file(env_path)
        legacy = _read_json(os.path.join(folder, "config.json"))
        if legacy:
            if legacy.get("locked", "").lower() in _TRUE:
                legacy["GOV_LOCKED"] = "true"
            return legacy
    return {}


_CFG = _load_file_config()
# A machine-wide install writes GOV_LOCKED=true so a user cannot redirect the hook
# (for example to a fake server, or to fail open) with environment variables.
_LOCKED = _CFG.get("GOV_LOCKED", "").lower() in _TRUE


def _setting(name: str, default: str = "") -> str:
    if _LOCKED and _CFG.get(name):
        return _CFG[name]
    return os.getenv(name) or _CFG.get(name) or default


def _token() -> str:
    """API token from the env/file setting, a token file, or the OS credential store."""
    direct = _setting("GOV_API_TOKEN")
    if direct:
        return direct
    path = _setting("GOV_API_TOKEN_FILE")
    if path:
        try:
            with open(os.path.expanduser(path), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""
    if _setting("GOV_TOKEN_SOURCE").lower() == "keyring":
        try:
            import keyring  # optional dependency

            return keyring.get_password(KEYRING_SERVICE, "GOV_API_TOKEN") or ""
        except Exception:  # noqa: BLE001 - missing package or locked store
            return ""
    return ""


def _config_error() -> str:
    """Return a description of what is missing or unsafe, or '' if usable."""
    if not API:
        return "GOV_API_URL is not configured"
    parsed = urllib.parse.urlparse(API)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return f"GOV_API_URL is not a valid http(s) URL: {API!r}"
    loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme == "http" and not loopback and _setting("GOV_ALLOW_INSECURE_HTTP").lower() not in _TRUE:
        return "GOV_API_URL uses http:// to a remote host; use https:// (or GOV_ALLOW_INSECURE_HTTP=true for testing)"
    if not TOKEN:
        return "GOV_API_TOKEN is not configured (set it, GOV_API_TOKEN_FILE, or GOV_TOKEN_SOURCE=keyring)"
    return ""


API = _setting("GOV_API_URL").rstrip("/")
TOKEN = _token()
TIMEOUT = float(_setting("GOV_TIMEOUT", "3"))
FAIL_OPEN = _setting("GOV_FAIL_MODE", "closed").lower() == "open"
MAX_FILE_BYTES = int(float(_setting("GOV_MAX_FILE_MB", "10")) * 1024 * 1024)
JUSTIFY_RE = re.compile(re.escape(_setting("GOV_JUSTIFY_MARKER", "#justify:")) + r"\s*(.+)", re.IGNORECASE)
PATH_KEY_RE = re.compile(r"(?:^|_)(?:path|file|filepath|file_path|filename|target_file)s?$", re.IGNORECASE)
COMMAND_KEYS = ("command", "cmd", "script")
REWRITE_ACTIONS = ("mask", "pseudonymize")


def _ssl_context():
    bundle = _setting("GOV_CA_BUNDLE")
    if not bundle:
        return None  # system trust store
    import ssl

    return ssl.create_default_context(cafile=os.path.expanduser(bundle))


class GovernanceUnavailable(Exception):
    pass


# ---------------------------------------------------------------- utilities
def debug(msg: str) -> None:
    path = _setting("GOV_HOOK_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(msg.rstrip() + "\n")


def identity() -> dict:
    return {
        "user": _setting("GOV_USER") or getpass.getuser(),
        "host": platform.node(),
        "device_id": _setting("GOV_DEVICE_ID"),
    }


ID_TOKEN_COMMAND = _setting("GOV_ID_TOKEN_COMMAND")
ID_TOKEN_TIMEOUT = float(_setting("GOV_ID_TOKEN_TIMEOUT", "8"))
_ID_CACHE = os.path.join(os.path.expanduser("~"), ".ai-governance", "id_token.cache")


def _jwt_expiry(token: str) -> float:
    """exp claim of a JWT, read without verifying (the server verifies). 0 if unreadable."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
    except Exception:  # noqa: BLE001
        return 0.0


def _id_token(refresh: bool = False) -> str:
    """The signed-in user's access token, from the cache or GOV_ID_TOKEN_COMMAND."""
    if not refresh:
        try:
            with open(_ID_CACHE, encoding="utf-8") as fh:
                cached = fh.read().strip()
            if cached and _jwt_expiry(cached) - time.time() > 120:
                return cached
        except OSError:
            pass
    try:
        out = subprocess.run(ID_TOKEN_COMMAND, shell=True, capture_output=True, text=True,
                             timeout=ID_TOKEN_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise GovernanceUnavailable(f"getting your sign-in token took over {ID_TOKEN_TIMEOUT:g} s "
                                    "(GOV_ID_TOKEN_COMMAND)") from exc
    token = (out.stdout or "").strip()
    if token.startswith("{"):           # full JSON output, e.g. az without --query
        try:
            token = json.loads(token).get("accessToken", "")
        except json.JSONDecodeError:
            token = ""
    if out.returncode != 0 or token.count(".") != 2:
        detail = (out.stderr or out.stdout or "").strip().splitlines()[-1:] or ["no token printed"]
        raise GovernanceUnavailable("could not get your sign-in token (sign in again, e.g. 'az login'): "
                                    + detail[0][:200])
    try:
        os.makedirs(os.path.dirname(_ID_CACHE), exist_ok=True)
        fd = os.open(_ID_CACHE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
    except OSError:
        pass                            # caching is an optimisation only
    return token


def call(path: str, body: dict, _retry: bool = True) -> dict:
    problem = _config_error()
    if problem:
        raise GovernanceUnavailable(problem)
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Gov-Token": TOKEN}
    if ID_TOKEN_COMMAND:
        headers["Authorization"] = "Bearer " + _id_token(refresh=not _retry)
    req = urllib.request.Request(API + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl_context()) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:  # the server answered, with an error
        try:
            detail = json.loads(exc.read() or b"{}").get("detail", "")
        except Exception:  # noqa: BLE001
            detail = ""
        if exc.code == 401 and ID_TOKEN_COMMAND and "user access token" in str(detail) and _retry:
            return call(path, body, _retry=False)   # expired or revoked: fetch a fresh one once
        hint = {401: "token rejected; the hook and server tokens differ",
                403: "your desktop user doesn't match your signed-in account",
                500: "server error; see the server log"}.get(exc.code, "")
        if detail and exc.code in (401, 403, 503):
            hint = str(detail)[:200]
        raise GovernanceUnavailable(f"the server returned HTTP {exc.code}" + (f" ({hint})" if hint else "")) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise GovernanceUnavailable(f"no answer from {API} within {TIMEOUT:g} s (GOV_TIMEOUT)") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise GovernanceUnavailable(f"no answer from {API} within {TIMEOUT:g} s (GOV_TIMEOUT)") from exc
        if isinstance(reason, ConnectionRefusedError):
            raise GovernanceUnavailable(f"nothing is listening at {API}; is the server running?") from exc
        raise GovernanceUnavailable(f"cannot reach {API}: {reason}") from exc
    except (OSError, ValueError) as exc:
        raise GovernanceUnavailable(f"error talking to {API}: {exc}") from exc


def read_stdin_json() -> dict:
    try:
        raw = sys.stdin.read()
    except Exception:  # noqa: BLE001
        return {}
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw}


def summarise(res: dict) -> str:
    counts: dict[str, int] = {}
    for f in res.get("findings", []):
        if f["action"] != "allow":
            counts[f["entity"]] = counts.get(f["entity"], 0) + 1
    return ", ".join(f"{k} ({v})" for k, v in sorted(counts.items())) or res.get("reason", "")


def find_paths(obj, found=None) -> list[str]:
    """Collect file paths from a tool input, whatever the tool calls the field."""
    found = [] if found is None else found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and PATH_KEY_RE.search(k):
                found.append(v)
            elif isinstance(v, list) and PATH_KEY_RE.search(k):
                found.extend(x for x in v if isinstance(x, str))
            else:
                find_paths(v, found)
    elif isinstance(obj, list):
        for v in obj:
            find_paths(v, found)
    return found


def find_commands(obj) -> list[str]:
    if isinstance(obj, dict):
        return [v for k, v in obj.items() if k in COMMAND_KEYS and isinstance(v, str)]
    return []


def resolve_path(path: str, cwd: str) -> str:
    path = os.path.expanduser(path)
    return path if os.path.isabs(path) else os.path.join(cwd or os.getcwd(), path)


def scan_file(path: str, ctx: dict) -> dict:
    body = {**ctx, "file_path": path, "channel": "file_read"}
    try:
        size = os.path.getsize(path)
    except OSError:
        return call("/v1/scan-file", body)  # path rules still apply to missing files
    if size <= MAX_FILE_BYTES:
        with open(path, "rb") as fh:
            body["content_b64"] = base64.b64encode(fh.read()).decode()
    else:
        return {"decision": "block", "reason": f"file larger than {MAX_FILE_BYTES // 1048576} MB is not sent to the AI assistant",
                "findings": []}
    return call("/v1/scan-file", body)


def write_sanitized(path: str, res: dict, cwd: str) -> str | None:
    """Write a redacted copy next to the project and return its path."""
    base = _setting("GOV_SANITIZED_DIR") or os.path.join(cwd or os.getcwd(), ".governance-sanitized")
    os.makedirs(base, exist_ok=True)
    tag = hashlib.sha256(os.path.abspath(path).encode()).hexdigest()[:8]
    name = os.path.basename(path)
    if res.get("redacted_image_b64"):
        out = os.path.join(base, f"{tag}_{os.path.splitext(name)[0]}.png")
        with open(out, "wb") as fh:
            fh.write(base64.b64decode(res["redacted_image_b64"]))
        return out
    if res.get("redacted_text") is not None:
        if res.get("extraction", "").startswith("pdf"):
            name += ".txt"
        out = os.path.join(base, f"{tag}_{name}")
        with open(out, "w", encoding="utf-8", newline="") as fh:
            fh.write(res["redacted_text"])
        return out
    return None


def emit_json(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


# ------------------------------------------------------------- Claude Code
def claude_prompt(payload: dict, ctx: dict) -> int:
    prompt = payload.get("prompt", "")
    m = JUSTIFY_RE.search(prompt)
    ctx["justification"] = m.group(1).strip() if m else ""
    res = call("/v1/scan", {**ctx, "text": prompt, "channel": "prompt"})
    decision = res["decision"]
    if decision in ("allow", "warn_allow"):
        return 0
    found = summarise(res)
    if decision == "warn":
        reason = (f"Governance: this prompt contains {found}. If it is needed, resend it "
                  f"with '#justify: <reason>' on a new line. Your justification is logged.")
    elif decision == "block":
        reason = (f"Governance: blocked. This prompt contains {found}, which must not be sent to "
                  f"an external AI service. Remove it and try again.")
    else:  # mask / pseudonymize: hooks cannot rewrite a prompt, so offer the redacted text
        reason = (f"Governance: this prompt contains {found}. Prompts cannot be changed in flight, "
                  f"so resend this redacted version instead:\n\n{res.get('redacted_text', '')}")
    emit_json({"decision": "block", "reason": reason})
    return 0


def claude_pretool(payload: dict, ctx: dict) -> int:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()

    def deny(reason: str) -> int:
        emit_json({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}})
        return 0

    if tool == "Read":
        path = resolve_path(tool_input.get("file_path", ""), cwd)
        res = scan_file(path, ctx)
        d = res["decision"]
        if d == "block":
            return deny(f"Governance: reading {os.path.basename(path)} is blocked ({summarise(res)}).")
        if d in REWRITE_ACTIONS:
            copy = write_sanitized(path, res, cwd)
            if not copy:
                return deny(f"Governance: {os.path.basename(path)} contains {summarise(res)}.")
            new_input = {**tool_input, "file_path": copy}
            emit_json({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": f"Governance: serving a redacted copy ({summarise(res)} masked).",
                "updatedInput": new_input,
                "additionalContext": (f"The file {path} contained restricted data ({summarise(res)}). "
                                      f"You were given a redacted copy; placeholders like <IN_MOBILE> "
                                      f"stand for removed values. Do not try to recover them."),
            }})
            return 0
        if d == "warn":
            return deny(f"Governance: {os.path.basename(path)} needs a justification ({summarise(res)}).")
        return 0

    # Bash commands and MCP tool inputs: text leaving the machine or entering context.
    texts = find_commands(tool_input) if tool == "Bash" else [json.dumps(tool_input)]
    for t in texts:
        res = call("/v1/scan", {**ctx, "text": t, "channel": "command" if tool == "Bash" else "tool_input"})
        if res["decision"] in ("block", "mask", "pseudonymize", "warn"):
            return deny(f"Governance: the {tool} input contains {summarise(res)}.")
    return 0


def _replace_strings(obj, replacements: list[str], counter: list[int]):
    if isinstance(obj, str):
        value = replacements[counter[0]]
        counter[0] += 1
        return value
    if isinstance(obj, dict):
        return {k: _replace_strings(v, replacements, counter) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_strings(v, replacements, counter) for v in obj]
    return obj


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def claude_posttool(payload: dict, ctx: dict) -> int:
    response = payload.get("tool_response")
    if response is None:
        return 0
    texts = _strings(response)
    if not texts:
        return 0
    res = call("/v1/scan-batch", {**ctx, "texts": texts, "channel": "tool_output"})
    d = res["decision"]
    if d in ("allow", "warn_allow"):
        return 0
    if d == "block":
        withheld = [f"[Withheld by governance policy: {summarise(res)}]"] * len(texts)
        replacement = _replace_strings(response, withheld, [0])
        context = f"The {payload.get('tool_name')} output contained {summarise(res)} and was withheld."
    else:
        replacement = _replace_strings(response, res["redacted_texts"], [0])
        context = f"Restricted values ({summarise(res)}) were masked in the {payload.get('tool_name')} output."
    emit_json({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                      "updatedToolOutput": replacement,
                                      "additionalContext": context}})
    return 0


# -------------------------------------------------------------------- Kiro
def kiro_block(msg: str) -> int:
    sys.stderr.write(msg.rstrip() + "\n")
    return 2


def _kiro_prompt_text(payload: dict) -> str:
    """Kiro IDE 1.x sends the prompt in the stdin JSON; 0.12 used a USER_PROMPT env var
    holding a JSON string; some 1.0.x builds send an empty prompt."""
    text = payload.get("prompt") or payload.get("user_prompt") or ""
    if not text:
        env = os.getenv("USER_PROMPT", "")
        try:
            decoded = json.loads(env) if env else ""
            text = decoded if isinstance(decoded, str) else json.dumps(decoded)
        except ValueError:
            text = env
    return text or payload.get("_raw", "")


def kiro_prompt(payload: dict, ctx: dict) -> int:
    prompt = _kiro_prompt_text(payload)
    if not prompt.strip():
        # Nothing to scan: this Kiro build does not pass the prompt to hooks.
        # File reads, shell and MCP calls are still checked by the Pre Tool Use hooks.
        debug("kiro prompt hook received no prompt text; upgrade Kiro IDE to 1.2 or later")
        return 0
    m = JUSTIFY_RE.search(prompt)
    ctx["justification"] = m.group(1).strip() if m else ""
    res = call("/v1/scan", {**ctx, "text": prompt, "channel": "prompt"})
    d = res["decision"]
    if d in ("allow", "warn_allow"):
        return 0
    found = summarise(res)
    if d == "warn":
        return kiro_block(f"Governance: prompt contains {found}. Resend with '#justify: <reason>' if it is needed.")
    if d == "block":
        return kiro_block(f"Governance: prompt blocked. It contains {found}, which must not leave the company.")
    return kiro_block(f"Governance: prompt contains {found}. Resend this redacted version:\n\n{res.get('redacted_text', '')}")


def kiro_pretool(payload: dict, ctx: dict) -> int:
    tool_input = payload.get("tool_input") or {}
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            tool_input = {"command": tool_input}
    cwd = payload.get("cwd") or os.getcwd()
    tool = payload.get("tool_name", "")

    for raw in find_paths(tool_input):
        path = resolve_path(raw, cwd)
        if os.path.isdir(path):
            continue
        res = scan_file(path, ctx)
        d = res["decision"]
        if d == "block":
            return kiro_block(f"Governance: reading {raw} is blocked ({summarise(res)}). Do not retry this file.")
        if d in REWRITE_ACTIONS:
            copy = write_sanitized(path, res, cwd)
            if copy:
                return kiro_block(
                    f"Governance: {raw} contains {summarise(res)}. Read the redacted copy at "
                    f"{copy} instead; placeholders like <IN_MOBILE> stand for removed values.")
            return kiro_block(f"Governance: {raw} contains {summarise(res)} and cannot be read.")
        if d == "warn":
            return kiro_block(f"Governance: {raw} contains {summarise(res)}; ask the user to confirm and justify.")

    texts = find_commands(tool_input) or ([json.dumps(tool_input)] if tool_input else [])
    for t in texts:
        res = call("/v1/scan", {**ctx, "text": t, "channel": "tool_input"})
        if res["decision"] in ("block", "mask", "pseudonymize", "warn"):
            return kiro_block(f"Governance: the {tool or 'tool'} input contains {summarise(res)}.")
    return 0


def kiro_posttool(payload: dict, ctx: dict) -> int:
    # Kiro cannot rewrite tool output; scan for the audit trail and warn the agent.
    texts = _strings(payload.get("tool_response") or payload.get("tool_output") or payload.get("output") or "")
    if not texts:
        return 0
    res = call("/v1/scan-batch", {**ctx, "texts": texts, "channel": "tool_output"})
    if res["decision"] not in ("allow", "warn_allow"):
        sys.stdout.write(
            f"Governance notice: the last tool output contained {summarise(res)}. "
            f"Do not repeat, summarise or transmit those values.\n")
    return 0


HANDLERS = {
    ("claude", "prompt"): claude_prompt,
    ("claude", "pretool"): claude_pretool,
    ("claude", "posttool"): claude_posttool,
    ("kiro", "prompt"): kiro_prompt,
    ("kiro", "pretool"): kiro_pretool,
    ("kiro", "posttool"): kiro_posttool,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", choices=["claude", "kiro"], required=True)
    ap.add_argument("--event", choices=["prompt", "pretool", "posttool"], required=True)
    args = ap.parse_args()

    payload = read_stdin_json()
    # Kiro IDE 0.12 used camelCase field names; normalise to the 1.x snake_case envelope.
    for old, new in (("toolName", "tool_name"), ("toolArgs", "tool_input"), ("toolResult", "tool_response")):
        if old in payload and new not in payload:
            payload[new] = payload[old]
    debug(f"[{args.agent}/{args.event}] payload keys: {sorted(payload)}")
    ctx = {
        **identity(),
        "agent": "claude-code" if args.agent == "claude" else "kiro-ide",
        "hook_event": args.event,
        "session_id": str(payload.get("session_id", "")),
        "tool_name": str(payload.get("tool_name", "")),
        "cwd": str(payload.get("cwd", "")),
    }
    try:
        return HANDLERS[(args.agent, args.event)](payload, ctx)
    except GovernanceUnavailable as exc:
        debug(f"governance API unavailable: {exc}")
        problem = _config_error()
        detail = (f"the governance hook is misconfigured: {problem}" if problem
                  else f"the data-protection check failed: {exc}")
        msg = (f"Governance: {detail}, so this action is blocked (fail-closed). "
               "Ask IT to check the ai-governance configuration and server.")
        if FAIL_OPEN:
            return 0
        if args.agent == "kiro":
            # Kiro cannot stop output that already arrived; only prompts and tool calls block.
            return 0 if args.event == "posttool" else kiro_block(msg)
        if args.event == "posttool":
            # Claude Code can still keep the unscanned output away from the model.
            emit_json({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                              "updatedToolOutput": _replace_strings(
                                                  payload.get("tool_response"),
                                                  [msg] * len(_strings(payload.get("tool_response"))), [0]),
                                              "additionalContext": msg}})
            return 0
        if args.event == "prompt":
            emit_json({"decision": "block", "reason": msg})
        else:
            emit_json({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                              "permissionDecision": "deny",
                                              "permissionDecisionReason": msg}})
        return 0


if __name__ == "__main__":
    sys.exit(main())
