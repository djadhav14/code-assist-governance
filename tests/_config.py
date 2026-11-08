"""Test configuration: environment variables first, then the repo's .env and secrets.

No addresses or tokens are hard-coded. Set GOV_API_URL and GOV_API_TOKEN (or
GOV_API_TOKEN_FILE), or run scripts/init_secrets.py to create .env and secrets/.

For a remote test server:
  GOV_CA_BUNDLE         PEM file of the CA that signed the server's certificate
  GOV_ID_TOKEN_COMMAND  command printing your access token, if the server runs
                        GOV_AUTH_MODE=token+oidc (sent as Authorization: Bearer)
"""

from __future__ import annotations

import os
import ssl
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env_file() -> dict:
    sys.path.insert(0, os.path.join(ROOT, "detection_api"))
    from app.settings import parse_env_file  # same parser the server uses

    path = os.getenv("GOV_ENV_FILE") or os.path.join(ROOT, ".env")
    return parse_env_file(path) if os.path.isfile(path) else {}


def _resolve(name: str, file_values: dict) -> str:
    return os.getenv(name) or file_values.get(name, "")


def load() -> tuple[str, str]:
    values = _env_file()
    url = _resolve("GOV_API_URL", values).rstrip("/")
    token = _resolve("GOV_API_TOKEN", values)
    if not token:
        token_file = _resolve("GOV_API_TOKEN_FILE", values)
        if token_file:
            path = token_file if os.path.isabs(token_file) else os.path.join(ROOT, token_file)
            with open(path, encoding="utf-8") as fh:
                token = fh.read().strip()
    missing = [n for n, v in (("GOV_API_URL", url), ("GOV_API_TOKEN / GOV_API_TOKEN_FILE", token)) if not v]
    if missing:
        env_path = os.getenv("GOV_ENV_FILE") or os.path.join(ROOT, ".env")
        where = env_path if os.path.isfile(env_path) else f"{env_path} (file not found)"
        sys.exit(f"Not configured: {', '.join(missing)}\n"
                 f"Looked in environment variables and {where}.\n"
                 "Fix: python3 scripts/init_secrets.py   (creates .env and secrets/, or upgrades an older .env)")
    return url, token


def _install_opener() -> None:
    """Every urllib call in the tests then trusts GOV_CA_BUNDLE and sends the bearer token."""
    ca = os.getenv("GOV_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=ca) if ca else None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    cmd = os.getenv("GOV_ID_TOKEN_COMMAND")
    if cmd:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if out.returncode != 0 or not out.stdout.strip():
            sys.exit(f"GOV_ID_TOKEN_COMMAND failed: {(out.stderr or out.stdout).strip()[:300]}")
        opener.addheaders.append(("Authorization", "Bearer " + out.stdout.strip()))
    urllib.request.install_opener(opener)


API_URL, API_TOKEN = load()
_install_opener()
