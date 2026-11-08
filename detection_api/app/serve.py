"""Start the API with host, port and workers taken from configuration.

    python -m app.serve                      # reads env vars / .env / *_FILE secrets
    GOV_ENV_FILE=../.env python -m app.serve

Configuration is validated before uvicorn starts, so a missing secret fails fast
with a clear message instead of starting an unauthenticated server.
"""

from __future__ import annotations

import sys

import uvicorn

from .settings import load_settings


def main() -> int:
    try:
        s = load_settings()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2
    if s.auth_disabled:
        print("WARNING: GOV_AUTH_DISABLED=true - the API accepts unauthenticated requests.", file=sys.stderr)
    uvicorn.run("app.main:app", host=s.host, port=s.port, workers=s.workers,
                log_level=s.log_level, proxy_headers=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
