#!/usr/bin/env python3
"""Create local configuration for the AI Governance server.

    python scripts/init_secrets.py            # create .env and secrets/ if missing
    python scripts/init_secrets.py --rotate   # replace both secrets with new random values

Creates
  .env                       non-secret settings, copied from .env.example; on Linux/macOS
                             GOV_UID/GOV_GID are set to your user so the OTel Collector
                             container can write audit events into ./logs
  logs/                      folder for the collector's audit event file
  secrets/gov_api_token      random API token  (shared with the IDE hooks)
  secrets/gov_hash_key       random HMAC key   (server only; never leaves the server)

Permissions (Linux/macOS): secrets/ is 0700 so other host users cannot open it.
The files inside are 0644 because Docker Compose bind-mounts them into the
container, where the server runs as an unprivileged user (UID 10001) that must
be able to read them. On Windows, the folder inherits your user profile's ACL;
keep the project inside your profile.

Rotating the API token requires updating every hook client (rebuild and redeploy
the Intune packages). Rotating the hash key changes every value fingerprint and
pseudonym token, so old audit events no longer correlate with new ones.
"""

from __future__ import annotations

import argparse
import os
import platform
import secrets
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRETS = {"gov_api_token": 32, "gov_hash_key": 48}


SECRET_KEYS = ("GOV_API_TOKEN", "GOV_HASH_KEY")


def _key(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return ""
    return line.removeprefix("export ").split("=", 1)[0].strip()


def upgrade_env(env_path: str, example_path: str) -> None:
    """Bring a .env from an older version up to date, keeping the user's values.

    * Adds settings that are in .env.example but missing from .env.
    * Comments out GOV_API_TOKEN / GOV_HASH_KEY: before version 0.4 these were kept
      in .env; they now live in secrets/, and a stale copy in .env would override it.
    """
    with open(env_path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    present = {_key(l) for l in lines}
    changed = []
    for i, line in enumerate(lines):
        if _key(line) in SECRET_KEYS:
            lines[i] = "# moved to secrets/ by init_secrets.py: " + _key(line) + "=<removed>"
            changed.append(f"removed {_key(line)} (now read from secrets/)")
    with open(example_path, encoding="utf-8") as fh:
        missing = [l for l in fh.read().splitlines()
                   if _key(l) and _key(l) not in present and _key(l) not in SECRET_KEYS]
    if missing:
        lines += ["", "# --- added by init_secrets.py (settings introduced after this .env was created) ---"]
        lines += missing
        changed += [f"added {_key(l)}" for l in missing]
    if changed:
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        for c in changed:
            print(f"        upgraded .env: {c}")


def set_owner_ids(env_path: str) -> None:
    """Record the current user's UID/GID in .env (used by docker-compose.yml)."""
    with open(env_path, encoding="utf-8") as fh:
        lines = [l for l in fh.read().splitlines() if not l.startswith(("GOV_UID=", "GOV_GID="))]
    lines += [f"GOV_UID={os.getuid()}", f"GOV_GID={os.getgid()}"]
    with open(env_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rotate", action="store_true", help="overwrite existing secrets with new values")
    ap.add_argument("--dir", default=os.path.join(ROOT, "secrets"), help="secrets folder")
    args = ap.parse_args()

    env_path = os.path.join(ROOT, ".env")
    if not os.path.exists(env_path):
        shutil.copyfile(os.path.join(ROOT, ".env.example"), env_path)
        print(f"created {env_path}")
    else:
        print(f"kept    {env_path}")
        upgrade_env(env_path, os.path.join(ROOT, ".env.example"))
    posix = platform.system() != "Windows"
    if posix:
        set_owner_ids(env_path)
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    os.makedirs(args.dir, exist_ok=True)
    if posix:
        os.chmod(args.dir, 0o700)
    for name, nbytes in SECRETS.items():
        path = os.path.join(args.dir, name)
        if os.path.exists(path) and not args.rotate:
            print(f"kept    {path}")
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(secrets.token_urlsafe(nbytes) + "\n")
        if posix:
            os.chmod(path, 0o644)  # readable by the container user; the 0700 folder keeps other users out
        print(f"{'rotated' if args.rotate else 'created'} {path}")

    print("\nNext: python scripts/doctor.py    (checks your setup)")
    print("      docker compose up -d --build")
    print("Give the IDE hooks the token with:  --token-file secrets/gov_api_token")
    return 0


if __name__ == "__main__":
    sys.exit(main())
