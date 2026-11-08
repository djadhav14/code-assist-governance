#!/usr/bin/env python3
"""Build Intune deployment packages for the ai-governance hooks.

    GOV_API_URL=https://governance.internal:8088 \
    python intune/build_intune_packages.py --agent both --token-file secrets/gov_api_token \
        --idc-start-url https://my-org.awsapps.com/start --idc-region ap-south-1 \
        --set "GOV_ID_TOKEN_COMMAND=az account get-access-token --scope api://<app-id>/.default --query accessToken -o tsv"

--set KEY=VALUE   extra hook setting written into the locked governance.env, e.g.
                  GOV_CA_BUNDLE, GOV_TIMEOUT, GOV_ID_TOKEN_COMMAND (repeatable). Embedded
                  base64-encoded, so values may contain spaces and quotes.

--agent claude | kiro | both   (default both)

Outputs (in intune/out/):
  windows/                     source folder for a Win32 app. Wrap it on a Windows machine with
                               IntuneWinAppUtil.exe -c intune\\out\\windows -s Install-AIGovernance.ps1 -o intune\\out
  Detect-AIGovernance.ps1      custom detection script for that Win32 app
  ai-governance-linux.sh       self-contained Intune Linux platform script (payload embedded)

The version stamp is a hash of the hook, the installer and the build options, so
Intune redeploys whenever any of them changes and the packages are rebuilt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import shutil
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLIENTS = os.path.join(ROOT, "clients")
TEMPLATES = os.path.join(HERE, "templates")
PAYLOAD_FILES = ("governance_hook.py", "install_hooks.py")
PLACEHOLDERS = ("VERSION", "AGENT", "API_URL", "TOKEN", "KIRO_POLICY_WINDOWS", "KIRO_POLICY_LINUX",
                "IDC_START_URL", "IDC_REGION", "SETTINGS_B64", "PAYLOAD_B64")
sys.path.insert(0, CLIENTS)
from install_hooks import ALLOWED_EXTRA  # noqa: E402  same allow-list as the installer


def version(options: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in PAYLOAD_FILES:
        with open(os.path.join(CLIENTS, name), "rb") as fh:
            h.update(fh.read())
    for key in sorted(options):
        if key != "TOKEN":
            h.update(f"{key}={options[key]}".encode())
    return h.hexdigest()[:12]


def render(template: str, values: dict[str, str]) -> str:
    with open(os.path.join(TEMPLATES, template), encoding="utf-8") as fh:
        text = fh.read()
    for key, value in values.items():
        text = text.replace(f"__{key}__", value)
    leftover = [p for p in PLACEHOLDERS if f"__{p}__" in text]
    if leftover:
        raise SystemExit(f"{template}: unreplaced placeholders {leftover}")
    return text


def payload_b64() -> str:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in PAYLOAD_FILES:
            tar.add(os.path.join(CLIENTS, name), arcname=name)
    raw = base64.b64encode(buf.getvalue()).decode()
    return "\n".join(raw[i : i + 76] for i in range(0, len(raw), 76))


def write(path: str, text: str, crlf: bool = False) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\r\n" if crlf else "\n") as fh:
        fh.write(text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", choices=["claude", "kiro", "both"], default="both")
    ap.add_argument("--api-url", default=os.getenv("GOV_API_URL", ""),
                    help="governance API URL reachable from developer laptops (or set GOV_API_URL)")
    ap.add_argument("--token-file", default=os.getenv("GOV_API_TOKEN_FILE", ""),
                    help="file holding the API token (preferred), or set GOV_API_TOKEN")
    ap.add_argument("--token", default="", help="token on the command line (discouraged)")
    ap.add_argument("--kiro-policy-path-windows", default="",
                    help="Kiro admin managed-settings.json path on Windows (default: installer's built-in path)")
    ap.add_argument("--kiro-policy-path-linux", default="",
                    help="Kiro admin managed-settings.json path on Linux (default: installer's built-in path)")
    ap.add_argument("--idc-start-url", default="", help="restrict Kiro sign-in to this IAM Identity Center start URL")
    ap.add_argument("--idc-region", default="", help="AWS Region of the Identity Center directory")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="extra hook setting for the locked governance.env (repeatable)")
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    args = ap.parse_args()
    if not args.api_url:
        raise SystemExit("Set the API URL with --api-url or GOV_API_URL.")
    if args.token_file:
        with open(os.path.expanduser(args.token_file), encoding="utf-8") as fh:
            args.token = fh.read().strip()
    elif not args.token:
        args.token = os.getenv("GOV_API_TOKEN", "")
    if not args.token:
        raise SystemExit("Provide the API token with --token-file or GOV_API_TOKEN.")
    if args.api_url.startswith("http://") and not args.api_url.startswith(("http://127.0.0.1", "http://localhost")):
        raise SystemExit("Use an https:// API URL for fleet packages; the hooks refuse plain http to remote hosts.")

    for value in (args.api_url, args.token, args.idc_start_url, args.idc_region,
                  args.kiro_policy_path_windows, args.kiro_policy_path_linux):
        if any(c in value for c in "\"'`$\n"):
            raise SystemExit(f"Option value contains a quote, $ or newline, which the scripts cannot embed safely: {value!r}")

    settings_lines = []
    for item in args.set:
        key, _, value = item.partition("=")
        if key not in ALLOWED_EXTRA or not value or "\n" in value:
            raise SystemExit(f"--set {item!r}: allowed keys are {', '.join(sorted(ALLOWED_EXTRA))}")
        settings_lines.append(f"{key}={value}")
    settings_b64 = base64.b64encode("\n".join(settings_lines).encode()).decode() if settings_lines else ""

    options = {
        "AGENT": args.agent, "API_URL": args.api_url, "TOKEN": args.token,
        "KIRO_POLICY_WINDOWS": args.kiro_policy_path_windows, "KIRO_POLICY_LINUX": args.kiro_policy_path_linux,
        "IDC_START_URL": args.idc_start_url, "IDC_REGION": args.idc_region,
        "SETTINGS_B64": settings_b64,
    }
    values = {**options, "VERSION": version(options)}
    if os.path.isdir(args.out):
        shutil.rmtree(args.out)

    win = os.path.join(args.out, "windows")
    for t in ("Install-AIGovernance.ps1", "Uninstall-AIGovernance.ps1"):
        write(os.path.join(win, t), render(t, values), crlf=True)
    for name in PAYLOAD_FILES:
        shutil.copy2(os.path.join(CLIENTS, name), os.path.join(win, name))
    # The detection script is uploaded to Intune separately, not packaged.
    write(os.path.join(args.out, "Detect-AIGovernance.ps1"), render("Detect-AIGovernance.ps1", values), crlf=True)

    linux = os.path.join(args.out, "ai-governance-linux.sh")
    write(linux, render("ai-governance-linux.sh", {**values, "PAYLOAD_B64": payload_b64()}))
    os.chmod(linux, 0o755)

    print(f"Built ai-governance {values['VERSION']} for {args.agent}")
    print(f"  Windows Win32 source folder : {win}")
    print(f"  Windows detection script    : {os.path.join(args.out, 'Detect-AIGovernance.ps1')}")
    print(f"  Linux platform script       : {linux}")
    if args.agent != "claude" and not (args.kiro_policy_path_windows and args.kiro_policy_path_linux):
        print("  NOTE: Kiro documents its admin policy path for macOS only. Confirm the Windows/Linux paths")
        print("        and pass --kiro-policy-path-windows / --kiro-policy-path-linux if they differ from")
        print("        the installer defaults (C:\\Program Files\\Kiro\\..., /etc/kiro/...).")
    print("These files contain the API token: keep intune/out/ out of source control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
