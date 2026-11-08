#!/usr/bin/env python3
"""Check that the AI Governance package and this machine are ready.

    python scripts/doctor.py            # package, configuration, Docker, server
    python scripts/doctor.py --local    # no-Docker route: checks Python packages and Tesseract;
                                        # Docker problems become warnings

Standard library only. Every failed check prints how to fix it. Exit code 0 means
no failures (warnings are allowed).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file the package ships. A missing one means an incomplete or old download.
MANIFEST = [
    "VERSION", "CHANGELOG.md", "README.md", "LICENSE", "SECURITY.md", ".env.example", ".gitignore",
    "docker-compose.yml", "otel-collector.yaml", "logs/.gitkeep", ".github/workflows/ci.yml",
    "detection_api/Dockerfile", "detection_api/requirements.txt", "detection_api/policy.yaml",
    "detection_api/rules/recognizers.json", "detection_api/models/README.md",
    "detection_api/app/__init__.py", "detection_api/app/main.py", "detection_api/app/serve.py",
    "detection_api/app/settings.py", "detection_api/app/engine.py", "detection_api/app/rules.py",
    "detection_api/app/policy.py", "detection_api/app/audit.py", "detection_api/app/identity.py",
    "clients/governance_hook.py", "clients/install_hooks.py",
    "scripts/init_secrets.py", "scripts/doctor.py", "scripts/validate_rules.py", "scripts/ci.sh",
    "tests/_config.py", "tests/make_samples.py", "tests/test_api.py", "tests/test_hooks.py",
    "tests/test_rules.py", "tests/test_policy.py", "tests/test_identity.py", "tests/test_aws_secrets.py",
    "tests/test_offline_suffix.py",
    "deploy/aws/docker-compose.test-server.yml", "deploy/aws/Caddyfile", "deploy/aws/test-server.env.example",
    "deploy/aws/iam-policy-read-secret.json", "deploy/aws/ecs-task-definition.template.json",
    "intune/build_intune_packages.py",
    "intune/templates/Install-AIGovernance.ps1", "intune/templates/Uninstall-AIGovernance.ps1",
    "intune/templates/Detect-AIGovernance.ps1", "intune/templates/ai-governance-linux.sh",
    "docs/architecture.md", "docs/configuration.md", "docs/detection-api.md", "docs/detection-rules.md",
    "docs/ide-hooks.md", "docs/intune.md", "docs/debugging.md",
    "siem/wazuh/README-wazuh.md", "siem/wazuh/ai_governance_rules.xml", "siem/wazuh/setup_wazuh.py",
    "siem/wazuh/check_wazuh.py", "siem/wazuh/sample-events.jsonl",
]

results = {"fail": 0, "warn": 0}


def report(ok: bool | None, label: str, fix: str = "") -> None:
    """ok=True pass, False fail, None warning."""
    tag = "PASS" if ok else ("WARN" if ok is None else "FAIL")
    if ok is False:
        results["fail"] += 1
    elif ok is None:
        results["warn"] += 1
    print(f"  [{tag}] {label}")
    if fix and not ok:
        for line in fix.strip().splitlines():
            print(f"         {line}")


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


# Files removed in later versions. Unzipping a new version over an old folder
# doesn't delete them; they are unused, but they mislead anyone reading the code.
STALE = {
    "detection_api/app/recognizers.py": "0.7.0 (patterns moved to detection_api/rules/recognizers.json)",
    "docs/ide-setup.md": "1.0.0 (replaced by docs/ide-hooks.md and docs/intune.md)",
    "intune/README-intune.md": "1.0.0 (replaced by docs/intune.md)",
}


def check_package() -> None:
    print("\nPackage")
    version_file = os.path.join(ROOT, "VERSION")
    version = open(version_file).read().strip() if os.path.exists(version_file) else "unknown"
    missing = [f for f in MANIFEST if not os.path.exists(os.path.join(ROOT, f))]
    report(not missing, f"all {len(MANIFEST)} package files present (version {version})",
           "Missing: " + ", ".join(missing) + "\nYou probably have an older or incomplete download; "
           "re-download the latest ai-governance-local zip.")
    report(sys.version_info >= (3, 9), f"Python {sys.version.split()[0]} (3.9+ needed)",
           "Install Python 3.9 or later.")
    stale = [f for f in STALE if os.path.exists(os.path.join(ROOT, f))]
    report(None if stale else True,
           "no leftover files from older versions" if not stale else
           "leftover files from an older version (not used by the server)",
           "\n".join(f"{f}: removed in {STALE[f]}" for f in stale)
           + "\nDelete them: rm " + " ".join(stale) if stale else "")
    rules_file = os.path.join(ROOT, "detection_api", "rules", "recognizers.json")
    if os.path.exists(rules_file):
        sys.path.insert(0, os.path.join(ROOT, "detection_api"))
        from app import rules as rl
        try:
            rs = rl.load_file(rules_file)
            report(True, f"detection rules valid (version {rs.version}, {len(rs.enabled)} recognizers)")
        except rl.RulesError as exc:
            report(False, "detection rules file is invalid; the server will not start with it",
                   "\n".join(exc.problems) + "\nDetails: python3 scripts/validate_rules.py")


def env_values() -> dict:
    sys.path.insert(0, os.path.join(ROOT, "detection_api"))
    from app.settings import parse_env_file

    path = os.path.join(ROOT, ".env")
    return parse_env_file(path) if os.path.exists(path) else {}


def check_config() -> tuple[str, str]:
    print("\nConfiguration")
    env_path = os.path.join(ROOT, ".env")
    report(os.path.exists(env_path), ".env exists", "Run: python scripts/init_secrets.py")
    values = env_values()
    stale = [k for k in ("GOV_API_TOKEN", "GOV_HASH_KEY") if values.get(k)]
    report(not stale, ".env holds no secrets (they belong in secrets/)",
           f"{', '.join(stale)} found in .env, probably from an older version; it overrides secrets/.\n"
           "Run: python3 scripts/init_secrets.py   (upgrades .env and moves you to secrets/)")
    token = ""
    for name in ("gov_api_token", "gov_hash_key"):
        path = os.path.join(ROOT, "secrets", name)
        value = open(path).read().strip() if os.path.exists(path) else ""
        report(len(value) >= 16, f"secrets/{name} present (16+ characters)", "Run: python scripts/init_secrets.py")
        if name == "gov_api_token":
            token = value
    if os.name != "nt":
        report(bool(values.get("GOV_UID")), "GOV_UID/GOV_GID set in .env (collector can write ./logs)",
               "Run: python scripts/init_secrets.py   (it adds them to an existing .env)")
    url = os.getenv("GOV_API_URL") or values.get("GOV_API_URL", "")
    report(bool(url), f"GOV_API_URL = {url or '(not set)'}", "Set GOV_API_URL in .env, e.g. http://127.0.0.1:8088")
    return url, token


def check_docker(optional: bool = False) -> None:
    print("\nDocker" + (" (optional for the no-Docker route)" if optional else ""))
    fail = None if optional else False
    if not shutil.which("docker"):
        report(fail, "docker command found",
               "Install Docker Engine (Ubuntu) or Docker Desktop (Windows/macOS/Ubuntu),\n"
               "or skip Docker and use the no-Docker route in README step 3B.")
        return
    report(True, "docker command found")
    code, out = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if code != 0:
        _, ctx = run(["docker", "context", "show"])
        hint = ("The docker command cannot reach a Docker engine.\n"
                f"Current context: {ctx or 'unknown'}  (list them with: docker context ls)\n")
        if "desktop" in (out + ctx).lower():
            hint += ("It points at Docker Desktop, which is not running. Either start it:\n"
                     "  systemctl --user start docker-desktop    (or open Docker Desktop)\n"
                     "or, if you use the standard Docker Engine instead:\n"
                     "  docker context use default && sudo systemctl start docker\n")
        elif "permission denied" in out.lower():
            hint += "Add yourself to the docker group: sudo usermod -aG docker $USER, then log out and in.\n"
        else:
            hint += "Start the engine: sudo systemctl start docker   (or start Docker Desktop)\n"
        if os.getenv("DOCKER_HOST"):
            hint += f"Note: DOCKER_HOST={os.environ['DOCKER_HOST']} overrides the context; try: unset DOCKER_HOST\n"
        report(fail, "Docker engine reachable", hint)
        return
    report(True, f"Docker engine reachable (server {out})")
    code, out = run(["docker", "compose", "version", "--short"])
    report(code == 0, f"docker compose v2 available ({out if code == 0 else 'missing'})",
           "Install the Docker Compose plugin (docker-compose-plugin package), or update Docker Desktop.")


def check_local() -> None:
    print("\nNo-Docker route")
    try:
        import presidio_analyzer  # noqa: F401
        import fastapi  # noqa: F401
        report(True, "server Python packages installed")
    except ImportError as exc:
        report(False, f"server Python packages installed ({exc.name} missing)",
               "Run: python -m pip install -r detection_api/requirements.txt")
    try:
        import spacy

        spacy.load(os.getenv("GOV_NLP_MODEL", "en_core_web_lg"))
        report(True, "spaCy model installed")
    except Exception:  # noqa: BLE001
        report(False, "spaCy model installed",
               "Run: python -m spacy download en_core_web_lg   (or en_core_web_sm, and set GOV_NLP_MODEL)")
    report(bool(shutil.which("tesseract")) or None, "Tesseract OCR found (needed only for images and scanned PDFs)",
           "Ubuntu: sudo apt install tesseract-ocr   Windows: install from the UB-Mannheim Tesseract build")


def check_server(url: str, token: str) -> None:
    print("\nServer")
    if not url:
        report(False, "server check skipped (no GOV_API_URL)")
        return
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/healthz", timeout=5) as r:
            health = json.load(r)
        report(True, f"{url}/healthz answers (auth: {health.get('auth')}, model: {health.get('nlp_model')})")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        report(None, f"server not reachable at {url} ({exc})",
               "Start it: docker compose up -d --build   (or README step 3B without Docker)\n"
               "If it is starting, wait for: docker compose ps  ->  detection-api (healthy)")
        return
    body = json.dumps({"text": "hello", "channel": "prompt"}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/v1/scan", data=body,
                                 headers={"Content-Type": "application/json", "X-Gov-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            report(r.status == 200, "API accepts the token in secrets/gov_api_token")
    except urllib.error.HTTPError as exc:
        report(False, f"API rejected the token (HTTP {exc.code})",
               "The server was started with a different token. Restart it after init_secrets.py:\n"
               "  docker compose up -d --force-recreate detection-api")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", action="store_true", help="also check the no-Docker route")
    args = ap.parse_args()
    print(f"AI Governance setup check  ({ROOT})")
    check_package()
    url, token = check_config()
    check_docker(optional=args.local)
    if args.local:
        check_local()
    check_server(url, token)
    print(f"\n{results['fail']} failure(s), {results['warn']} warning(s)")
    return 1 if results["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
