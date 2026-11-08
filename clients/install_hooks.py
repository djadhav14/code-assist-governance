#!/usr/bin/env python3
"""Install the governance hook for Claude Code and/or Kiro IDE (Ubuntu, Windows, macOS).

Scopes
  --scope project   one repo (testing):
                      Claude Code -> <project>/.claude/settings.local.json
                      Kiro        -> <project>/.kiro/hooks/, <project>/.kiroignore
  --scope user      every project, for the signed-in user only (no admin rights; the
                    user can still edit or remove it):
                      Claude Code -> ~/.claude/settings.json (CLI and VS Code extension)
                      Kiro        -> ~/.kiro/hooks/ai-governance.json (global hooks, Kiro 1.0.182+)
                                     and ~/.kiro/settings/kiroignore
  --scope managed   whole machine, every user; needs sudo / an elevated prompt:
                      Claude Code -> OS managed-settings.json (users cannot override)
                      Kiro        -> global hooks in every user's ~/.kiro/hooks/ (and in the
                                     template profile for future users), global kiroignore,
                                     and Kiro's admin permission policy (managed-settings.json)

Examples
    python install_hooks.py --agent both --scope project --project /path/to/repo --token T
    sudo python3 install_hooks.py --agent both --scope managed --token T --lock-hooks \
         --idc-start-url https://my-org.awsapps.com/start --idc-region ap-south-1

The hook script and a "locked" config always live in an admin-only folder for
--scope managed, so users cannot redirect the hook or make it fail open.
Use --uninstall to remove what was added for the chosen scope.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEYRING_SERVICE = "ai-governance"
# Hook timeouts in seconds; override with --prompt-timeout / --tool-timeout or
# GOV_HOOK_PROMPT_TIMEOUT / GOV_HOOK_TOOL_TIMEOUT.
TIMEOUTS = {"prompt": 10, "tool": 15}
HOME = os.path.expanduser("~")
MARK = "ai-governance"
SYSTEM = platform.system()

# ------------------------------------------------------------------ policy content
SECRET_READ_DENY = [
    "Read(./.env)", "Read(./.env.*)", "Read(**/*.pem)", "Read(**/*.key)",
    "Read(**/*.p12)", "Read(**/id_rsa*)", "Read(**/secrets/**)", "Read(**/customer-data/**)",
]

SECRET_GLOBS = [
    "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx",
    "**/id_rsa*", "**/id_ed25519*", "**/secrets/**", "**/customer-data/**", "**/pii/**",
]

KIRO_ADMIN_RULES = [
    # Admin rules may only deny or ask, and a deny here beats any user allow.
    {"capability": "fs_read", "match": SECRET_GLOBS, "exclude": ["**/.env.example"], "effect": "deny"},
    {"capability": "fs_write", "match": SECRET_GLOBS, "exclude": ["**/.env.example"], "effect": "deny"},
]
KIRO_RULE_FIELDS = {"capability", "match", "exclude", "effect"}  # Kiro rejects the whole file on unknown fields

KIROIGNORE = """# --- ai-governance: never let the agent read these ---
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
id_rsa*
id_ed25519*
secrets/
customer-data/
pii/
# --- end ai-governance ---
"""

# Kiro documents its admin policy path for macOS only. The Windows and Linux
# defaults below follow the same pattern but are NOT confirmed by Kiro's docs:
# check the Windows/Linux tabs on kiro.dev/docs/enterprise/governance/permissions/
# and pass --kiro-policy-path if they differ.
KIRO_POLICY_DEFAULTS = {
    "Darwin": ("/Library/Application Support/Kiro/managed-settings.json", True),
    "Linux": ("/etc/kiro/managed-settings.json", False),
    "Windows": (os.path.join(os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles", r"C:\Program Files"),
                             "Kiro", "managed-settings.json"), False),
}


# ------------------------------------------------------------------ paths
def _rooted(path: str, root: str) -> str:
    return os.path.join(root, path.lstrip("/\\").replace(":", "")) if root else path


def managed_paths(root: str = "") -> tuple[str, str]:
    """(governance install dir, Claude Code managed-settings.json). `root` is for testing."""
    if SYSTEM == "Windows":
        # ProgramW6432 always names the 64-bit folder, even under a 32-bit parent
        # such as the Intune Management Extension.
        pf = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles", r"C:\Program Files")
        gov, cc = os.path.join(pf, "ai-governance"), os.path.join(pf, "ClaudeCode", "managed-settings.json")
    elif SYSTEM == "Darwin":
        gov = "/Library/Application Support/ai-governance"
        cc = "/Library/Application Support/ClaudeCode/managed-settings.json"
    else:
        gov, cc = "/opt/ai-governance", "/etc/claude-code/managed-settings.json"
    return _rooted(gov, root), _rooted(cc, root)


def windows_launcher_dir(root: str = "") -> str:
    # Kiro runs hook commands through a shell; a space-free launcher path works in
    # both cmd.exe and PowerShell without quoting tricks.
    return _rooted(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ai-governance"), root)


def kiro_policy_path(override: str, root: str) -> str:
    if override:
        return _rooted(override, root)
    path, verified = KIRO_POLICY_DEFAULTS.get(SYSTEM, KIRO_POLICY_DEFAULTS["Linux"])
    if not verified:
        print(f"  NOTE: Kiro's docs do not confirm the admin policy path on {SYSTEM}; using {path}.")
        print("        Confirm it in Kiro's documentation and pass --kiro-policy-path if it differs.")
    return _rooted(path, root)


def claude_settings_path(scope: str, project: str, root: str) -> str:
    if scope == "managed":
        return managed_paths(root)[1]
    if scope == "user":
        return os.path.join(HOME, ".claude", "settings.json")
    return os.path.join(project, ".claude", "settings.local.json")


def user_homes(root: str, override: list[str] | None) -> list[tuple[str, int, int]]:
    """Every local user profile plus the template for profiles created later.

    Returns (home, uid, gid); uid/gid are -1 on Windows or for templates.
    """
    if override:
        return [(h, -1, -1) for h in override]
    homes: list[tuple[str, int, int]] = []
    if SYSTEM == "Windows":
        users = _rooted(os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users"), root)
        skip = {"public", "all users", "default user", "defaultapppool"}
        for name in sorted(os.listdir(users)) if os.path.isdir(users) else []:
            path = os.path.join(users, name)
            if os.path.isdir(path) and name.lower() not in skip:
                homes.append((path, -1, -1))  # includes "Default", the new-profile template
    else:
        import pwd

        for entry in pwd.getpwall():
            if entry.pw_uid >= 1000 and entry.pw_dir.startswith(("/home/", "/Users/")) \
                    and os.path.isdir(_rooted(entry.pw_dir, root)) and entry.pw_name != "nobody":
                homes.append((_rooted(entry.pw_dir, root), entry.pw_uid, entry.pw_gid))
        skel = _rooted("/etc/skel", root)
        if SYSTEM == "Linux" and os.path.isdir(skel):
            homes.append((skel, -1, -1))
    return homes


# ---------------------------------------------------------------- helpers
def load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def save_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)  # never leave a half-written policy file (Kiro fails closed on bad JSON)


def check_writable(path: str) -> None:
    probe = os.path.dirname(path)
    while not os.path.exists(probe):
        probe = os.path.dirname(probe)
    if not os.access(probe, os.W_OK):
        hint = "an Administrator PowerShell" if SYSTEM == "Windows" else "sudo"
        sys.exit(f"Cannot write {path}. Run this installer with {hint} for --scope managed.")


def chown_tree(path: str, stop: str, uid: int, gid: int) -> None:
    """Give a user ownership of folders we created inside their home (POSIX only)."""
    if uid < 0 or SYSTEM == "Windows":
        return
    p = path
    while p.startswith(stop) and p != stop:
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass
        p = os.path.dirname(p)


def _restrict(path: str, private: bool) -> None:
    """POSIX permissions: private = owner only; otherwise world-readable, root-writable."""
    if SYSTEM == "Windows":
        return  # user profiles are private by default; managed folders get ACLs from the Intune script
    os.chmod(path, 0o600 if private else 0o644)


def _env_line(key: str, value: str) -> str:
    if any(c in value for c in "\n\r"):
        sys.exit(f"Refusing to write {key}: value contains a newline")
    return f'{key}="{value}"' if any(c in value for c in " #'") else f"{key}={value}"


def store_token_keyring(token: str) -> bool:
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, "GOV_API_TOKEN", token)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"  keyring unavailable ({exc.__class__.__name__}); falling back to a private token file")
        return False


def install_core(gov_dir: str, api_url: str, token: str, token_store: str, user: str,
                 locked: bool, extra: dict[str, str]) -> str:
    os.makedirs(gov_dir, exist_ok=True)
    if not locked and SYSTEM != "Windows":
        os.chmod(gov_dir, 0o700)
    hook = os.path.join(gov_dir, "governance_hook.py")
    shutil.copy2(os.path.join(HERE, "governance_hook.py"), hook)

    lines = ["# ai-governance hook configuration (written by install_hooks.py)",
             "# Secrets: the token lives in the OS credential store or in api_token, not here,",
             "# unless --token-store inline was chosen."]
    if locked:
        lines.append("GOV_LOCKED=true  # values here override the user's environment variables")
    lines.append(_env_line("GOV_API_URL", api_url))
    lines.append(_env_line("GOV_FAIL_MODE", "closed" if locked else extra.pop("GOV_FAIL_MODE", "closed")))

    token_file = os.path.join(gov_dir, "api_token")
    if token_store == "auto":
        token_store = "file" if locked else "keyring"
    if token_store == "keyring" and (locked or not store_token_keyring(token)):
        token_store = "file"  # a machine-wide install runs as SYSTEM/root and cannot use users' keyrings
    if token_store == "keyring":
        lines.append("GOV_TOKEN_SOURCE=keyring")
        print("  token  -> OS credential store (service 'ai-governance')")
    elif token_store == "file":
        with open(token_file, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
        # Machine-wide: the hook runs as each user, so users must be able to read it.
        _restrict(token_file, private=not locked)
        lines.append(_env_line("GOV_API_TOKEN_FILE", token_file))
        print(f"  token  -> {token_file} ({'readable by all users' if locked else 'owner only'})")
    else:
        lines.append(_env_line("GOV_API_TOKEN", token))
        print("  token  -> inline in governance.env (not recommended)")
    if token_store != "file" and os.path.exists(token_file):
        os.remove(token_file)

    if user and not locked:
        lines.append(_env_line("GOV_USER", user))  # machine-wide installs log the signed-in OS user
    for key, value in sorted(extra.items()):
        lines.append(_env_line(key, value))

    env_path = os.path.join(gov_dir, "governance.env")
    with open(env_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    _restrict(env_path, private=not locked)
    legacy = os.path.join(gov_dir, "config.json")
    if os.path.exists(legacy):
        os.remove(legacy)  # superseded by governance.env; may contain a plaintext token
    if locked and SYSTEM != "Windows":
        os.chmod(hook, 0o755)
    print(f"  hook   -> {hook}")
    print(f"  config -> {env_path}{'  (locked)' if locked else ''}")
    return hook


# ------------------------------------------------------------ Claude Code
def claude_hook_block(python: str, hook: str) -> dict:
    def h(event: str, timeout: int) -> dict:
        return {"type": "command", "command": python,
                "args": [hook, "--agent", "claude", "--event", event],
                "timeout": timeout, "onFailure": "block", "statusMessage": "Governance check"}

    return {
        "UserPromptSubmit": [{"hooks": [h("prompt", TIMEOUTS["prompt"])]}],
        "PreToolUse": [{"matcher": "Read|Bash|mcp__.*", "hooks": [h("pretool", TIMEOUTS["tool"])]}],
        "PostToolUse": [{"matcher": "Bash|Grep|WebFetch|WebSearch|mcp__.*", "hooks": [h("posttool", TIMEOUTS["tool"])]}],
    }


def _is_ours(entry: dict) -> bool:
    return any("governance_hook.py" in " ".join([x.get("command", "")] + x.get("args", []))
               for x in entry.get("hooks", []))


def _has_our_hooks(path: str) -> bool:
    hooks = load_json(path).get("hooks", {}) if os.path.exists(path) else {}
    return any(_is_ours(e) for entries in hooks.values() for e in entries)


def install_claude(path: str, hook: str, python: str, scope: str, lock_hooks: bool, uninstall: bool) -> None:
    settings = load_json(path)
    hooks = settings.setdefault("hooks", {})
    for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
        hooks[event] = [e for e in hooks.get(event, []) if not _is_ours(e)]
    perms = settings.setdefault("permissions", {})
    perms["deny"] = [d for d in perms.get("deny", []) if d not in SECRET_READ_DENY]
    if not uninstall:
        for event, entries in claude_hook_block(python, hook).items():
            hooks[event].extend(entries)
        perms["deny"].extend(SECRET_READ_DENY)
        if scope == "managed":
            perms["disableBypassPermissionsMode"] = "disable"
            if lock_hooks:
                settings["allowManagedHooksOnly"] = True
    elif scope == "managed":
        settings.pop("allowManagedHooksOnly", None)
        perms.pop("disableBypassPermissionsMode", None)
    for event in list(hooks):
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        settings.pop("hooks")
    if not perms.get("deny"):
        perms.pop("deny", None)
    if not perms:
        settings.pop("permissions")
    save_json(path, settings)
    print(f"  Claude Code {scope} settings -> {path}")
    if scope == "managed" and not uninstall and _has_our_hooks(os.path.join(HOME, ".claude", "settings.json")):
        print("  WARNING: ~/.claude/settings.json also has ai-governance hooks; remove them with "
              "'install_hooks.py --agent claude --scope user --uninstall' to avoid double checks.")


# -------------------------------------------------------------------- Kiro
def kiro_command(python: str, hook: str, event: str, launcher: str | None) -> str:
    if launcher:  # Windows managed install
        return f"{launcher} {event}"
    q = (lambda s: f'"{s}"' if " " in s else s)
    return f"{q(python)} {q(hook)} --agent kiro --event {event}"


def kiro_hooks_file(python: str, hook: str, launcher: str | None = None) -> dict:
    def h(name: str, trigger: str, event: str, matcher: str | None = None, timeout: int | None = None) -> dict:
        d = {"name": f"{MARK}: {name}", "trigger": trigger,
             "action": {"type": "command", "command": kiro_command(python, hook, event, launcher)},
             "timeout": timeout or TIMEOUTS["tool"], "enabled": True}
        if matcher:
            d["matcher"] = matcher
        return d

    return {"version": "v1", "hooks": [
        h("scan prompt", "UserPromptSubmit", "prompt", timeout=TIMEOUTS["prompt"]),
        h("scan file reads", "PreToolUse", "pretool", "read"),
        h("scan shell commands", "PreToolUse", "pretool", "shell"),
        h("scan MCP tool inputs", "PreToolUse", "pretool", "@mcp"),
        h("audit shell output", "PostToolUse", "posttool", "shell"),
        h("audit MCP output", "PostToolUse", "posttool", "@mcp"),
    ]}


def _merge_kiroignore(path: str, uninstall: bool) -> None:
    existing = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    start = existing.find("# --- ai-governance")
    if start != -1:
        end = existing.find("# --- end ai-governance ---", start)
        end = len(existing) if end == -1 else end + len("# --- end ai-governance ---\n")
        existing = existing[:start] + existing[end:]
    if not uninstall:
        existing = (existing + ("\n" if existing and not existing.endswith("\n") else "") + KIROIGNORE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(existing)


def write_windows_launcher(launcher_dir: str, python: str, hook: str) -> str:
    os.makedirs(launcher_dir, exist_ok=True)
    path = os.path.join(launcher_dir, "kiro-hook.cmd")
    with open(path, "w", encoding="ascii", newline="\r\n") as fh:
        fh.write("@echo off\n")
        fh.write(f'"{python}" "{hook}" --agent kiro --event %1\n')
        fh.write("exit /b %ERRORLEVEL%\n")
    print(f"  Kiro launcher -> {path}")
    return path


def install_kiro_project(project: str, python: str, hook: str, uninstall: bool) -> None:
    hooks_path = os.path.join(project, ".kiro", "hooks", "ai-governance.json")
    if uninstall:
        if os.path.exists(hooks_path):
            os.remove(hooks_path)
        _merge_kiroignore(os.path.join(project, ".kiroignore"), True)
        print(f"  removed {hooks_path}")
        return
    save_json(hooks_path, kiro_hooks_file(python, hook))
    print(f"  Kiro workspace hooks -> {hooks_path}")
    for path in (os.path.join(project, ".kiroignore"), os.path.join(HOME, ".kiro", "settings", "kiroignore")):
        _merge_kiroignore(path, False)
        print(f"  kiroignore -> {path}")
    print("  NOTE: in Kiro IDE settings, set 'Agent Ignore Files' (kiroAgent.agentIgnoreFiles)")
    print("        to include \".kiroignore\" so the workspace file is enforced.")


def install_kiro_user(python: str, hook: str, gov_dir: str, uninstall: bool) -> None:
    """Global Kiro hooks for the current user: they apply to every workspace they open."""
    hooks_path = os.path.join(HOME, ".kiro", "hooks", "ai-governance.json")
    ignore_path = os.path.join(HOME, ".kiro", "settings", "kiroignore")
    if uninstall:
        if os.path.exists(hooks_path):
            os.remove(hooks_path)
        if os.path.exists(ignore_path):
            _merge_kiroignore(ignore_path, True)
        print(f"  removed {hooks_path}")
        return
    launcher = write_windows_launcher(gov_dir, python, hook) if SYSTEM == "Windows" else None
    save_json(hooks_path, kiro_hooks_file(python, hook, launcher))
    _merge_kiroignore(ignore_path, False)
    print(f"  Kiro global hooks (every workspace) -> {hooks_path}")
    print(f"  kiroignore -> {ignore_path}")
    print("  NOTE: global hooks need Kiro IDE 1.0.182 or later (1.2+ recommended).")


def install_kiro_policy(path: str, idc_start_url: str, idc_region: str, uninstall: bool) -> None:
    policy = load_json(path)
    rules = [r for r in policy.get("rules", []) if r not in KIRO_ADMIN_RULES]
    if not uninstall:
        rules.extend(KIRO_ADMIN_RULES)
        if idc_start_url:
            signin = {"capability": "signin_method", "match": ["*"], "exclude": ["idc"], "effect": "deny"}
            rules = [r for r in rules if r.get("capability") != "signin_method"] + [signin]
            settings = policy.setdefault("settings", {})
            settings["idc_start_url"] = idc_start_url
            if idc_region:
                settings["idc_region"] = idc_region
    for r in rules:  # Kiro rejects the whole file (and denies every tool) on unknown fields
        bad = set(r) - KIRO_RULE_FIELDS
        if bad or r.get("effect") not in ("deny", "ask"):
            sys.exit(f"Refusing to write Kiro policy: invalid rule {r}")
    if rules:
        policy["rules"] = rules
    else:
        policy.pop("rules", None)
    if uninstall and any(r.get("capability") == "signin_method" for r in rules):
        print("  NOTE: the IAM Identity Center sign-in restriction was left in place on purpose;")
        print(f"        delete the signin_method rule and 'settings' from {path} to remove it.")
    save_json(path, policy)
    if SYSTEM != "Windows":
        os.chmod(path, 0o644)
    print(f"  Kiro admin policy -> {path}")


def install_kiro_managed(python: str, hook: str, homes: list[tuple[str, int, int]], policy_path: str,
                         idc_start_url: str, idc_region: str, launcher_dir: str, uninstall: bool) -> None:
    launcher = None
    if SYSTEM == "Windows" and not uninstall:
        launcher = write_windows_launcher(launcher_dir, python, hook)
    hooks_doc = kiro_hooks_file(python, hook, launcher)
    for home, uid, gid in homes:
        hooks_path = os.path.join(home, ".kiro", "hooks", "ai-governance.json")
        ignore_path = os.path.join(home, ".kiro", "settings", "kiroignore")
        if uninstall:
            if os.path.exists(hooks_path):
                os.remove(hooks_path)
            if os.path.exists(ignore_path):
                _merge_kiroignore(ignore_path, True)
            continue
        save_json(hooks_path, hooks_doc)
        _merge_kiroignore(ignore_path, False)
        for p in (hooks_path, ignore_path):
            chown_tree(p, home, uid, gid)
    print(f"  Kiro global hooks + kiroignore -> {len(homes)} profile(s): "
          + ", ".join(os.path.basename(h) or h for h, _, _ in homes))
    install_kiro_policy(policy_path, idc_start_url, idc_region, uninstall)


def update_gitignore(project: str) -> None:
    path = os.path.join(project, ".gitignore")
    existing = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    if ".governance-sanitized/" not in existing:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(("\n" if existing and not existing.endswith("\n") else "") + ".governance-sanitized/\n")


# -------------------------------------------------------------------- main
ALLOWED_EXTRA = {"GOV_TIMEOUT", "GOV_FAIL_MODE", "GOV_MAX_FILE_MB", "GOV_CA_BUNDLE", "GOV_DEVICE_ID",
                 "GOV_ID_TOKEN_COMMAND", "GOV_ID_TOKEN_TIMEOUT",
                 "GOV_SANITIZED_DIR", "GOV_HOOK_LOG", "GOV_JUSTIFY_MARKER", "GOV_ALLOW_INSECURE_HTTP"}


def resolve_install_config(args) -> tuple[str, str, dict[str, str]]:
    api_url = args.api_url.strip()
    if not api_url:
        sys.exit("The governance API URL is required: pass --api-url or set GOV_API_URL.")
    if args.token:
        print("  WARNING: --token exposes the token in process lists and shell history; "
              "prefer --token-file or the GOV_API_TOKEN environment variable.")
        token = args.token
    elif args.token_file:
        with open(os.path.expanduser(args.token_file), encoding="utf-8") as fh:
            token = fh.read().strip()
    elif os.getenv("GOV_API_TOKEN"):
        token = os.environ["GOV_API_TOKEN"]
    elif sys.stdin.isatty():
        import getpass
        token = getpass.getpass("Governance API token: ").strip()
    else:
        token = ""
    if not token:
        sys.exit("The governance API token is required: use --token-file or set GOV_API_TOKEN.")
    extra = {}
    items = list(args.set)
    if args.settings_file:
        with open(args.settings_file, encoding="utf-8") as fh:
            items += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    for item in items:
        key, _, value = item.partition("=")
        if key not in ALLOWED_EXTRA or not value:
            sys.exit(f"--set {item!r}: allowed keys are {', '.join(sorted(ALLOWED_EXTRA))}")
        extra[key] = value
    return api_url, token, extra


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", choices=["claude", "kiro", "both"], required=True)
    ap.add_argument("--project", default="", help="repository to protect (required for --scope project)")
    ap.add_argument("--scope", choices=["project", "user", "managed"], default="project")
    ap.add_argument("--api-url", default=os.getenv("GOV_API_URL", ""),
                    help="governance API URL (or set GOV_API_URL); required")
    ap.add_argument("--token-file", default=os.getenv("GOV_API_TOKEN_FILE", ""),
                    help="file holding the API token (preferred); or set GOV_API_TOKEN")
    ap.add_argument("--token", default="", help="API token on the command line (discouraged: visible in "
                    "process lists and shell history)")
    ap.add_argument("--token-store", choices=["auto", "keyring", "file", "inline"], default="auto",
                    help="where the hook reads the token: auto = OS credential store for a user install, "
                         "a token file for a machine-wide install")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="extra hook setting, e.g. --set GOV_TIMEOUT=5 --set GOV_CA_BUNDLE=/etc/ssl/corp-ca.pem")
    ap.add_argument("--settings-file", default="",
                    help="file of KEY=VALUE lines, applied like --set (used by the Intune packages)")
    ap.add_argument("--prompt-timeout", type=int, default=int(os.getenv("GOV_HOOK_PROMPT_TIMEOUT", "10")))
    ap.add_argument("--tool-timeout", type=int, default=int(os.getenv("GOV_HOOK_TOOL_TIMEOUT", "15")))
    ap.add_argument("--user", default="", help="identity to log, e.g. your Entra UPN (not used for managed)")
    ap.add_argument("--python", default=sys.executable,
                    help="interpreter the hooks run with; for managed scope use one every user can run")
    ap.add_argument("--lock-hooks", action="store_true",
                    help="Claude Code managed scope: set allowManagedHooksOnly (blocks user/project/plugin hooks)")
    ap.add_argument("--kiro-policy-path", default="", help="override Kiro's admin managed-settings.json path")
    ap.add_argument("--idc-start-url", default="", help="Kiro: allow only IAM Identity Center sign-in with this start URL")
    ap.add_argument("--idc-region", default="", help="Kiro: AWS Region of the Identity Center directory")
    ap.add_argument("--managed-root", default="", help=argparse.SUPPRESS)  # testing without admin rights
    ap.add_argument("--homes", nargs="*", help=argparse.SUPPRESS)          # testing: explicit profile list
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args()

    TIMEOUTS.update(prompt=args.prompt_timeout, tool=args.tool_timeout)
    do_claude = args.agent in ("claude", "both")
    do_kiro = args.agent in ("kiro", "both")
    project = os.path.abspath(args.project) if args.project else ""
    if args.scope == "project" and not (project and os.path.isdir(project)):
        print("--project <existing folder> is required for --scope project", file=sys.stderr)
        return 1

    managed = args.scope == "managed"
    gov_dir = managed_paths(args.managed_root)[0] if managed else os.path.join(HOME, ".ai-governance")
    hook = os.path.join(gov_dir, "governance_hook.py")
    claude_path = claude_settings_path(args.scope, project, args.managed_root) if do_claude else ""
    kiro_policy = kiro_policy_path(args.kiro_policy_path, args.managed_root) if (managed and do_kiro) else ""
    if managed and not args.managed_root:
        for p in filter(None, (os.path.join(gov_dir, "config.json"), claude_path, kiro_policy)):
            check_writable(p)

    print("Installing ai-governance hooks" if not args.uninstall else "Removing ai-governance hooks")
    if not args.uninstall:
        api_url, token, extra = resolve_install_config(args)
        hook = install_core(gov_dir, api_url, token, args.token_store, args.user, locked=managed, extra=extra)
        if project:
            update_gitignore(project)
    if do_claude:
        install_claude(claude_path, hook, args.python, args.scope, args.lock_hooks, args.uninstall)
    if do_kiro:
        if managed:
            install_kiro_managed(args.python, hook, user_homes(args.managed_root, args.homes), kiro_policy,
                                 args.idc_start_url, args.idc_region, windows_launcher_dir(args.managed_root),
                                 args.uninstall)
        elif args.scope == "user":
            install_kiro_user(args.python, hook, gov_dir, args.uninstall)
        else:
            install_kiro_project(project, args.python, hook, args.uninstall)
    if args.scope == "user" and not args.uninstall:
        print("  TIP: if you installed per-project hooks earlier, remove them to avoid double checks:")
        print("       install_hooks.py --agent both --scope project --project <repo> --uninstall")
    if args.uninstall and managed and os.path.isdir(gov_dir) and not (do_claude ^ do_kiro):
        shutil.rmtree(gov_dir, ignore_errors=True)
    print("Done. Fully quit and reopen VS Code / Kiro, then start a new chat session.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
