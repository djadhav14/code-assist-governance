# Fleet rollout through Microsoft Intune

*Version 1.0.0, 8 Nov 2026.*

One build produces an Intune package per platform. Each package installs the governance hooks **machine-wide** for Claude Code (VS Code extension and CLI), Kiro IDE, or both, for every user on the device, in a way users can't switch off. It runs the same installer as the per-user setup in [ide-hooks.md](ide-hooks.md), with `--scope managed`.

## 1. What gets enforced

| Layer | Claude Code | Kiro IDE | Can a developer change it? |
| --- | --- | --- | --- |
| Hook script and **locked** config | `/opt/ai-governance/` · `C:\Program Files\ai-governance\` | Same files | No: admin-only folder. `GOV_LOCKED=true` makes the hook ignore the user's environment variables |
| Hook registration | **Managed settings**: `/etc/claude-code/managed-settings.json` · `C:\Program Files\ClaudeCode\managed-settings.json` | **Global hooks in every profile**: `~/.kiro/hooks/ai-governance.json`, plus the template for new profiles (`/etc/skel`, `C:\Users\Default`) | Claude Code: no. Kiro: yes, so Intune re-applies them |
| Secrets files kept away from the agent | Managed `Read` deny rules; `disableBypassPermissionsMode` | **Admin permission policy** (`fs_read`/`fs_write` deny on `.env`, `*.pem`, `*.key`, `secrets/`, `customer-data/`, `pii/`) plus global `kiroignore` | Policy: no. kiroignore: re-applied |
| Other hooks | `--lock-hooks` sets `allowManagedHooksOnly`: user, project and plugin hooks don't run | — | No |
| Sign-in | — | Optional: admin policy allows only IAM Identity Center, with your start URL and Region | No |
| Identity (optional) | `GOV_ID_TOKEN_COMMAND` in the locked config: every call carries the user's Entra ID access token ([ide-hooks.md, section 5](ide-hooks.md#5-production-verified-user-identity)) | Same | No |

**Kiro hooks are the weaker layer.** They live in each user's profile, so a developer can disable one in the Agent Hooks panel. Intune puts them back:
- **Ubuntu:** the script re-applies everything every hour.
- **Windows:** detection fails if any profile's hook file is missing or set to `"enabled": false`, and Intune then reinstalls the app.

**Version requirements:**
- **Claude Code:** `onFailure: "block"` (fail closed when the hook itself fails) needs v2.1.295 or later.
- **Kiro IDE:** 1.0.182 or later for global hooks; **1.2 or later** recommended, because some 1.0.x builds send an empty prompt to hooks [5][6].
- **Kiro admin policy path:** Kiro documents the macOS path only (`/Library/Application Support/Kiro/managed-settings.json`) [3]. The installer defaults to `/etc/kiro/managed-settings.json` on Linux and `C:\Program Files\Kiro\managed-settings.json` on Windows. **These two are unconfirmed.** Check Kiro's *Permission policies* page, pass the real paths at build time if they differ, and verify with check 4 in section 6.

## 2. Build the packages

Once per release, on any machine with this repository and the API token:

```bash
python3 intune/build_intune_packages.py --agent both \
  --api-url https://governance.corp.internal --token-file /secure/path/gov_api_token \
  --idc-start-url https://<org>.awsapps.com/start --idc-region ap-south-1 \
  --kiro-policy-path-windows "C:\Program Files\Kiro\managed-settings.json" \
  --kiro-policy-path-linux /etc/kiro/managed-settings.json \
  --set GOV_TIMEOUT=5 \
  --set "GOV_ID_TOKEN_COMMAND=az account get-access-token --scope api://<application-client-id>/.default --query accessToken -o tsv"
```

| Option | Purpose |
| --- | --- |
| `--api-url` | Must be `https://` for fleet packages |
| `--token-file` | The API token; for AWS, read it from Secrets Manager into a file only you can read, and delete the file afterwards |
| `--agent claude` / `kiro` | One tool only |
| `--idc-*` | Restrict Kiro sign-in to IAM Identity Center; leave out to keep sign-in unchanged |
| `--set KEY=VALUE` (repeatable) | Extra settings in the locked config: `GOV_CA_BUNDLE` (private CA path on the device), `GOV_TIMEOUT`, `GOV_ID_TOKEN_COMMAND`, `GOV_ID_TOKEN_TIMEOUT`, … (same allow-list as the installer). Embedded base64-encoded, so values may contain spaces and quotes |

The build writes three outputs to `intune/out/`:
- `windows/`: the Win32 app source folder.
- `Detect-AIGovernance.ps1`: the detection script.
- `ai-governance-linux.sh`: the Ubuntu platform script, with the hook and installer embedded.

Each build gets a **version stamp**, a hash of the code and the options, so Intune redeploys whenever either changes.

**`intune/out/` contains the API token. Never commit it** (`.gitignore` excludes it). Microsoft also advises against putting sensitive information in Linux scripts [2]. Per-user identity (section 5 of [ide-hooks.md](ide-hooks.md)) makes the shared token a device credential rather than the only one.

If you set `GOV_CA_BUNDLE`, deploy the CA file to the same path on every device first. Use an Intune trusted-certificate profile, or include it in a script.

## 3. Windows: Win32 app (runs as System)

**Prerequisite: Python 3 for all users**, under `C:\Program Files\Python3*`. Deploy it as its own Intune app and add it as a **dependency**. If you use `GOV_ID_TOKEN_COMMAND`, deploy the Azure CLI too.

**Package it** on a Windows machine:

```powershell
IntuneWinAppUtil.exe -c intune\out\windows -s Install-AIGovernance.ps1 -o intune\out
```

**Create the app:** Apps → Windows → Add → *Windows app (Win32)*:

| Setting | Value |
| --- | --- |
| Install command | `%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AIGovernance.ps1` |
| Uninstall command | Same, with `.\Uninstall-AIGovernance.ps1` |
| Install behavior | **System** |
| Return codes | 0 = Success; 1 = Failed (Python not found); 2 = Failed |
| Detection | Custom script `intune\out\Detect-AIGovernance.ps1`; "Run as 32-bit process" = **No** |
| Dependencies | Your Python 3 app (and Azure CLI, if used) |
| Assignment | **Required**, developer device group |

Notes:
- **Why `Sysnative`.** The Intune Management Extension is a 32-bit process. Without `Sysnative`, the script runs as 32-bit PowerShell and may write to `Program Files (x86)`, where Claude Code doesn't look.
- **Kiro launcher.** Kiro hooks call `C:\ProgramData\ai-governance\kiro-hook.cmd <event>`, a path without spaces that works whether Kiro uses `cmd.exe` or PowerShell. The folder is admin-write, user-read.
- **Token handling.** The token reaches the installer through an environment variable of the install process only, never on a command line, and is removed afterwards.
- **Log:** `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ai-governance-install.log`.

## 4. Ubuntu: Linux platform script (runs as root)

Go to Devices → Manage devices → Scripts and remediations → Platform scripts → Add → **Linux** [2]. Upload `intune/out/ai-governance-linux.sh` with these settings:

| Setting | Value |
| --- | --- |
| Execution context | **Root** |
| Execution frequency | **Every 1 hour**: each run restores removed hooks and covers new users |
| Execution retries | 3 |

What the script does:
- **Re-applies everything on every run.** Running it again is safe.
- **Leaves Kiro its own folders.** Each user's `~/.kiro` files are owned by that user, so Kiro can still write its state there. The hook script and policies stay root-owned.
- **Log:** `/var/log/ai-governance-intune.log`. The token is never written to it.

## 5. Supporting Intune policies

1. **Remove local admin rights** from developer accounts, with an account protection or local users and groups policy. Without this, a developer can delete the managed files.
2. **Deploy Python 3** machine-wide on Windows; Ubuntu ships `python3`. Also deploy the Azure CLI and the CA certificate, if your build uses them.
3. **Kiro console** (enterprise profile): prompt logging and activity reports to S3, an MCP allow-list, and web tools as your policy requires.
4. **Network:** allow the AI endpoints only from managed devices (egress allow-list or proxy), so an unmanaged tool can't bypass the hooks.

## 6. Verify on a pilot device

| # | Check | Expected |
| --- | --- | --- |
| 1 | Intune device status | App or script **Installed** / **Succeeded** |
| 2 | Claude Code: quit and reopen VS Code, new session, `/hooks` | `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, labelled as managed |
| 3 | Kiro: reopen, open any folder, Agent Hooks panel | Six `ai-governance:` hooks, enabled |
| 4 | Kiro: ask the agent to read a `.env` file | Denied, rule source **administration**. If not, the Kiro policy path is wrong: rebuild with `--kiro-policy-path-*` |
| 5 | Kiro sign-in screen (with `--idc-*`) | Only your organization (IAM Identity Center) |
| 6 | Prompt `Borrower mobile +91 98765 43210 gets no SMS` in both IDEs | Blocked; Claude Code shows the redacted version to resend |
| 7 | Stop the server (or block its address) and send any prompt | Blocked, fail closed |
| 8 | Claude Code: add `"disableAllHooks": true` to `~/.claude/settings.json`, retry 6 | Still blocked: user settings can't disable managed hooks |
| 9 | Audit log / SIEM | One `governance.decision` per check with `host_name`, and `user_verified: true` if identity is on |

Synthetic test files and prompts: `python3 tests/make_samples.py <folder>`.

## 7. Change or rotate

| Change | What to do |
| --- | --- |
| `policy.yaml`, `recognizers.json` | Server-side only; no new packages ([detection-rules.md](detection-rules.md)) |
| New hook code (new release) | Rebuild, upload the new Win32 package and Linux script; the version stamp changes, so Intune redeploys |
| **Rotate the API token** | 1. In the secret, set the new `GOV_API_TOKEN` and keep the old value as `GOV_API_TOKEN_PREVIOUS`; restart the server, which now accepts both ([detection-api.md, 4.7](detection-api.md#47-rotate-the-secret)). 2. Rebuild the packages with the new token and redeploy. 3. Once Intune reports every device updated, remove `GOV_API_TOKEN_PREVIOUS` and restart. No device is locked out at any point |
| New server address, CA, or identity command | Rebuild with the new `--api-url` / `--set`, redeploy |

## 8. Manual machine-wide install (pilot or troubleshooting)

The same installer Intune runs, run as admin on one machine:

```bash
# Ubuntu (root)
sudo GOV_API_TOKEN="$(cat /secure/path/gov_api_token)" python3 clients/install_hooks.py --agent both --scope managed \
     --api-url https://governance.corp.internal --token-store file --python /usr/bin/python3 --lock-hooks \
     --idc-start-url https://<org>.awsapps.com/start --idc-region ap-south-1
```
```powershell
# Windows (Administrator PowerShell)
$env:GOV_API_TOKEN = Get-Content C:\secure\gov_api_token
python clients\install_hooks.py --agent both --scope managed `
       --api-url https://governance.corp.internal --token-store file `
       --python "C:\Program Files\Python312\python.exe" --lock-hooks
Remove-Item Env:\GOV_API_TOKEN
```

Remove with `--scope managed --uninstall`. Uninstall keeps the Kiro IAM Identity Center sign-in restriction on purpose, and prints how to remove it.

## 9. Limits

| Limit | Impact | Mitigation |
| --- | --- | --- |
| Hooks can't rewrite prompts (both IDEs) | Prompts with maskable data are blocked; the user resends the redacted text | Later phase: an LLM gateway that rewrites requests in flight |
| Images pasted into a Claude Code prompt don't reach the hook | Not scanned | Gateway phase; image files the agent *reads* are OCR-scanned |
| Kiro can't rewrite reads or tool output | Mask and pseudonymize become block with a redacted copy; tool output is audit-only | Accepted |
| Kiro hooks live in user profiles | Can be disabled until the next re-apply | Hourly re-apply (Ubuntu), detection-driven reinstall (Windows), SIEM alert on Kiro activity without governance events |
| Client-side enforcement | Local admins can bypass it | Remove local admin; egress allow-list |
| Shared API token on devices | Readable by signed-in users | `token+oidc` identity; rotate the token |
| Other assistants in VS Code (e.g. Copilot) | Not covered | Extension allow-list, network policy |

**Testing status:**
- **Linux script:** the build and the generated script were run as root on Ubuntu. Extra settings reached the locked config exactly, re-runs were idempotent, uninstall cleaned up, and the token stayed out of the log.
- **Windows scripts:** generated from the same templates, but not executed in the build environment (no PowerShell there). Run them on a pilot device before assigning to the group.

## Sources

1. [Claude Code settings and managed settings](https://code.claude.com/docs/en/settings) and [hooks reference](https://code.claude.com/docs/en/hooks)
2. [Intune: custom Bash scripts for Linux](https://learn.microsoft.com/mem/intune/configuration/custom-settings-linux)
3. [Kiro admin permission policies](https://kiro.dev/docs/enterprise/governance/permissions/) and [sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/)
4. [Kiro hooks](https://kiro.dev/docs/hooks/), [.kiroignore](https://kiro.dev/docs/kiroignore/)
5. [Kiro IDE global hooks, v1.0.182 (Classmethod)](https://dev.classmethod.jp/articles/kiro-ide-10182-global-hooks/)
6. [Kiro IDE hook payload reference (AWS Labs)](https://awslabs.github.io/aidlc-workflows/reference/kiro-ide-hook-payload/)
7. [Intune Win32 custom detection rules](https://petervanderwoude.nl/post/working-with-custom-detection-rules-for-win32-apps/)
