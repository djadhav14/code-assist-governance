# Changelog

Check your version with `cat VERSION` (PowerShell: `Get-Content VERSION`). Run `python scripts/doctor.py` to confirm the download is complete.

## 1.0.0 (8 Nov 2026)
First public release. Consolidates everything below, plus:
- **Verified user identity** (`GOV_AUTH_MODE=token+oidc` / `oidc`):
  - The server verifies an Entra ID (or other OIDC) access token on every call: signature via the tenant's JWKS, exact issuer, audience and expiry. `HS*`/`none` and non-HTTPS key URLs are refused.
  - The verified account drives per-user overrides and the audit `user_id`. The desktop user is kept as `user_claimed`, and a mismatch is logged (Wazuh 100160) or refused (`GOV_IDENTITY_MISMATCH=block`, 100161).
  - The hook fetches the token with `GOV_ID_TOKEN_COMMAND` (e.g. Azure CLI) and caches it until shortly before expiry.
- **AWS Secrets Manager** (`GOV_AWS_SECRET_ID`): secrets come from one JSON secret, through the instance or task role. Mixing sources is refused, and long-term IAM user keys are flagged.
- **Token rotation without lockout:** `GOV_API_TOKEN_PREVIOUS` is accepted during a rotation.
- **Fixed:** a bad `policy.yaml` edit made every request fail with HTTP 500, so the hooks blocked everything. The previous policy now stays in force, `/healthz` reports `policy_last_error`, and `governance.policy_rejected` is logged (Wazuh 100153).
- **Intune:** `build_intune_packages.py --set KEY=VALUE` adds locked hook settings (identity command, CA bundle, timeouts), embedded base64-encoded.
- **AWS deployment files** in `deploy/aws/`:
  - an EC2 test-server compose with Caddy TLS;
  - a least-privilege IAM policy;
  - an ECS Fargate task-definition template.
- **Tests:** they now trust `GOV_CA_BUNDLE` and send a bearer token, so they run against a remote TLS server. New suites: `test_identity.py`, `test_aws_secrets.py`, `test_policy.py`. `scripts/ci.sh` and a GitHub Actions workflow run everything.
- **Docs consolidated:**
  - Main guides: `docs/detection-api.md`, `docs/ide-hooks.md`, `docs/intune.md`, `docs/debugging.md`, and a new README.
  - Replaced: `docs/ide-setup.md` and `intune/README-intune.md`, which `doctor.py` now flags as leftovers.
- **Repository files:** `LICENSE` (MIT) and `SECURITY.md`.

## 0.7.3 (8 Nov 2026)
- `install_hooks.py --scope user` now covers Kiro too: global hooks in `~/.kiro/hooks/` and `~/.kiro/settings/kiroignore`, for every workspace (Kiro IDE 1.0.182+). With Claude Code (`~/.claude/settings.json`, shared by the CLI and the VS Code extension), one command now covers every project for the signed-in user, with no admin rights.
- README step 6 is now the per-user install; per-project becomes optional step 7. New mode A2 in `docs/ide-setup.md`.

## 0.7.2 (8 Nov 2026)
- Docs: the hook install commands (README steps 6 and 7, `docs/ide-setup.md`) take `--user` from the desktop sign-in name (`$USER` on Ubuntu/macOS, `$env:USERNAME` on Windows) instead of a typed e-mail address, with Windows PowerShell versions and other identity formats.

## 0.7.1 (8 Nov 2026)
- `doctor.py` warns about files left over from older versions. Unzipping 0.7.0 over an older folder kept the removed `detection_api/app/recognizers.py`; the server never imports it, but it suggested the patterns still came from code.
- `tests/test_rules.py` fails if any server module imports `recognizers.py`.

## 0.7.0 (8 Nov 2026)
- **Detection rules moved out of code** into `detection_api/rules/recognizers.json`, a versioned file (`version`, `updated_by`, `change_note`) with test samples for every recognizer. Exported from the old `recognizers.py` unchanged: same 9 recognizers, 21 patterns, scores, context words and regex flags (verified). `app/recognizers.py` is removed.
- **Hot reload with checks:** the server validates a changed file (structure, regex compiles, a speed test against catastrophic backtracking, the file's own test samples, a new version for new content), builds and warms up a new analyzer, then swaps it in without a restart. A rejected file leaves the previous version in force; an invalid file at start-up stops the server (fail closed).
- **Audit trail:** every decision now records `rules_version`, `policy_version`, and the recognizer and pattern behind each finding. New events `governance.rules_loaded` (with what was added, removed or changed) and `governance.rules_rejected`. Each accepted version is archived in `logs/rules-archive/`.
- New `GET /v1/rules`; `/healthz` shows the rules version. New Wazuh rules 100150–100152.
- New `scripts/validate_rules.py` (for pre-commit or CI), `tests/test_rules.py`, `docs/detection-rules.md`. `doctor.py` validates the rules file.
- Docker: the rules folder is mounted read-only (`GOV_RULES_DIR`), as a folder, so editor saves are always seen.

## 0.6.3 (8 Nov 2026)
- Fixed: the Docker build failed when GitHub returned "504 Gateway Time-out" while downloading the spaCy model. The model download now retries up to 5 times, and pip uses longer timeouts and 10 retries.
- Python packages are installed in their own cached layer, so a failed model download no longer re-downloads every package on the next build.
- New offline option: put the model wheel in `detection_api/models/` (see the README there) and the build installs it without any download.

## 0.6.2 (8 Nov 2026)
- Corrected diagnosis of the 0.6.1 fix. The "claude prompt with justification" failure in `tests/test_hooks.py` was **HTTP 500 from a PermissionError**, not a slow download. Since 0.6.0 the server container runs as your uid, but the image built tldextract's cache in `/app/.tldextract` as uid 10001. Presidio's email check opened that cache's lock file for writing and failed, so every request containing an email address errored. The 0.6.1 change (cache off, bundled list) already avoids the lock file; this release removes the leftover build-time cache and `TLDEXTRACT_CACHE` from the Dockerfile.
- New `tests/test_offline_suffix.py`: checks the server never opens the tldextract cache, even when the cache folder is read-only.

## 0.6.1 (8 Nov 2026)
- Fixed: requests containing an email address could fail inside Presidio's email check (tldextract cache). The server now uses the public-suffix list bundled with the library with its disk cache off. (The cause is described correctly under 0.6.2.)
- The server warms up every recognizer at start-up, so the first real request is as fast as later ones; `/healthz` answers only when it is ready.
- The hook now names the actual cause when a check fails: no answer within N seconds, HTTP 500 or 401 from the server, nothing listening at the address, or misconfiguration. It no longer reports everything as "unreachable".

## 0.6.0 (8 Nov 2026)
- **Wazuh integration** (`siem/wazuh/`): custom rules (IDs 100100–100140; blocks, redactions, justifications, overrides, repeated attempts), a setup script that connects a wazuh-docker single-node stack without editing Wazuh's own files, an end-to-end check script, sample events and a guide sized for 12 GB laptops.
- Server writes a flat JSON audit file (`GOV_AUDIT_FILE`, default `logs/governance-decisions.jsonl`), one decision per line, for Wazuh and other log shippers. OpenTelemetry output is unchanged.
- Fixed: a user's free-text justification was logged as typed and could contain PII. It is now scanned and masked before it reaches any log.
- The server container runs as your user (like the collector) so it can write into `logs/`.

## 0.5.1 (8 Nov 2026)
- Fixed: unzipping a new version over an old folder kept the old `.env`, which lacks `GOV_API_URL` and still holds the token, so `tests/test_api.py` stopped with "Set GOV_API_URL and GOV_API_TOKEN". `init_secrets.py` now upgrades an existing `.env`: it adds missing settings and removes secrets that now live in `secrets/`.
- `doctor.py` flags secrets left in `.env`; the tests name exactly which setting is missing.

## 0.5.0 (8 Nov 2026)
- Added `scripts/doctor.py`: checks package completeness, configuration, Docker and the running server, and explains how to fix each failure.
- Fixed: on Linux, the OTel Collector container could not write `logs/` (permission denied). `init_secrets.py` now records your user ID in `.env` and Compose runs the collector as that user.
- README rewritten: prerequisites, a single ordered quick start, a no-Docker route, troubleshooting, and a complete file list.
- Added `VERSION` and this changelog; the zip file name now carries the version.

## 0.4.0 (30 Oct 2026)
- No hard-coded server address, port or secret anywhere. Settings come from environment variables, `.env`, or secret files.
- Added `scripts/init_secrets.py` (creates `.env` and random secrets in `secrets/`) and `docs/configuration.md`.
- Server refuses to start without `GOV_API_TOKEN` and `GOV_HASH_KEY`; constant-time token check; `python -m app.serve` entry point.
- Docker Compose mounts secrets as Docker secrets. Hook config moved to `governance.env`; token kept in the OS credential store or an owner-only file.

## 0.3.0 (29 Oct 2026)
- Intune packages enforce the hooks machine-wide for Kiro IDE as well as Claude Code. Added `docs/ide-setup.md` and `docs/architecture.md`.

## 0.2.0 (29 Oct 2026)
- Machine-wide Claude Code install (`--scope managed`) and first Intune packages.

## 0.1.0 (27 Oct 2026)
- Detection API (Presidio + India recognizers + secrets + OCR), hook script for Claude Code and Kiro, installer and tests.
