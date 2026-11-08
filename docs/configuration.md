# Configuration and secret storage

*Version 1.0.0, 8 Nov 2026.*

Nothing environment-specific is hard-coded. Every address, port, secret and tuning value comes from **environment variables**, an **`.env`-style file**, or a **secret file**. Two values are secrets, and neither has a default; the code refuses to run without them:

| Secret | Used by | Purpose |
| --- | --- | --- |
| `GOV_API_TOKEN` | Server and every hook client | Authenticates hook calls to the API |
| `GOV_HASH_KEY` | Server only | HMAC key for value fingerprints and pseudonym tokens. Must never leave the server |

## 1. Where each component reads its settings

| Component | Resolution order (highest first) |
| --- | --- |
| **Server** (`detection_api/app/settings.py`) | 1. Environment variables · 2. `NAME_FILE` secret files (e.g. `GOV_API_TOKEN_FILE=/run/secrets/gov_api_token`) · 3. `.env` file (`GOV_ENV_FILE`, else `./.env`); it never overrides real environment variables · 4. Defaults for non-secret tuning only. **Or**, for the secrets, AWS Secrets Manager (`GOV_AWS_SECRET_ID`), which excludes the other secret sources |
| **Hook** (`clients/governance_hook.py`) | 1. **Locked** `governance.env` next to the script (`GOV_LOCKED=true`; machine-wide installs) · 2. Environment variables · 3. `GOV_ENV_FILE`, else `governance.env` next to the script, else `~/.ai-governance/governance.env` · 4. Legacy `config.json` (read for backward compatibility) |
| **Installer** (`clients/install_hooks.py`) | `--api-url` or `GOV_API_URL`. Token: `--token-file`, then `GOV_API_TOKEN`, then an interactive prompt. `--token` works but prints a warning |
| **Intune build** (`intune/build_intune_packages.py`) | `--api-url` or `GOV_API_URL`; token from `--token-file` or `GOV_API_TOKEN`. Refuses `http://` to remote hosts |
| **Tests** (`tests/_config.py`) | Environment variables, then the repo `.env` and `secrets/` |
| **Docker Compose** | `.env` for non-secret values; `./secrets/*` mounted as Docker secrets |

## 2. Settings reference

### Server

| Variable | Default | Notes |
| --- | --- | --- |
| `GOV_API_TOKEN` / `GOV_API_TOKEN_FILE` | **required** (16+ chars) | Compared in constant time |
| `GOV_HASH_KEY` / `GOV_HASH_KEY_FILE` | **required** (16+ chars) | Rotating it breaks correlation with older audit events |
| `GOV_API_TOKEN_PREVIOUS` / `_FILE` | unset | Old token, still accepted during a rotation; logs a warning while set |
| `GOV_AWS_SECRET_ID` / `GOV_AWS_REGION` | unset | Read the secrets from one Secrets Manager secret (JSON with `GOV_API_TOKEN`, `GOV_HASH_KEY`, optional `GOV_API_TOKEN_PREVIOUS`), using the instance or task role. See `docs/detection-api.md` |
| `GOV_AUTH_MODE` | `token` | `token`, `token+oidc` or `oidc`. See `docs/ide-hooks.md`, section 5 |
| `GOV_OIDC_ISSUER` / `GOV_OIDC_AUDIENCE` / `GOV_OIDC_JWKS_URL` | — | Required with `*oidc`; JWKS URL must be `https://` |
| `GOV_OIDC_USER_CLAIMS` / `GOV_OIDC_ID_CLAIMS` / `GOV_OIDC_ALGORITHMS` | `preferred_username,upn,unique_name,email` / `oid,sub` / `RS256` | |
| `GOV_IDENTITY_MISMATCH` | `log` | `block` refuses (403) a desktop user that isn't the signed-in account |
| `GOV_AUTH_DISABLED` | `false` | Local development only; logs a warning at start-up |
| `GOV_HOST` / `GOV_PORT` / `GOV_WORKERS` | `127.0.0.1` / `8088` / `2` | The image sets `GOV_HOST=0.0.0.0` inside the container |
| `GOV_LOG_LEVEL` | `info` | |
| `GOV_POLICY_PATH` | `policy.yaml` beside the app | |
| `GOV_RECOGNIZERS_PATH` | `rules/recognizers.json` beside the app | Detection rules; see `docs/detection-rules.md`. Docker: `/app/rules/recognizers.json` |
| `GOV_RULES_ARCHIVE_DIR` | unset (`.env.example`: `./logs/rules-archive`; Docker: always that folder) | Copy of every rules version the server accepted. Unset: no archive, and no check against reusing old version numbers across restarts |
| `GOV_NLP_MODEL` | `en_core_web_lg` | Also a Docker build argument |
| `GOV_CHUNK_CHARS` / `GOV_MAX_TEXT_CHARS` / `GOV_MAX_PDF_OCR_PAGES` / `GOV_CACHE_SIZE` | 100000 / 2000000 / 10 / 4096 | |
| `GOV_AUDIT_FILE` | unset (`.env.example`: `./logs/governance-decisions.jsonl`; Docker: always that file) | Flat JSON audit file, one decision per line, for Wazuh. Relative paths resolve against `.env` |
| `GOV_ENVIRONMENT` / `OTEL_SERVICE_NAME` / `OTEL_EXPORTER_OTLP_ENDPOINT` | `local` / `ai-governance-detection` / unset | OTLP export is on only when the endpoint is set |
| `GOV_ENV_FILE` | `./.env` if present | Relative `*_FILE` paths resolve against this file's folder |

### Docker Compose (`.env`)

| Variable | Default | Notes |
| --- | --- | --- |
| `GOV_BIND_ADDRESS` / `GOV_PUBLISH_PORT` | `127.0.0.1` / `8088` | Host address and port the API is published on |
| `GOV_SECRETS_DIR` | `./secrets` | Holds `gov_api_token` and `gov_hash_key` |
| `GOV_POLICY_FILE` / `GOV_EVENT_LOG_DIR` | `./detection_api/policy.yaml` / `./logs` | |
| `GOV_RULES_DIR` | `./detection_api/rules` | Folder with `recognizers.json`, mounted read-only |
| `GOV_IMAGE_TAG` / `OTEL_COLLECTOR_TAG` | `local` / `latest` | Pin the collector tag in production |

### Hook client

| Variable | Default | Notes |
| --- | --- | --- |
| `GOV_API_URL` | **required** | Must be `https://` unless the host is loopback |
| `GOV_API_TOKEN` / `GOV_API_TOKEN_FILE` / `GOV_TOKEN_SOURCE=keyring` | **one required** | See section 3 |
| `GOV_CA_BUNDLE` | system trust store | PEM file of your internal CA, if the API certificate is internal |
| `GOV_ALLOW_INSECURE_HTTP` | `false` | Allows `http://` to a remote host. Testing only |
| `GOV_TIMEOUT` / `GOV_FAIL_MODE` / `GOV_MAX_FILE_MB` | `3` / `closed` / `10` | |
| `GOV_USER` / `GOV_DEVICE_ID` | OS user / empty | Identity fields for the audit log (self-reported; logged as `user_claimed` when identity is verified) |
| `GOV_ID_TOKEN_COMMAND` / `GOV_ID_TOKEN_TIMEOUT` | unset / `8` | Command printing the user's access token for `token+oidc` servers, e.g. `az account get-access-token --scope api://<id>/.default --query accessToken -o tsv`; cached in `~/.ai-governance/id_token.cache` (0600) until 2 minutes before expiry |
| `GOV_SANITIZED_DIR` / `GOV_HOOK_LOG` / `GOV_JUSTIFY_MARKER` | `<cwd>/.governance-sanitized` / off / `#justify:` | |
| `GOV_LOCKED` | — | Set only inside the admin-only file by machine-wide installs |

### Installer

`--prompt-timeout` and `--tool-timeout` set the IDE hook timeouts, defaulting to 10 s and 15 s; they can also come from `GOV_HOOK_PROMPT_TIMEOUT` and `GOV_HOOK_TOOL_TIMEOUT`. Use `--set KEY=VALUE` to add any allowed hook setting, e.g. `--set GOV_CA_BUNDLE=/etc/ssl/corp-ca.pem`.

## 3. Recommended secure storage

### Server secrets

| Environment | Recommendation | Why |
| --- | --- | --- |
| **Laptop / Docker Compose** | `python scripts/init_secrets.py` creates random secrets in `./secrets/`. Compose mounts them at `/run/secrets/` and points `GOV_*_FILE` at them | Secrets never appear in `docker inspect`, environment listings, image layers or `.env`. The `secrets/` folder is `0700` (owner-only); the files are `0644` only so the container's non-root user can read the bind mount |
| **AWS test server (EC2)** | AWS **Secrets Manager** via `GOV_AWS_SECRET_ID`, read with the **instance profile** role (`deploy/aws/iam-policy-read-secret.json`) | No secrets on disk, no IAM user keys, CloudTrail records every read |
| **AWS production (ECS Fargate)** | Secrets Manager via `GOV_AWS_SECRET_ID` and the **task role**, or the task definition's `secrets` injection | Same, plus rotation without redeploying images |
| **Oracle Cloud** | OCI **Vault** secrets, read at start-up into `GOV_*_FILE` paths | Same properties as Secrets Manager |

Never commit `.env`, `secrets/` or `intune/out/`; `.gitignore` excludes all three. `.env` holds only non-secret settings.

### Hook client token on developer laptops

The token is a **client credential**: anything the hook can read, the signed-in user can read too, because the hook runs as that user. No local storage method changes that. Storage choices therefore aim to keep the token **out of shell history, process lists, repositories, backups and other users' reach**, while the real control is the server side (TLS, network restrictions, rotation, and per-user identity later).

| Install type | Storage (installer default) | Protection |
| --- | --- | --- |
| **Per user** (`--scope project` or `user`) | **OS credential store** via the optional `keyring` package: Windows Credential Manager (DPAPI, tied to the user's login), macOS Keychain, or Linux Secret Service. `governance.env` contains only `GOV_TOKEN_SOURCE=keyring` | Encrypted at rest under the user's login; unreadable by other users or from a copied disk |
| Per user, no `keyring` package | `~/.ai-governance/api_token`, mode `0600`, in a `0700` folder | Owner-only file; not in any repository |
| **Machine-wide** (`--scope managed`, Intune) | `/opt/ai-governance/api_token` or `C:\Program Files\ai-governance\api_token`; root/Administrators write, users read | Users can't change or redirect it (locked config); it can't sit in one user's keyring because Intune installs as SYSTEM/root |

How the token travels at install time:
- **Never on the command line.** Intune scripts pass it through an environment variable of the install process only, and remove it afterwards. Command lines are visible to other processes and in logs; verified, the token doesn't appear in the Intune install log.
- **Building packages:** use `--token-file secrets/gov_api_token` or `GOV_API_TOKEN`, not `--token`.

Install the optional package for credential-store support (per-user installs):

```bash
python -m pip install keyring        # on Linux also needs a Secret Service, e.g. GNOME Keyring
```

### Hardening, in order of value

1. **Use TLS.** Use `https://` for any non-loopback API URL; the hook refuses plain `http://` to remote hosts. Point `GOV_CA_BUNDLE` at your internal CA if needed.
2. **Restrict the network.** Only managed devices should reach the API: private ALB, VPN or ZTNA, security groups.
3. **Rotate the API token** with `scripts/init_secrets.py --rotate`, or Secrets Manager rotation, and rebuild and redeploy the Intune packages. The version stamp changes, so Intune pushes the new token.
4. **Turn on per-user identity** (`GOV_AUTH_MODE=token+oidc`, built in since 1.0.0). Entra ID access tokens are validated by the API, so the shared token is no longer the only credential, and the audit `user_id` is verified rather than self-reported.
5. **Keep `GOV_HASH_KEY` server-only.** Holding it allows fingerprints to be tested against guessed values, so access to it should be limited to the SOC lead.

## 4. Quick start

```bash
python scripts/init_secrets.py                 # .env + secrets/ with random values
docker compose up -d --build                   # server: reads .env and Docker secrets
python tests/test_api.py && python tests/test_hooks.py

# Hooks for one repo, token kept in the OS credential store (or a 0600 file):
GOV_API_URL=http://127.0.0.1:8088 \
python clients/install_hooks.py --agent both --scope project --project ~/my-repo \
       --token-file secrets/gov_api_token

# Run the server without Docker (reads ../.env and the secret files):
cd detection_api && GOV_ENV_FILE=../.env python -m app.serve
```
