# Debugging guide

*Version 1.0.0, 8 Nov 2026.* Most entries below are problems met while building and testing this project, with the cause and the fix that worked.

## 1. First five minutes

```bash
cat VERSION                                   # which build is this?
python3 scripts/doctor.py                     # package, leftover files, config, rules file, Docker, server, token
curl -s http://127.0.0.1:8088/healthz | python3 -m json.tool      # versions, auth mode, secrets source
docker compose logs --tail 60 detection-api   # the server's own error, with traceback
tail -3 logs/governance-decisions.jsonl       # the last decisions (flat audit file)
```

**The block message names the cause.** When a hook blocks because of a problem rather than a policy, the reason says which (section 3). The server log says why.

**Run a hook by hand.** This takes the IDE out of the picture:

```bash
echo '{"hook_event_name":"UserPromptSubmit","prompt":"Borrower PAN ABCPE1234F","session_id":"debug","cwd":"/tmp"}' \
  | python3 ~/.ai-governance/governance_hook.py --agent claude --event prompt
# Machine-wide installs: /opt/ai-governance/governance_hook.py (Windows: C:\Program Files\ai-governance\...)
```

**Hook debug log.** Add `GOV_HOOK_LOG=/tmp/gov-hook.log` to `~/.ai-governance/governance.env` (or `--set GOV_HOOK_LOG=…` at install), reproduce the problem, and read the file. Remove the setting afterwards.

---

## 2. Server won't start or build

| Symptom | Cause | Fix |
| --- | --- | --- |
| `failed to connect to the docker API at unix:///home/<you>/.docker/desktop/docker.sock` | The `docker` CLI points at Docker Desktop, which isn't running | Start it (`systemctl --user start docker-desktop`), or use Docker Engine: `docker context use default && sudo systemctl start docker`. Check with `docker context ls`; `unset DOCKER_HOST` |
| Build fails: `504 Gateway Time-out` for `en_core_web_*.whl` | GitHub's download servers busy | Rebuild (the build retries 5 times), or download the wheel once into `detection_api/models/` with `curl -fL -C - --retry 20 --retry-all-errors -O <url>` ([models/README.md](../detection_api/models/README.md)) |
| `Configuration error: GOV_API_TOKEN … is not set` / `GOV_HASH_KEY … is not set` | No secrets | `python3 scripts/init_secrets.py` |
| Tests say `Not configured: GOV_API_URL` | `.env` from an older version | `python3 scripts/init_secrets.py`: upgrades `.env` in place, keeps the secrets |
| `Detection rules rejected, server not started` | `rules/recognizers.json` invalid | `python3 scripts/validate_rules.py` lists each problem |
| `GOV_AWS_SECRET_ID is set, so remove GOV_API_TOKEN_FILE …` | Secrets from two places; often a local `.env` on the test server | Use one source; on AWS, don't use `.env` / `secrets/` |
| `Cannot read AWS Secrets Manager secret … Unable to locate credentials` | The container can't reach the instance role | IMDSv2 hop limit 2 ([detection-api.md, 4.3](detection-api.md#43-let-containers-reach-the-instance-role-imdsv2-hop-limit)); check that the instance has the profile |
| `… AccessDeniedException` | Role can't read that secret, or can't use its KMS key | Check the ARN pattern in `iam-policy-read-secret.json` (secret ARNs end in `-` + 6 characters) and the KMS statement |
| `… must be a JSON object with GOV_API_TOKEN and GOV_HASH_KEY` | Secret stored as plain text | Store `{"GOV_API_TOKEN": "...", "GOV_HASH_KEY": "..."}` |
| Warning `AWS credentials are long-term IAM user keys` | `AWS_ACCESS_KEY_ID` starting `AKIA` in the environment | Remove the keys; use the instance profile or task role |
| `GOV_OIDC_… is required` / `GOV_OIDC_JWKS_URL must be https://` | Incomplete identity settings | [ide-hooks.md, 5.4](ide-hooks.md#54-configure-the-server) |
| `address already in use` on 8088 | Another server (often an older folder's container) | `docker ps`; stop it. Without Docker: `fuser -k 8088/tcp` (Linux) |
| `doctor.py` warns about leftover files | Unzipping a new version over an old folder keeps removed files | Delete the files it lists. They are unused, but misleading |
| Server answers, but behaves like an old version | Image not rebuilt, or a container from another folder still running | `cat VERSION`; `docker compose build --no-cache detection-api && docker compose up -d --force-recreate` |

---

## 3. Hooks cannot reach the server

Hooks **fail closed**: any problem blocks the prompt or tool call, with this message:

`Governance: the data-protection check failed: <cause>, so this action is blocked (fail-closed).`

The cause is one of these:

| Cause in the message | Meaning | Fix |
| --- | --- | --- |
| `nothing is listening at http://…` | Server not running, or wrong port | Start it; check `GOV_API_URL` in `governance.env` |
| `no answer from … within 3 s (GOV_TIMEOUT)` | Server slow or network latency | `docker compose logs`; raise with `--set GOV_TIMEOUT=5` |
| `the server returned HTTP 401 (token rejected …)` | Hook and server tokens differ | Re-run the installer with the current token; after a rotation, see [intune.md, 7](intune.md#7-change-or-rotate) |
| `the server returned HTTP 401 (user access token …)` | Identity mode: token missing, expired, wrong audience or issuer | Section 6 |
| `the server returned HTTP 403 (desktop user … does not match …)` | `GOV_IDENTITY_MISMATCH=block` | Section 6 |
| `the server returned HTTP 500 (server error …)` | Exception in the server | `docker compose logs --tail 60 detection-api` shows the traceback |
| `cannot reach https://…: CERTIFICATE_VERIFY_FAILED unable to get local issuer certificate` | Server certificate from a private CA the laptop doesn't trust | `--set GOV_CA_BUNDLE=/path/ca.pem` ([detection-api.md, 4.5](detection-api.md#45-tls-certificate-for-developers)) |
| `… CERTIFICATE_VERIFY_FAILED … Missing Authority Key Identifier` | Python 3.13+ checks certificates strictly; the certificate lacks standard fields | Reissue the certificate with a current CA (Caddy's are fine) |
| `could not get your sign-in token (sign in again, e.g. 'az login')` | `GOV_ID_TOKEN_COMMAND` failed | Run the command yourself; `az login` |
| `the governance hook is misconfigured: GOV_API_URL is not configured` | Hook installed without `--api-url` | Re-run the installer with `--api-url` and the token |
| `… misconfigured: GOV_API_URL uses http:// to a remote host` | Plain HTTP to a non-loopback address | Use `https://` |

**Real example (fixed in 0.6.1).** "Unreachable" was once reported for what was really an HTTP 500. The server log showed `PermissionError: … /app/.tldextract/…lock`. The container ran as a different user from the one that built a cache inside the image. Since 0.6.1 the email check uses its bundled data with no cache, and since 0.6.0 the hooks name the real cause. So when a message seems to contradict the server log, believe the log.

---

## 4. Policy and detection rules

| Symptom | Cause | Fix |
| --- | --- | --- |
| Edited `policy.yaml`, nothing changed | Docker mounts `policy.yaml` as a single file. An editor that saves by replacing the file (`sed -i`, some `vim` settings) leaves the container on the old copy | `docker compose exec detection-api grep -n "IN_GSTIN" /app/policy.yaml`. If old: `docker compose up -d --force-recreate detection-api` |
| Mistake in `policy.yaml` (YAML error, unknown action such as `blok`, missing field) | The edit is rejected; the previous policy stays in force, requests keep working. `/healthz` shows `"policy_last_error": true`; a `governance.policy_rejected` event (Wazuh 100153) names the problem | `curl -s -H "X-Gov-Token: …" http://127.0.0.1:8088/v1/rules` → `policy_last_error`, or `docker compose logs --tail 20 detection-api`. Fix the file; the next request loads it |
| Edited `recognizers.json`, nothing changed | File rejected (wrong regex, failing test sample, same `version` for new content) | `curl -s -H "X-Gov-Token: $(cat secrets/gov_api_token)" http://127.0.0.1:8088/v1/rules` → `last_error`; `python3 scripts/validate_rules.py` |
| PAN blocked although the policy says `pseudonymize` | Expected for **prompts**: hooks can't rewrite a prompt, so the user resends the redacted version shown. Files and tool output are pseudonymized in place | [ide-hooks.md, section 1](ide-hooks.md#what-each-policy-action-means) |
| A correctly formatted test value is detected (e.g. `ADKPL1234X`) | It *is* a valid PAN format | Describe the format instead, or allow it for one user with a time-limited override in `policy.yaml` |
| GSTIN not detected | This Presidio version checks GSTIN structure only, no checksum; text with different structure isn't GSTIN | Test with `27ABCPE1234F1Z5` |

---

## 5. IDE problems

| Symptom | Cause | Fix |
| --- | --- | --- |
| `~/.claude/settings.json` not updated | `--scope project` writes `<repo>/.claude/settings.local.json` instead; or the command stopped early (`--project <existing folder> is required`) | Use `--scope user` for global; read the installer's output, which prints every path it writes |
| `/hooks` shows nothing in VS Code | VS Code not fully restarted, or an old session | Quit VS Code completely, reopen, start a **new** Claude Code session |
| Every check appears twice in the audit log | Hooks installed at two scopes | Uninstall one (`--scope project --project <repo> --uninstall`) |
| Kiro: no hooks in Agent Hooks panel | Kiro older than 1.0.182 (no global hooks), or Kiro not restarted | Update Kiro; reopen it |
| Kiro: prompt never scanned, tool calls are | Some Kiro 1.0.x builds send an empty prompt to hooks | Kiro 1.2 or later |
| Kiro: repo `.kiroignore` ignored | Kiro reads workspace ignore files only if configured | Settings → *Agent Ignore Files* (`kiroAgent.agentIgnoreFiles`) → add `.kiroignore`. The global kiroignore works without this |
| Managed install: user removed a Kiro hook | Kiro hooks live in user profiles | Intune restores them (hourly on Ubuntu, at detection on Windows) |

---

## 6. Verified identity (`GOV_AUTH_MODE=token+oidc`)

Decode a token to see its claims, without verifying it, so only on your own machine:

```bash
TOKEN=$(az account get-access-token --scope api://<app-id>/.default --query accessToken -o tsv)
python3 -c "import base64,json,sys; p=sys.argv[1].split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))),indent=1))" "$TOKEN" \
  | grep -E '"(iss|aud|ver|exp|preferred_username|upn|oid)"'
```

| Server says | Check |
| --- | --- |
| `user access token required` | Hook has no `GOV_ID_TOKEN_COMMAND`, or it printed nothing |
| `user access token expired` | Clock skew over 60 s, or a stale cache: delete `~/.ai-governance/id_token.cache` |
| `… rejected: Invalid audience` | `aud` ≠ `GOV_OIDC_AUDIENCE`. v2.0 tokens carry the client ID; v1.0 tokens may carry the `api://…` URI. Add both, or set `requestedAccessTokenVersion: 2` |
| `… rejected: Invalid issuer` | `iss` must match exactly: v2.0 ends in `/v2.0`; v1.0 tokens have a different issuer. Use the version you configured |
| `… rejected: Unable to find a signing key that matches` | `GOV_OIDC_JWKS_URL` is for another tenant |
| `has no user name claim` | Token lacks `preferred_username`/`upn`. Request the `profile` scope, or set `GOV_OIDC_USER_CLAIMS` |
| HTTP 503 `cannot reach identity provider keys` | Server can't reach `login.microsoftonline.com`: allow outbound HTTPS from the server |
| HTTP 403 desktop user mismatch | Desktop name and account differ: wrong `az` account (`az account show`), shared login, or copied config. Use `GOV_IDENTITY_MISMATCH=log` while investigating |

---

## 7. Audit log and SIEM

| Symptom | Check |
| --- | --- |
| No `logs/governance-decisions.jsonl` | `GOV_AUDIT_FILE` set? Docker sets it automatically; `logs/` must be writable by `GOV_UID` (`init_secrets.py` sets it) |
| No `logs/governance-events.jsonl` (OTel) | `docker compose logs otel-collector`; `OTEL_EXPORTER_OTLP_ENDPOINT` reaches the collector; the no-Docker route has no collector |
| Wazuh shows no alerts | `python3 siem/wazuh/check_wazuh.py` sends a synthetic event and looks for rule 100132 ([README-wazuh.md](../siem/wazuh/README-wazuh.md)) |
| Justification shows `<PERSON>` | PII inside reasons is masked; the small language model sometimes mistakes words for names. `en_core_web_lg` is less prone to it |

List every warning a user overrode with `#justify:`:

```bash
python3 - <<'EOF'
import json
for line in open("logs/governance-decisions.jsonl"):
    g = json.loads(line).get("governance", {})
    if g.get("decision") == "warn_allow" and g.get("justification"):
        print(f'{g["timestamp"][:19]}  {g.get("user_id","-"):24} {g["data_classes"]:15} "{g["justification"]}"')
EOF
```

In Wazuh: Threat Hunting, filter `rule.id: 100111`.

---

## 8. Reporting a problem

Include:
- **Version and setup check:** `cat VERSION` and `python3 scripts/doctor.py`.
- **Server error:** the last 60 lines of `docker compose logs detection-api`.
- **The block message**, word for word.
- **The decision itself:** the `event_id` from the response or audit log, never the prompt or file contents.

Don't attach real customer data, tokens or `.env`/`secrets/` contents.
