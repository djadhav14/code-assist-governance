# Detection API: install, run and test in each environment

*Version 1.0.0, 8 Nov 2026.*

The Detection API is the FastAPI + Microsoft Presidio server that every IDE hook calls. It finds PII, secrets and confidential markers in text, files and images. It then applies `policy.yaml` (allow, mask, pseudonymize, warn, block), and logs one audit event per decision. How it works inside: [architecture.md](architecture.md). Every setting: [configuration.md](configuration.md).

| Environment | Where it runs | Secrets | TLS | Who signs in | Status in this repo |
| --- | --- | --- | --- | --- | --- |
| **Local** | Your laptop: Docker Compose, or a Python venv | `./secrets/` files (Docker secrets) | None (loopback only) | Shared token | Built and tested |
| **Test server** | One EC2 instance: Docker Compose + Caddy | **AWS Secrets Manager**, read with the instance role | Caddy, private CA or public certificate | Shared token, optionally + Entra ID | Compose, IAM policy and secret loader tested against a simulated AWS (moto); not run on a real EC2 instance |
| **Production** | ECS Fargate behind an internal ALB | AWS Secrets Manager, read with the task role | ALB with an ACM certificate | Shared token + Entra ID (`token+oidc`) | Reference design and task-definition template; not deployed |

---

## 1. API at a glance

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Liveness, plus the policy and rules versions, auth mode, secrets source and entity list |
| `POST /v1/scan` | yes | Scan one text: prompt, tool input or tool output |
| `POST /v1/scan-batch` | yes | Scan several texts in one call |
| `POST /v1/scan-file` | yes | Scan a file's bytes (text, PDF, image with OCR), with path rules |
| `GET /v1/rules` | yes | Detection rules version in force, recognizers, last rejected file |

"Auth" means `X-Gov-Token: <GOV_API_TOKEN>` and, with `GOV_AUTH_MODE=token+oidc`, `Authorization: Bearer <user access token>` too ([ide-hooks.md, section 5](ide-hooks.md#5-production-verified-user-identity)).

---

## 2. Local

### 2.1 Install

Prerequisites: Python 3.9+ for the scripts and hooks (3.10–3.13 to run the server without Docker), and Docker Engine with Compose or Docker Desktop **running**. You also need about 3 GB of disk and 4 GB of free RAM for the large language model (`en_core_web_lg`). With 8 GB of RAM or less, set `GOV_NLP_MODEL=en_core_web_sm` in `.env`.

```bash
cd ai-governance-local
python3 scripts/doctor.py           # package check; config and server checks fail until the next steps
python3 scripts/init_secrets.py     # creates .env, secrets/gov_api_token, secrets/gov_hash_key, logs/
```

`init_secrets.py` keeps existing secrets when run again; `--rotate` replaces them. Run it again after every upgrade: it adds new settings to an existing `.env`.

**Option A: Docker (recommended)**

```bash
docker compose up -d --build        # first build ~10 min; downloads Python packages and the spaCy model
docker compose ps                   # wait for detection-api (healthy)
curl http://127.0.0.1:8088/healthz  # Windows PowerShell: curl.exe ...
```

**Option B: no Docker**

```bash
python3 -m venv .venv && source .venv/bin/activate         # Windows: .venv\Scripts\Activate.ps1
pip install -r detection_api/requirements.txt
python -m spacy download en_core_web_lg                    # or en_core_web_sm
sudo apt install tesseract-ocr                             # optional: images and scanned PDFs
cd detection_api && GOV_ENV_FILE=../.env python -m app.serve
```

The server listens on `127.0.0.1:8088`. With Docker it is published on loopback only, unless you set `GOV_BIND_ADDRESS`.

### 2.2 Test

| Command | Needs | Expect |
| --- | --- | --- |
| `python3 scripts/doctor.py` (add `--local` for option B) | — | `0 failure(s)` |
| `python3 tests/test_api.py` | running server | 19/19: every data class and action |
| `python3 tests/test_hooks.py` | running server | 30/30: both IDE hook protocols, fail-closed, configuration |
| `python3 tests/test_rules.py` | — | 26/26: rules file checks; add `--live detection_api/rules/recognizers.json` for hot reload (31/31) |
| `python3 tests/test_identity.py` | server packages (option B venv) | 21/21: verified identity with a stand-in identity provider |
| `python3 tests/test_aws_secrets.py` | `pip install boto3 "moto[secretsmanager]"` | 13/13: Secrets Manager loading and token rotation, simulated AWS |
| `python3 tests/test_policy.py` | server packages | 10/10: a bad `policy.yaml` edit never causes an outage |
| `cd detection_api && python ../tests/test_offline_suffix.py` | server packages | 2/2 |
| `bash scripts/ci.sh` | server packages | Everything above, the way GitHub Actions runs it |

Quick manual checks:

```bash
TOKEN=$(cat secrets/gov_api_token)
# PAN -> pseudonymize
curl -s -X POST http://127.0.0.1:8088/v1/scan -H "Content-Type: application/json" -H "X-Gov-Token: $TOKEN" \
  -d "{\"text\": \"Borrower PAN ABCPE1234F needs re-check.\", \"channel\": \"prompt\", \"user\": \"$USER\"}" | python3 -m json.tool
# GSTIN -> warn (add "justification": "..." to get warn_allow)
curl -s -X POST http://127.0.0.1:8088/v1/scan -H "Content-Type: application/json" -H "X-Gov-Token: $TOKEN" \
  -d "{\"text\": \"Vendor GSTIN 27ABCPE1234F1Z5 for the invoice\", \"channel\": \"prompt\", \"user\": \"$USER\"}" | python3 -m json.tool
tail -1 logs/governance-decisions.jsonl                      # the audit record: never the value, only a keyed hash
```

### 2.3 Change policy and rules locally

- **`detection_api/policy.yaml`**: what to do with each data class. Edit the file and bump `version:`. The server reloads it on the next request, with no restart. If a Docker container keeps the old content, run `docker compose up -d --force-recreate detection-api` ([debugging.md](debugging.md#4-policy-and-detection-rules)).
- **`detection_api/rules/recognizers.json`**: what to detect. It's validated and hot-reloaded, and every version is archived: [detection-rules.md](detection-rules.md).

---

## 3. Choosing how secrets reach the server

The server needs two secrets: `GOV_API_TOKEN` (hooks authenticate with it) and `GOV_HASH_KEY` (keys the audit fingerprints and pseudonym tokens). Neither has a default, and the server refuses to start without them. Exactly one source is used:

| Source | Set | Used for |
| --- | --- | --- |
| Secret files | `GOV_API_TOKEN_FILE`, `GOV_HASH_KEY_FILE` | Local Docker (Compose mounts `./secrets/` at `/run/secrets/`) |
| **AWS Secrets Manager** | `GOV_AWS_SECRET_ID` (name or ARN) and `GOV_AWS_REGION` | Test server and production |
| Environment variables | `GOV_API_TOKEN`, `GOV_HASH_KEY` | Only if your platform injects them securely |

With `GOV_AWS_SECRET_ID` set, also setting `GOV_API_TOKEN`, `GOV_HASH_KEY` or their `_FILE` variants is refused at start-up, so there is never doubt about which value is in force. `/healthz` shows `"secrets_source": "aws-secrets-manager"`.

**AWS credentials:** the server uses boto3's default credential chain, which means:
- on EC2: the **instance profile role**;
- on ECS: the **task role**;
- on a laptop: an `aws sso login` profile.

No access keys are configured anywhere. If the process does find long-term IAM user keys (`AKIA…`), it still starts but logs a warning. Those keys never expire, and anyone who copies them from the host can read the secret.

---

## 4. Test server on AWS (EC2 + Secrets Manager)

One EC2 instance runs the same containers as your laptop, plus Caddy for TLS. The files are in `deploy/aws/`:

| File | Purpose |
| --- | --- |
| `docker-compose.test-server.yml` | detection-api (secrets from Secrets Manager, not published), OTel collector, Caddy on 443 |
| `Caddyfile` | TLS in front of the API; private CA by default |
| `test-server.env.example` | Non-secret settings for that compose file |
| `iam-policy-read-secret.json` | Least-privilege policy: read **one** secret, decrypt only through Secrets Manager |

Commands use the AWS CLI with your admin profile (e.g. `aws sso login --profile admin`). Replace `<…>` placeholders.

### 4.1 Create the secret

Generate both values on your machine and upload them as one JSON secret, without the values passing through shell history:

```bash
umask 077
python3 -c 'import json,secrets; print(json.dumps({"GOV_API_TOKEN": secrets.token_urlsafe(32), "GOV_HASH_KEY": secrets.token_urlsafe(48)}))' > /tmp/gov-secret.json
aws secretsmanager create-secret --name ai-governance/test \
    --description "AI governance detection API (test)" \
    --secret-string file:///tmp/gov-secret.json --region ap-south-1
shred -u /tmp/gov-secret.json 2>/dev/null || rm -f /tmp/gov-secret.json
```

Add `--kms-key-id <key-arn>` to encrypt it with your own KMS key instead of the AWS-managed one; the IAM policy below already allows that key.

### 4.2 Give the instance a role that can read only that secret

```bash
# Policy: edit region, account ID and KMS key in the file first (remove the KMS statement if you used the AWS-managed key)
aws iam create-policy --policy-name ai-governance-read-test-secret \
    --policy-document file://deploy/aws/iam-policy-read-secret.json
aws iam create-role --role-name ai-governance-test-server \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name ai-governance-test-server \
    --policy-arn arn:aws:iam::<account-id>:policy/ai-governance-read-test-secret
aws iam create-instance-profile --instance-profile-name ai-governance-test-server
aws iam add-role-to-instance-profile --instance-profile-name ai-governance-test-server --role-name ai-governance-test-server
aws ec2 associate-iam-instance-profile --instance-id <i-…> --iam-instance-profile Name=ai-governance-test-server
```

### 4.3 Let containers reach the instance role (IMDSv2 hop limit)

The containers reach the instance metadata service through Docker's network bridge. That takes one network hop more than the default allows, so raise the hop limit to 2 and keep IMDSv2 required:

```bash
aws ec2 modify-instance-metadata-options --instance-id <i-…> --http-tokens required --http-put-response-hop-limit 2
```

Without this, the server fails at start-up with `Cannot read AWS Secrets Manager secret … Unable to locate credentials`.

### 4.4 Install and start

Instance: Ubuntu 24.04 with at least 8 GB RAM for `en_core_web_lg` with 2 workers. Security group: inbound **443 only, from your office/VPN range**; no public 8088.

```bash
# On the instance
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker "$USER" && newgrp docker
git clone https://github.com/<you>/<repo>.git ai-governance-local && cd ai-governance-local
mkdir -p logs
cp deploy/aws/test-server.env.example deploy/aws/test-server.env
nano deploy/aws/test-server.env          # GOV_AWS_SECRET_ID, GOV_SITE_ADDRESS, GOV_UID/GID (id -u / id -g), image tags
docker compose -f deploy/aws/docker-compose.test-server.yml --env-file deploy/aws/test-server.env up -d --build
docker compose -f deploy/aws/docker-compose.test-server.yml --env-file deploy/aws/test-server.env logs --tail 30 detection-api
```

The start-up log should show `auth mode token, secrets from aws-secrets-manager`, then `Application startup complete`.

### 4.5 TLS certificate for developers

`GOV_SITE_ADDRESS` is the name the hooks use, and it must resolve to the instance.

- **Private name** (default `Caddyfile`, `local_certs`): Caddy issues the certificate from its own CA. Copy that CA to developer laptops and set `GOV_CA_BUNDLE` in the hooks:

  ```bash
  docker compose -f deploy/aws/docker-compose.test-server.yml --env-file deploy/aws/test-server.env \
      exec caddy cat /data/caddy/pki/authorities/local/root.crt > governance-test-ca.pem
  ```

- **Public DNS name:** delete the `local_certs` line. Caddy then obtains a publicly trusted certificate (port 80 or 443 must be reachable for the challenge), and no `GOV_CA_BUNDLE` is needed.
- **Corporate CA:** replace the site block with `tls /path/cert.pem /path/key.pem`, mounting the files.

Python 3.13 rejects certificates that miss standard fields such as *Authority Key Identifier*, so very old internal CAs may need reissuing. Caddy's certificates are fine ([debugging.md](debugging.md#3-hooks-cannot-reach-the-server)).

### 4.6 Test the test server

From your laptop, with the token read from Secrets Manager into this shell only:

```bash
export GOV_API_URL=https://governance-test.corp.internal
export GOV_CA_BUNDLE=$PWD/governance-test-ca.pem          # private CA only
export GOV_API_TOKEN=$(aws secretsmanager get-secret-value --secret-id ai-governance/test \
    --query SecretString --output text | python3 -c 'import json,sys; print(json.load(sys.stdin)["GOV_API_TOKEN"])')
curl --cacert "$GOV_CA_BUNDLE" "$GOV_API_URL/healthz"     # "secrets_source": "aws-secrets-manager"
python3 tests/test_api.py                                # 19/19
python3 tests/test_hooks.py                              # 30/30
unset GOV_API_TOKEN
```

If the server runs `GOV_AUTH_MODE=token+oidc`, also export `GOV_ID_TOKEN_COMMAND` (the same command the hooks use), and the tests send your access token too. Don't run `tests/test_rules.py --live` against a shared server: it edits the rules file in place.

### 4.7 Rotate the secret

Rotate the API token without locking anyone out. Keep the old token as `GOV_API_TOKEN_PREVIOUS` while the hooks are updated:

```bash
aws secretsmanager get-secret-value --secret-id ai-governance/test --query SecretString --output text > /tmp/old.json
python3 - <<'PY' > /tmp/gov-secret.json
import json, secrets
old = json.load(open("/tmp/old.json"))
print(json.dumps({"GOV_API_TOKEN": secrets.token_urlsafe(32), "GOV_API_TOKEN_PREVIOUS": old["GOV_API_TOKEN"],
                  "GOV_HASH_KEY": old["GOV_HASH_KEY"]}))
PY
aws secretsmanager put-secret-value --secret-id ai-governance/test --secret-string file:///tmp/gov-secret.json
rm -f /tmp/old.json /tmp/gov-secret.json
docker compose -f deploy/aws/docker-compose.test-server.yml --env-file deploy/aws/test-server.env restart detection-api
```

1. **The server accepts both tokens** and logs a warning while `GOV_API_TOKEN_PREVIOUS` is set. It reads the secret only at start-up, which is why it needs the restart.
2. **Get the new token to every hook:** rebuild and redeploy the Intune packages ([intune.md](intune.md#7-change-or-rotate)), or re-run the installer on test laptops.
3. **Finish the rotation:** once every device has the new token, remove `GOV_API_TOKEN_PREVIOUS` from the secret and restart again.

Rotate `GOV_HASH_KEY` only deliberately. Fingerprints and pseudonym tokens from before the change no longer match those after it, which breaks correlation in the SIEM.

---

## 5. Production (reference design: ECS Fargate)

| Concern | Design |
| --- | --- |
| Compute | ECS Fargate service, 2+ tasks across two AZs, `deploy/aws/ecs-task-definition.template.json` |
| Image | Built by CI, pushed to ECR, tagged with `VERSION`; the spaCy model baked in |
| Network | Internal ALB with an ACM certificate (HTTPS 443) in private subnets; reachable only from the corporate network/VPN. Tasks accept traffic only from the ALB security group |
| Secrets | `GOV_AWS_SECRET_ID=ai-governance/production`, read with the **task role** (`iam-policy-read-secret.json`, scoped to the production secret). Alternative: ECS `secrets` injection with `valueFrom` pointing to the JSON keys |
| Identity | `GOV_AUTH_MODE=token+oidc` with Microsoft Entra ID ([ide-hooks.md, section 5](ide-hooks.md#5-production-verified-user-identity)) |
| Audit | stdout → CloudWatch Logs (`awslogs`); flat audit file and rules archive on EFS (access point with uid/gid 10001, the image's user); OTel to your SIEM through an ADOT/collector sidecar or service |
| Policy and rules | Baked into the image per release, or mounted from EFS. For managed, staged rule rollouts use AWS AppConfig ([detection-rules.md, section 6](detection-rules.md#6-file-now-database-or-configuration-service-later)) |
| Health | Container health check on `/healthz`, ALB target health on the same path, `startPeriod` 120 s for model loading |
| Scaling | Each task runs `GOV_WORKERS` processes, and each process loads its own copy of the spaCy model, so memory grows with workers. Size tasks by measuring, and scale on CPU and p95 latency |

Production smoke test after each deployment (never the `--live` rules test):

```bash
curl -s https://governance.corp.internal/healthz              # versions, auth token+oidc, aws-secrets-manager
GOV_API_URL=https://governance.corp.internal GOV_ID_TOKEN_COMMAND="az account get-access-token --scope api://<app-id>/.default --query accessToken -o tsv" \
GOV_API_TOKEN=… python3 tests/test_api.py                     # synthetic data only; 19/19
```

Then confirm the events in the SIEM: Wazuh rule 100132 for the synthetic Aadhaar, and `user_verified: true`.

---

## 6. Test matrix

| Test | Local | Test server | Production |
| --- | --- | --- | --- |
| `doctor.py` | ✔ | ✔ (on the instance, `--local`) | — |
| `test_api.py`, `test_hooks.py` | ✔ | ✔ from a laptop (4.6) | `test_api.py` as a smoke test (synthetic data) |
| `test_rules.py` | ✔ incl. `--live` | Offline part only | Offline part only, in CI |
| `test_identity.py`, `test_aws_secrets.py`, `test_offline_suffix.py` | ✔ (CI) | — (CI) | — (CI) |
| IDE end to end (`tests/make_samples.py`) | ✔ | ✔ pilot laptops | Pilot group after each release |
| SIEM events (`siem/wazuh/check_wazuh.py`) | ✔ with local Wazuh | ✔ | ✔ |
