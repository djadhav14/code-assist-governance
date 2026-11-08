# Monitor AI governance in Wazuh

*For Wazuh 4.14.10 (wazuh-docker single-node) on a 12 GB laptop. As of 8 Nov 2026.*

Every governance decision becomes a Wazuh event. The Wazuh **manager** runs it through the rules in `ai_governance_rules.xml`, so blocks, redactions and overrides turn into **alerts** with levels, which you can then search on the Wazuh dashboard.

```
IDE hooks / tests ─► detection-api ──┬─► logs/governance-decisions.jsonl ─(read-only mount)─► wazuh.manager ─► rules ─► alerts ─► dashboard
                                     └─► OTLP ─► otel-collector ─► logs/governance-events.jsonl (unchanged; for other tools later)
```

**Why a file and not OpenTelemetry.** The Wazuh manager doesn't accept OpenTelemetry (OTLP) data. Wazuh's documented OpenTelemetry route goes through Data Prepper straight into the indexer, which gives dashboards but **skips the manager, so no rules run and no alerts fire** ([Wazuh blog](https://wazuh.com/blog/analyzing-application-metrics-in-wazuh-using-opentelemetry-and-data-prepper)). Instead, the governance server also writes each decision as one flat JSON line, which the manager reads with its built-in JSON decoder. The OpenTelemetry pipeline keeps running alongside.

---

## 1. Fit it into 12 GB

Wazuh's single-node stack asks for **4 CPU cores, 8 GB RAM and 50 GB of disk** ([Wazuh Docker docs](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)). To leave room for the governance server, your IDE and the OS:

1. **Use Docker Engine, not Docker Desktop.**
   - Docker Desktop runs everything inside a virtual machine. The VM's memory is fixed separately from your 12 GB, so you'd need to raise its limit in Settings → Resources.
   - Wazuh's `vm.max_map_count` setting must also be made inside that VM, not on your laptop.
   - Docker Engine runs directly on Ubuntu, with no VM overhead. Switch with `docker context use default`; README Troubleshooting covers the setup.
2. **Make the governance server lighter.** Set these in `.env`, then rebuild with `docker compose up -d --build`:
   ```
   GOV_NLP_MODEL=en_core_web_sm
   GOV_WORKERS=1
   ```
   The small model is a fraction of the size of the large one. Each worker loads its own copy, so one worker halves memory again. Detection of Indian IDs, cards and secrets is pattern-based, so it's unaffected. Only name (`PERSON`) detection gets slightly weaker.
3. **Leave Wazuh's indexer at its default 1 GB Java heap** (set in Wazuh's compose file).
4. While Wazuh starts, close what you don't need. Afterwards, check real usage with `docker stats --no-stream`.

## 2. Prepare the host (once)

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh-max-map-count.conf
```

Without this setting, the Wazuh indexer container exits shortly after starting.

## 3. Start the governance server with the audit file

From the `ai-governance-local` folder:

```bash
python3 scripts/init_secrets.py        # adds GOV_AUDIT_FILE to an older .env
docker compose up -d --build
python3 tests/test_api.py              # creates some decisions
ls -l logs/governance-decisions.jsonl  # one JSON line per decision
```

## 4. Install Wazuh and connect it

```bash
cd ~
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.10
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator     # creates TLS certificates

cd ~/python_projects/ai-governance/ai-governance-local
python3 siem/wazuh/setup_wazuh.py --wazuh-dir ~/wazuh-docker/single-node

cd ~/wazuh-docker/single-node
docker compose up -d                   # first start: several minutes
docker compose ps                      # wazuh.manager, wazuh.indexer, wazuh.dashboard all "Up"
```

`setup_wazuh.py` changes two things in the Wazuh folder, both reversed by `--uninstall`:

| File | Change |
| --- | --- |
| `config/wazuh_cluster/wazuh_manager.conf` | Appends a `<localfile>` block, between `ai-governance` markers, that reads `/var/log/ai-governance/governance-decisions.jsonl` as JSON. Existing events in the file are read on first start |
| `docker-compose.override.yml` (new) | Mounts this project's `logs/` folder **read-only** into the manager, plus the rules file as `/var/ossec/etc/rules/ai_governance_rules.xml`. Docker Compose merges it with Wazuh's own file automatically |

## 5. Verify

**End to end**, from the `ai-governance-local` folder:

```bash
python3 siem/wazuh/check_wazuh.py --wazuh-dir ~/wazuh-docker/single-node
```

It sends a synthetic Aadhaar prompt through the governance server and waits for Wazuh's alert with the same `event_id`. Expect `rule 100132 level 12`, followed by a count of all governance alerts by rule.

**Each rule on its own**, using Wazuh's rule tester:

```bash
cd ~/wazuh-docker/single-node
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
# paste a line from siem/wazuh/sample-events.jsonl; expected results below
```

| Sample line (in order) | Expected rule | Level |
| --- | --- | --- |
| 1. allow, nothing found | 100100 | 2 (recorded, no alert) |
| 2. warn: email address, justification required | 100110 | 5 |
| 3. warn_allow: sent with justification | 100111 | 6 |
| 4. pseudonymize: PAN | 100120 | 7 |
| 5. block: classification marker | 100130 | 10 |
| 6. block: card number | 100131 | 12 |
| 7. block: Aadhaar | 100132 | 12 |
| 8. block: `.env` path rule | 100133 | 10 |
| 9. per-user override used | 100101 | 10 |

**On the dashboard**, at `https://localhost`:
- Your browser will warn that the certificate is self-signed.
- Wazuh's compose file sets the login as `admin` / `SecretPassword`. **Change the default passwords before using this beyond your laptop** (see Wazuh's docs on changing user passwords).
- Open **Threat Hunting → Events** and filter on `rule.groups: ai_governance`. Fields appear as `data.governance.user_id`, `data.governance.decision`, `data.governance.data_classes` and so on.

## 6. The rules

| Rule | Level | Fires when |
| --- | --- | --- |
| 100100 | 2 | Any governance decision. Allowed requests stop here: they're recorded but don't alert |
| 100101 | 10 | A per-user override from `policy.yaml` was used |
| 100110 | 5 | A prompt was held until the user gives `#justify:` |
| 100111 | 6 | Sent with a justification, or allowed-and-logged in a file or tool output |
| 100120 | 7 | A value was masked or pseudonymized (PAN, mobile, UPI, IFSC, account…) |
| 100130 | 10 | Blocked (other classes, e.g. confidential-document marker) |
| 100131 | 12 | Blocked: payment card number. Tagged `pci_dss_3.4` |
| 100132 | 12 | Blocked: Aadhaar, IBAN, API key or token, private key, connection string |
| 100133 | 10 | Agent tried to read a restricted file (`.env`, keys, `customer-data/` …) |
| 100140 | 12 | 5 blocks for the same user within an hour; repeats for that user are suppressed for 10 minutes |
| 100150 | 5 | A new detection rules version is in force (`docs/detection-rules.md`) |
| 100152 | 8 | A new detection rules version removed a recognizer |
| 100151 | 10 | A detection rules file was rejected; the previous version stays in force |
| 100153 | 10 | A `policy.yaml` edit was rejected; the previous policy stays in force |
| 100160 | 8 | Verified identity: the desktop user doesn't match the signed-in account (logged, allowed) |
| 100161 | 10 | Verified identity: the same, refused (`GOV_IDENTITY_MISMATCH=block`) |

Each decision matches exactly one of 100100–100133: override events are matched first, and the decision rules exclude them. Rule 100140 is a correlation rule built on top of the block rules.

To tune the rules:
1. Edit `siem/wazuh/ai_governance_rules.xml`. Keep IDs within 100100–100199.
2. Restart the manager: `docker compose restart wazuh.manager` in the Wazuh folder.
3. Re-check with `wazuh-logtest`.

## 7. What gets logged

The audit file uses the same privacy rules as the other logs:
- **No raw sensitive values.** Each matched value appears only as a keyed hash in `value_hashes`.
- **Justifications are scanned first.** Anything sensitive inside one is masked before logging, e.g. `customer <UK_NHS> asked, PAN <IN_PAN>`.

Fields: `event_id`, `timestamp`, `user_id`, `host_name`, `agent`, `hook_event`, `session_id`, `tool_name`, `channel`, `decision`, `reason`, `justification`, `data_classes`, `actions`, `policy_sources`, `value_hashes`, `finding_count`, `file_path`, `path_rule`, `latency_ms`.

**Rotation.** The server reopens the file if it's moved, so a standard logrotate rule works:

```
/home/<you>/python_projects/ai-governance/ai-governance-local/logs/governance-decisions.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
```

Keep rotated files for as long as your audit retention policy requires. Wazuh's own index keeps the alerts separately.

## 8. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `wazuh.indexer` keeps restarting | Set `vm.max_map_count` (step 2); check free memory (step 1) |
| `check_wazuh.py`: rules file not mounted | Rerun `setup_wazuh.py`, then in the Wazuh folder: `docker compose up -d --force-recreate wazuh.manager` |
| `check_wazuh.py`: audit file not visible | Start the governance server first so the file exists, then recreate the manager as above |
| No alert within 90 s | In the Wazuh folder, run `docker compose logs wazuh.manager \| grep -iE "governance\|error"`. If you see an XML error in `ai_governance_rules.xml`, the manager will say which line |
| Port 443 or 514/udp already in use | Change the left-hand port in Wazuh's `docker-compose.yml` (e.g. `8443:5601`) |
| Alerts appear, but allowed requests don't | By design: level 2 isn't alerted. Allowed requests are in the audit file and the OpenTelemetry log |

**Remove the integration:**

```bash
python3 siem/wazuh/setup_wazuh.py --wazuh-dir ~/wazuh-docker/single-node --uninstall
```

Then run `docker compose up -d --force-recreate wazuh.manager` in the Wazuh folder.

## Test status

- **Tested here:**
  - The audit file comes from a real server run.
  - Every rule matches its intended real event, using the same conditions as the XML evaluated in Python.
  - The rules XML is well formed.
  - `setup_wazuh.py` was run against Wazuh's actual v4.14.10 compose and manager config: the merged compose validates, a rerun changes nothing, and uninstall restores the config byte for byte.
- **Not tested:** running the Wazuh containers themselves, because Docker Hub is blocked from the build environment. Steps 4–5 are the first real run. If anything fails, send the `check_wazuh.py` output and `docker compose logs wazuh.manager`.
