# Detection rules: `recognizers.json`

*As of 8 Nov 2026, version 0.7.0.*

The custom patterns the server detects (Indian bank accounts, IFSC, UPI, mobile numbers, secrets, connection strings, classification markers) live in **`detection_api/rules/recognizers.json`**, not in code. You change detection by publishing a new version of that file. The server checks the file, swaps it in **without a restart**, keeps a copy, and logs the change for the SOC. Every decision records which rules version and which pattern produced it.

## 1. What lives where

| What | File | Who changes it |
| --- | --- | --- |
| **What to detect**: custom regex patterns, context words, scores | `detection_api/rules/recognizers.json` | Detection-rules owner, through review |
| **What to do** with each data class: allow, mask, pseudonymize, warn, block; path rules; per-user overrides | `detection_api/policy.yaml` | Policy owner |
| Presidio's own recognizers: Aadhaar, PAN, cards, IBAN, email, phone, person names, passport, GSTIN… | Presidio code (they use checksum and NLP logic that a regex can't express) | Not editable; turn one off with `disabled_entities` in `policy.yaml` |

`GET /v1/rules` lists both: the custom recognizers from the file and the names of Presidio's built-in ones.

A new entity in `recognizers.json` that `policy.yaml` doesn't mention gets the policy's `default_action`. The validator and the server's `governance.rules_loaded` event both warn about this.

## 2. File format

```json
{
  "schema_version": 1,
  "version": "2026.11.08.1",
  "updated_at": "2026-11-08",
  "updated_by": "detection-rules owner's name or ID",
  "change_note": "What changed and why (ticket number)",
  "defaults": { "language": "en", "regex_flags": ["IGNORECASE", "MULTILINE", "DOTALL"] },
  "recognizers": [
    {
      "name": "InIfscRecognizer",
      "entity": "IN_IFSC",
      "group": "india",
      "enabled": true,
      "description": "IFSC branch codes: 4 letters, 0, 6 alphanumerics.",
      "patterns": [ { "name": "in_ifsc", "regex": "\\b[A-Z]{4}0[A-Z0-9]{6}\\b", "score": 0.6 } ],
      "context": ["ifsc", "branch", "bank", "neft", "rtgs"],
      "tests": { "match": ["Send NEFT to IFSC HDFC0001234 today."], "no_match": ["Code HDFC1001234"] }
    }
  ]
}
```

| Field | Rules |
| --- | --- |
| `version` | Required. Must change whenever the content changes. Convention: `YYYY.MM.DD.N` |
| `updated_by`, `change_note` | Required; they go into the audit event |
| `regex_flags` | Default is Presidio's own: case-insensitive, multi-line, `.` matches newlines. A recognizer can set its own list (`IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, `ASCII`) |
| `regex` | JSON string, so every backslash is doubled: `\b` is written `\\b`. Up to 2000 characters |
| `score` | Above 0, at most 1. It is compared with `score_threshold` / `min_score` in `policy.yaml`. Context words near a match raise the score, so ambiguous patterns (bank account, bare mobile number) start low |
| `enabled` | `false` keeps a recognizer in the file, and in the history, without using it |
| `tests.match` | Required for an enabled recognizer: text it must detect. Every pattern should be exercised by at least one sample, or you get a warning |
| `tests.no_match` | Text it must **not** detect: record known false positives here once fixed, so they can't return |

Test samples must be synthetic. Never put real customer data or real keys in this file; it is stored in Git, in the archive and in backups.

## 3. Checks before a file goes live

The server runs these checks on every new file, and `scripts/validate_rules.py` runs the same code before you push:

1. Structure: required fields, unique names, UPPER_CASE entity names, valid scores and flags
2. Every regex compiles with the flags Presidio will use, and none matches empty text
3. **Speed**: each pattern is run against hostile inputs (long runs of the same character, and similar). A pattern taking over 250 ms is rejected, because catastrophic backtracking in one regex would delay every request past the hooks' timeout
4. **Declared behaviour**: every `tests.match` sample is detected and no `tests.no_match` sample is
5. **Version discipline**: changed content with an unchanged `version`, or a `version` already archived for different content, is rejected
6. Presidio builds the recognizers, and the new analyzer passes a warm-up scan

If any check fails, the server **keeps the previous version in force**, logs `governance.rules_rejected` with every problem, and shows it under `last_error` in `GET /v1/rules`. At start-up there is no previous version, so a bad file stops the server from starting: it never runs without detection rules (fail closed).

## 4. Change workflow

```text
edit recognizers.json ─► validate_rules.py (pre-commit / CI) ─► pull request + review ─► merge
      ─► deploy the file ─► server checks, swaps, archives ─► governance.rules_loaded ─► Wazuh alert 100150
```

```bash
# 1. Edit, bump "version", set "updated_by" and "change_note"
# 2. Check it, and see what changed compared with the version in force:
git show HEAD:detection_api/rules/recognizers.json > /tmp/rules-previous.json
python3 scripts/validate_rules.py detection_api/rules/recognizers.json --against /tmp/rules-previous.json
# 3. Commit through a pull request. In CI: python3 scripts/validate_rules.py && python3 tests/test_rules.py
# 4. Deploy. Locally the compose file mounts detection_api/rules/, so saving the file is the deployment.
# 5. Confirm:
curl -s -H "X-Gov-Token: $(cat secrets/gov_api_token)" http://127.0.0.1:8088/v1/rules | python3 -m json.tool | head -20
```

**Rollback:** put the previous file back (same `version`, same content). The archive accepts that, because only *different* content under an old version number is refused. The rollback is logged as a new `governance.rules_loaded` event.

**Hot reload:** each request checks the file's timestamp (one `stat` call), and a changed file is built and warmed up before it replaces the old analyzer. Requests already running finish on the old version. Each server worker (`GOV_WORKERS`) reloads on its next request, so a worker never makes a decision with outdated rules. Each worker logs its own `rules_loaded` event, with `process_pid`; the Wazuh rule shows one alert.

## 5. Audit and tracing

| Question | Where the answer is |
| --- | --- |
| Which rules made this decision? | `rules_version` and `policy_version` on every `governance.decision` event |
| Which pattern matched? | `findings[].recognizer` and `findings[].pattern` (stdout/OTel); `patterns` in the flat audit file, e.g. `InMobileRecognizer.in_mobile_bare` |
| What exactly did that version contain? | The archive, `logs/rules-archive/<version>__<sha256-prefix>.json`, written when the server first accepts a version. Git history holds the same file with author and review |
| Who changed detection, when, and why? | `governance.rules_loaded`: version, previous version, `updated_by`, `change_note`, recognizers added/removed/changed, sha256, build time |
| Was a change refused? | `governance.rules_rejected`: the problems, the rejected version, and the version that stayed in force |

The archive is the server's own record of what actually ran, and it doesn't depend on Git. Back up `logs/rules-archive/` with the audit log, and keep both for the same retention period.

**Learning from the data:** decisions per pattern show where tuning pays off. A pattern with many `warn`/`warn_allow` decisions and justifications like "test data" is probably too broad. Raise its score threshold in `policy.yaml`, add context words, or tighten the regex, and add the false-positive text to `tests.no_match`.

Wazuh rules for these events (`siem/wazuh/ai_governance_rules.xml`):

| Rule | Level | When |
| --- | --- | --- |
| 100150 | 5 | A new rules version is in force |
| 100152 | 8 | A new version **removed** a recognizer (detection may be weaker) |
| 100151 | 10 | A rules file was rejected; the previous version stays in force |

## 6. File now, database or configuration service later?

The loader validates **content**, wherever it comes from. Only the step that fetches the file needs to change.

| Option | Versioning and audit | Approval | Fits |
| --- | --- | --- | --- |
| **JSON in Git** (built now) | Git history, plus the server's archive and audit events | Pull-request review | Prototype and 40-developer rollout. No extra infrastructure |
| **AWS AppConfig** (recommended for the AWS phase) | Hosted configurations have numbered versions; a deployment can be stopped, or a completed one reverted within 72 hours [1] | Deployment strategies; Lambda or JSON Schema validators run before a deployment [2] | Production: staged rollout across server instances, automatic rollback when a CloudWatch alarm fires [3] (for example, on a rise in HTTP 5xx) |
| Database (DynamoDB, PostgreSQL) | You build history tables, approval and rollback yourself | You build it | Only if you need an admin UI for non-technical editors |

For AWS, I recommend: keep Git as the place where rules are written and reviewed, and have CI publish each merged version to AppConfig. The server then reads from AppConfig instead of a mounted file, running the same checks, archive and audit events. A database adds the most work and gives the least control of the three.

Sources:
1. [Reverting a configuration — AWS AppConfig User Guide](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-deploying-reverting.html)
2. [Understanding validators — AWS AppConfig User Guide](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-configuration-and-profile-validators.html)
3. [Monitoring deployments for automatic rollback — AWS AppConfig User Guide](https://docs.aws.amazon.com/appconfig/latest/userguide/monitoring-deployments.html)
