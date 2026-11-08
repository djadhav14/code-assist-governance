#!/usr/bin/env python3
"""Prove that governance decisions arrive in Wazuh as alerts.

    python3 siem/wazuh/check_wazuh.py --wazuh-dir ~/wazuh-docker/single-node

Sends one synthetic Aadhaar prompt through the governance server, then waits for
Wazuh to raise an alert carrying the same event_id (expected: rule 100132,
level 12). Finally it summarises all ai_governance alerts by rule.
Needs the governance server and the Wazuh stack running.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from _config import API_TOKEN, API_URL  # noqa: E402
from test_api import synthetic_aadhaar  # noqa: E402

ALERTS = "/var/ossec/logs/alerts/alerts.json"


def manager(wdir: str, *cmd: str) -> tuple[int, str]:
    p = subprocess.run(["docker", "compose", "exec", "-T", "wazuh.manager", *cmd],
                       cwd=wdir, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wazuh-dir", required=True, help="the wazuh-docker/single-node folder")
    ap.add_argument("--wait", type=int, default=90, help="seconds to wait for the alert")
    args = ap.parse_args()
    wdir = os.path.abspath(os.path.expanduser(args.wazuh_dir))

    code, out = manager(wdir, "test", "-f", "/var/ossec/etc/rules/ai_governance_rules.xml")
    if code != 0:
        print("FAIL  rules file is not mounted in the manager. Run setup_wazuh.py, then in the Wazuh folder:\n"
              "      docker compose up -d --force-recreate wazuh.manager")
        print(out.strip()[:400])
        return 1
    print("PASS  rules file mounted in wazuh.manager")
    code, _ = manager(wdir, "test", "-r", "/var/log/ai-governance/governance-decisions.jsonl")
    print(("PASS" if code == 0 else "FAIL") + "  audit file visible to the manager")
    if code != 0:
        print("      Start the governance server first (it creates logs/governance-decisions.jsonl),\n"
              "      then recreate the manager so the mount picks it up.")
        return 1

    body = json.dumps({"text": f"KYC fails for Aadhaar {synthetic_aadhaar()}", "channel": "prompt",
                       "user": "wazuh-check", "agent": "check_wazuh"}).encode()
    req = urllib.request.Request(API_URL + "/v1/scan", data=body,
                                 headers={"Content-Type": "application/json", "X-Gov-Token": API_TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        event_id = json.load(r)["event_id"]
    print(f"SENT  synthetic Aadhaar prompt, event_id {event_id}")

    deadline = time.time() + args.wait
    alert = None
    while time.time() < deadline and alert is None:
        code, out = manager(wdir, "grep", event_id, ALERTS)
        if code == 0 and out.strip():
            alert = json.loads(out.strip().splitlines()[-1])
        else:
            time.sleep(5)
    if not alert:
        print(f"FAIL  no Wazuh alert within {args.wait} s. Check, in the Wazuh folder:\n"
              "      docker compose logs wazuh.manager | grep -iE 'ai_governance|governance-decisions|error'")
        return 1
    rule = alert.get("rule", {})
    ok = rule.get("id") == "100132"
    print(f"{'PASS' if ok else 'WARN'}  alert raised: rule {rule.get('id')} level {rule.get('level')} - "
          f"{rule.get('description')}")

    code, out = manager(wdir, "grep", '"ai_governance"', ALERTS)
    counts = Counter()
    for line in out.splitlines():
        try:
            r = json.loads(line)["rule"]
            counts[(r["id"], r["level"], r["description"].split(":")[0] + ": " + r["description"].split(":", 1)[1][:60])] += 1
        except (ValueError, KeyError, IndexError):
            continue
    print("\nai_governance alerts so far (rule, level, count):")
    for (rid, level, desc), n in sorted(counts.items()):
        print(f"  {rid}  level {level:>2}  x{n:<4} {desc}")
    print("\nIn the dashboard (https://localhost): Threat Hunting / Discover, filter rule.groups: ai_governance")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
