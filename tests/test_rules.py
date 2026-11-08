"""Tests for the detection rules file (detection_api/rules/recognizers.json).

Part 1 needs no server and no Presidio: it checks the shipped file and that the
loader rejects every kind of bad file.

    python3 tests/test_rules.py

Part 2 (optional) proves hot reload against the running server. It edits the
rules file the server reads, then restores the original byte-for-byte:

    python3 tests/test_rules.py --live detection_api/rules/recognizers.json
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection_api"))
from app import rules as rl  # noqa: E402

SHIPPED = ROOT / "detection_api" / "rules" / "recognizers.json"
results: list[bool] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(("PASS" if ok else "FAIL"), f" {name}" + (f"  -> {detail}" if detail and not ok else ""))


def rejected(doc: dict, needle: str) -> tuple[bool, str]:
    try:
        rl.parse(json.dumps(doc).encode())
    except rl.RulesError as exc:
        return any(needle in p for p in exc.problems), str(exc)
    return False, "accepted"


def offline() -> None:
    # The server must take every custom pattern from the rules file, never from code.
    import re
    refs = [f"{p.name}:{i}" for p in (ROOT / "detection_api" / "app").glob("*.py")
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if re.search(r"\bfrom\s+\.?recognizers\b|\bimport\s+.*\brecognizers\b|app\.recognizers", line)]
    check("no server code imports recognizers.py", not refs, ", ".join(refs))
    check("engine builds custom recognizers only from the rules file",
          "build_custom_recognizers(ruleset)" in (ROOT / "detection_api" / "app" / "engine.py").read_text())

    base = json.loads(SHIPPED.read_text(encoding="utf-8"))
    rs = rl.parse(SHIPPED.read_bytes())
    check("shipped file is valid", True)
    check("shipped file has no warnings", not rs.warnings, str(rs.warnings))
    check("every recognizer has test samples", all(r.patterns for r in rs.recognizers))

    def variant(fn):
        d = copy.deepcopy(base)
        fn(d)
        return d

    cases = [
        ("bad regex rejected", lambda d: d["recognizers"][0]["patterns"][0].update(regex="(unclosed"), "does not compile"),
        ("catastrophic regex rejected", lambda d: d["recognizers"][0]["patterns"][0].update(regex=r"(a+)+$"), "hostile input"),
        ("regex matching empty text rejected", lambda d: d["recognizers"][0]["patterns"][0].update(regex=r"\d*"), "matches empty"),
        ("failing test sample rejected", lambda d: d["recognizers"][1]["tests"]["match"].append("no ifsc here"), "not detected"),
        ("no_match sample that matches rejected", lambda d: d["recognizers"][1]["tests"]["no_match"].append("IFSC SBIN0001234"), "no_match sample detected"),
        ("missing test samples rejected", lambda d: d["recognizers"][0].pop("tests"), "tests.match"),
        ("score above 1 rejected", lambda d: d["recognizers"][0]["patterns"][0].update(score=1.5), "score"),
        ("duplicate recognizer name rejected", lambda d: d["recognizers"].append(copy.deepcopy(d["recognizers"][0])), "duplicate"),
        ("lower-case entity rejected", lambda d: d["recognizers"][0].update(entity="bank"), "UPPER_CASE"),
        ("missing change_note rejected", lambda d: d.update(change_note=""), "change_note"),
        ("missing version rejected", lambda d: d.update(version=""), "version"),
        ("unknown regex flag rejected", lambda d: d["recognizers"][0].update(regex_flags=["UNICODE_X"]), "regex_flags"),
    ]
    for name, fn, needle in cases:
        ok, detail = rejected(variant(fn), needle)
        check(name, ok, detail)
    try:
        rl.parse(b"{not json")
        check("invalid JSON rejected", False, "accepted")
    except rl.RulesError as exc:
        check("invalid JSON rejected", "not valid JSON" in str(exc), str(exc))

    # Store: version discipline, archive and diff
    tmp = Path(tempfile.mkdtemp(prefix="gov-rules-"))
    try:
        path, archive = tmp / "recognizers.json", tmp / "archive"
        path.write_bytes(SHIPPED.read_bytes())
        store = rl.RuleStore(str(path), str(archive))
        first = store.load_initial()
        check("initial load archived", len(list(archive.iterdir())) == 1)

        def write(doc):
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            os.utime(path, ns=(time.time_ns(), time.time_ns()))

        changed = variant(lambda d: d["recognizers"][0]["context"].append("loan account"))
        write(changed)
        status, _, err = store.poll()
        check("content change without new version rejected", status == "rejected" and "new version" in str(err), str(err))
        check("previous version stays in force", store.current.version == first.version)

        changed["version"] = "2026.11.08.2"
        changed["change_note"] = "test: add context word"
        write(changed)
        status, cand, _ = store.poll()
        ok = status == "candidate"
        if ok:
            new = store.commit(cand)
            ok = new.version == "2026.11.08.2" and new._changes["changed"] == ["InBankAccountRecognizer"]
        check("new version accepted with diff", ok, f"{status}")
        check("both versions archived", len(list(archive.iterdir())) == 2)

        old_reused = variant(lambda d: d["recognizers"][0]["context"].append("other"))  # version 2026.11.08.1
        write(old_reused)
        status, _, err = store.poll()
        check("reusing an archived version for new content rejected", status == "rejected" and "already used" in str(err), str(err))

        path.unlink()
        status, _, err = store.poll()
        check("deleted file reported, version kept", status == "rejected" and store.current.version == "2026.11.08.2", str(err))
        status, _, _ = store.poll()
        check("deleted file reported only once", status == "unchanged")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def live(rules_file: Path) -> None:
    sys.path.insert(0, str(ROOT / "tests"))
    from _config import API_TOKEN as TOKEN, API_URL as API  # noqa: E402

    def get(path):
        req = urllib.request.Request(API + path, headers={"X-Gov-Token": TOKEN})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def scan(text):
        req = urllib.request.Request(
            API + "/v1/scan", data=json.dumps({"text": text, "channel": "prompt", "user": "rules.test@example.com",
                                                "agent": "test"}).encode(),
            headers={"Content-Type": "application/json", "X-Gov-Token": TOKEN})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def wait_version(v, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            info = get("/v1/rules")
            if info["version"] == v:
                return info
            time.sleep(0.5)
        return get("/v1/rules")

    original = rules_file.read_bytes()
    before = get("/v1/rules")
    doc = json.loads(original)
    sample = "Loan LNX-2026-000123 is overdue"
    try:
        check("live: test text not detected before", not any(f["entity"] == "TEST_RULES_PROBE" for f in scan(sample)["findings"]))
        doc["version"] = before["version"] + ".livetest"
        doc["change_note"] = "tests/test_rules.py --live probe (restored afterwards)"
        doc["recognizers"].append({
            "name": "TestRulesProbeRecognizer", "entity": "TEST_RULES_PROBE", "enabled": True,
            "description": "Temporary probe added by tests/test_rules.py --live",
            "patterns": [{"name": "probe", "regex": r"\bLNX-\d{4}-\d{6}\b", "score": 0.9}],
            "context": [], "tests": {"match": [sample], "no_match": ["LNX-26-1"]},
        })
        rules_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        info = wait_version(doc["version"])
        check("live: new version in force without restart", info["version"] == doc["version"], info["version"])
        res = scan(sample)
        check("live: new pattern detects", any(f["entity"] == "TEST_RULES_PROBE" for f in res["findings"]), str(res["findings"]))

        bad = copy.deepcopy(doc)
        bad["version"] += ".bad"
        bad["recognizers"][-1]["patterns"][0]["regex"] = r"(a+)+$"
        rules_file.write_text(json.dumps(bad, indent=2), encoding="utf-8")
        time.sleep(1)
        info = get("/v1/rules")
        check("live: bad file rejected, good version kept",
              info["version"] == doc["version"] and info["last_error"] is not None, str(info.get("last_error")))
    finally:
        rules_file.write_bytes(original)
        os.utime(rules_file)
        info = wait_version(before["version"])
        check("live: original file restored and back in force", info["version"] == before["version"], info["version"])


def main() -> int:
    offline()
    if "--live" in sys.argv:
        live(Path(sys.argv[sys.argv.index("--live") + 1]).resolve())
    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
