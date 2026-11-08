"""policy.yaml reloads: a bad edit must never take the service down (or open it up).

No server needed; needs PyYAML (installed with the server's packages):
    python3 tests/test_policy.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection_api"))
try:
    from app import policy as pol
except ImportError as exc:
    print(f"SKIP  {exc} (install detection_api/requirements.txt)")
    sys.exit(0)

results: list[bool] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(("PASS" if ok else "FAIL"), f" {name}" + (f"  -> {detail}" if detail and not ok else ""))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gov-policy-"))
    path = tmp / "policy.yaml"
    shipped = (ROOT / "detection_api" / "policy.yaml").read_text(encoding="utf-8")
    path.write_text(shipped, encoding="utf-8")
    events = []
    try:
        store = pol.PolicyStore(str(path), on_rejected=lambda problem, v: events.append((problem, v)))
        p = store.reload_if_changed()
        check("shipped policy loads", p.entities.get("IN_PAN") is not None)
        good_version = p.version

        def write(text):
            path.write_text(text, encoding="utf-8")
            os.utime(path, ns=(time.time_ns(), time.time_ns()))

        write(shipped.replace("IN_GSTIN:               { action: warn }", "IN_GSTIN:               { action: blok }"))
        p = store.reload_if_changed()
        check("unknown action rejected, previous policy stays", p.version == good_version
              and p.entities["IN_GSTIN"].action == "warn", str(p.entities.get("IN_GSTIN")))
        check("rejection reported once", len(events) == 1 and "blok" in events[0][0], str(events))
        store.reload_if_changed()
        check("same bad file not reported again", len(events) == 1, str(events))
        check("last_error set", bool(store.last_error))

        write("entities: [unclosed")
        p = store.reload_if_changed()
        check("YAML syntax error rejected, previous policy stays", p.version == good_version and len(events) == 2)

        path.unlink()
        p = store.reload_if_changed()
        check("deleted file rejected, previous policy stays", p.version == good_version and len(events) == 3)

        write(shipped.replace("IN_GSTIN:               { action: warn }", "IN_GSTIN:               { action: block }")
              .replace("version: 1", "version: 2", 1))
        p = store.reload_if_changed()
        check("fixed file accepted", p.version == 2 and p.entities["IN_GSTIN"].action == "block")
        check("last_error cleared", store.last_error is None)

        bad = tmp / "bad.yaml"
        bad.write_text("default_action: maybe\n", encoding="utf-8")
        try:
            pol.PolicyStore(str(bad))
            check("bad policy at start-up refused", False, "accepted")
        except RuntimeError as exc:
            check("bad policy at start-up refused", "not started" in str(exc), str(exc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
