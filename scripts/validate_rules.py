#!/usr/bin/env python3
"""Check a detection rules file before you push it, with the server's own checks.

    python3 scripts/validate_rules.py                                  # the repo's rules file
    python3 scripts/validate_rules.py my-rules.json --against detection_api/rules/recognizers.json

Exit code 0 = the server will accept the file; 1 = it will reject it.
Use it in a pre-commit hook or CI job. Needs only Python 3.9+; install the
optional `regex` package (pip install regex) to include the speed check that
the server always runs.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection_api"))
from app import rules as rl  # noqa: E402

DEFAULT = ROOT / "detection_api" / "rules" / "recognizers.json"
POLICY = ROOT / "detection_api" / "policy.yaml"


def policy_entities(path: Path) -> tuple[set[str], str] | None:
    try:
        import yaml
    except ImportError:
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return set((raw.get("entities") or {}).keys()), raw.get("default_action", "allow")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", default=str(DEFAULT))
    ap.add_argument("--against", help="previous version, to list what changed and check the version was bumped")
    ap.add_argument("--policy", default=str(POLICY), help="policy.yaml to check entity coverage (default: repo's)")
    args = ap.parse_args()

    try:
        new = rl.load_file(args.file)
    except rl.RulesError as exc:
        print(f"RESULT: the server would REJECT {args.file}")
        for p in exc.problems:
            print("  -", p)
        return 1

    problems: list[str] = []
    print(f"Checked {args.file}")
    print(f"  version {new.version}  sha256 {new.sha256[:12]}  updated {new.updated_at or '-'} by {new.updated_by}")
    print(f"  change note: {new.change_note}")
    print(f"  {len(new.enabled)} enabled recognizers, {sum(len(r.patterns) for r in new.enabled)} patterns"
          + (f", {len(new.recognizers) - len(new.enabled)} disabled" if len(new.enabled) < len(new.recognizers) else ""))

    if args.against:
        try:
            old = rl.load_file(args.against)
        except rl.RulesError as exc:
            print(f"  (could not read --against file: {exc})")
            old = None
        if old:
            d = rl.diff(old, new)
            for k in ("added", "removed", "changed"):
                if d[k]:
                    print(f"  {k}: {', '.join(d[k])}")
            if old.sha256 == new.sha256:
                print("  no changes")
            elif old.version == new.version:
                problems.append(f"content changed but version is still {new.version}: the server will reject it")

    pol = policy_entities(Path(args.policy)) if Path(args.policy).exists() else None
    if pol:
        known, default = pol
        missing = sorted({r.entity for r in new.enabled} - known)
        if missing:
            new.warnings.append(f"no policy.yaml rule for {', '.join(missing)}: default_action {default!r} applies")

    for w in new.warnings:
        print("  warning:", w)
    for p in problems:
        print("  problem:", p)
    print("RESULT: the server would " + ("REJECT this file" if problems else "accept this file"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
