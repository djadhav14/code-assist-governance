"""Detection rules (custom recognizers) loaded from a versioned JSON file.

The patterns that Presidio doesn't ship (Indian bank accounts, IFSC, UPI, mobile
numbers, secrets, connection strings, classification markers) live in
rules/recognizers.json, not in code. Admins change detection by editing that
file; the server picks up a new version without a restart.

A file is accepted only if it passes every check below. Otherwise the server
keeps the last good version in force (and refuses to start if there is none):

* structure: required fields, unique names, scores between 0 and 1
* every regex compiles with the flags Presidio will use
* every recognizer's own test samples behave as declared ("match" samples are
  found, "no_match" samples aren't)
* speed: no pattern takes longer than MAX_PATTERN_MS on hostile input
  (catastrophic backtracking would stall every request)
* the version string changes whenever the content changes, so an audit event's
  version always identifies exactly one file

This module needs only the standard library (plus the optional `regex` package
for the speed check), so scripts/validate_rules.py can run it on any machine or
in CI. Building Presidio recognizers happens in engine.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import re as std_re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:  # Presidio matches with the `regex` package, which supports timeouts.
    import regex as rx
except ImportError:  # pragma: no cover - only on machines without Presidio
    rx = None

SCHEMA_VERSION = 1
MAX_REGEX_CHARS = 2000
MAX_PATTERN_MS = 250          # per pattern, on the hostile inputs below
_NAME = std_re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}$")
_PATTERN_NAME = std_re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_ENTITY = std_re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_VERSION = std_re.compile(r"^[0-9A-Za-z][0-9A-Za-z._\-]{0,63}$")
FLAG_NAMES = ("IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE", "ASCII")
DEFAULT_FLAGS = ["IGNORECASE", "MULTILINE", "DOTALL"]   # Presidio's own default

# Inputs that trigger catastrophic backtracking in badly written patterns.
_HOSTILE = [
    "a" * 5000 + "!",
    "1" * 5000 + "x",
    "a@" * 2500,
    "-" * 5000,
    ("ab" * 50 + " ") * 50,
    "=" * 2000 + ";" * 2000,
    "\n".join(["x" * 80] * 60),
]


class RulesError(ValueError):
    """The rules file was rejected. str() lists every problem found."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class PatternSpec:
    name: str
    regex: str
    score: float


@dataclass(frozen=True)
class RecognizerSpec:
    name: str
    entity: str
    patterns: tuple[PatternSpec, ...]
    context: tuple[str, ...]
    flags: tuple[str, ...]
    group: str = ""
    description: str = ""
    enabled: bool = True
    raw: str = ""       # canonical JSON of this recognizer, used for diffs


@dataclass
class RuleSet:
    version: str
    sha256: str
    updated_at: str
    updated_by: str
    change_note: str
    language: str
    recognizers: list[RecognizerSpec]
    path: str = ""
    loaded_at: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def enabled(self) -> list[RecognizerSpec]:
        return [r for r in self.recognizers if r.enabled]

    def summary(self) -> dict:
        return {
            "version": self.version, "sha256": self.sha256, "updated_at": self.updated_at,
            "updated_by": self.updated_by, "change_note": self.change_note,
            "loaded_at": self.loaded_at, "path": self.path,
            "recognizer_count": len(self.enabled),
            "pattern_count": sum(len(r.patterns) for r in self.enabled),
            "warnings": self.warnings,
        }


def flag_value(names, module=std_re) -> int:
    value = 0
    for n in names:
        value |= getattr(module, n)
    return value


def _compile(regex: str, flags: tuple[str, ...]):
    mod = rx or std_re
    return mod.compile(regex, flag_value(flags, mod))


def _timed_search(compiled, text: str, timeout_s: float):
    """Search with a timeout when the regex package is available."""
    if rx is not None:
        return compiled.search(text, timeout=timeout_s)
    return compiled.search(text)


def parse(data: bytes, path: str = "") -> RuleSet:
    """Parse and fully validate a rules file. Raises RulesError listing every problem."""
    problems: list[str] = []
    warnings: list[str] = []
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RulesError([f"not valid JSON: {exc}"]) from exc
    if not isinstance(doc, dict):
        raise RulesError(["top level must be a JSON object"])

    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"schema_version must be {SCHEMA_VERSION}")
    version = str(doc.get("version") or "")
    if not _VERSION.match(version):
        problems.append("version is required: letters, digits, '.', '_' or '-', e.g. 2026.11.08.1")
    for key in ("updated_by", "change_note"):
        if not str(doc.get(key) or "").strip():
            problems.append(f"{key} is required (it goes into the audit trail)")

    defaults = doc.get("defaults") or {}
    language = defaults.get("language", "en")
    default_flags = defaults.get("regex_flags", DEFAULT_FLAGS)

    recs_raw = doc.get("recognizers")
    if not isinstance(recs_raw, list) or not recs_raw:
        problems.append("recognizers must be a non-empty list")
        recs_raw = []

    seen_names: set[str] = set()
    recognizers: list[RecognizerSpec] = []
    for i, r in enumerate(recs_raw):
        where = f"recognizers[{i}]"
        if not isinstance(r, dict):
            problems.append(f"{where} must be an object")
            continue
        name = str(r.get("name") or "")
        where = f"recognizer {name or i!r}"
        if not _NAME.match(name):
            problems.append(f"{where}: name must start with a letter, 3-64 letters/digits/_")
        elif name in seen_names:
            problems.append(f"{where}: duplicate name")
        seen_names.add(name)
        entity = str(r.get("entity") or "")
        if not _ENTITY.match(entity):
            problems.append(f"{where}: entity must be UPPER_CASE, e.g. IN_BANK_ACCOUNT")
        enabled = r.get("enabled", True)
        if not isinstance(enabled, bool):
            problems.append(f"{where}: enabled must be true or false")
        flags = r.get("regex_flags", default_flags)
        if not isinstance(flags, list) or any(f not in FLAG_NAMES for f in flags):
            problems.append(f"{where}: regex_flags must be a list of {', '.join(FLAG_NAMES)}")
            flags = DEFAULT_FLAGS
        flags = tuple(flags)
        context = r.get("context") or []
        if not isinstance(context, list) or not all(isinstance(c, str) and c.strip() for c in context):
            problems.append(f"{where}: context must be a list of words")
            context = []

        patterns: list[PatternSpec] = []
        compiled = []
        pnames: set[str] = set()
        for j, p in enumerate(r.get("patterns") or []):
            pwhere = f"{where} pattern {p.get('name', j)!r}" if isinstance(p, dict) else f"{where} pattern {j}"
            if not isinstance(p, dict):
                problems.append(f"{pwhere}: must be an object")
                continue
            pname, regex, score = str(p.get("name") or ""), p.get("regex"), p.get("score")
            if not _PATTERN_NAME.match(pname) or pname in pnames:
                problems.append(f"{pwhere}: name missing, invalid or duplicated")
            pnames.add(pname)
            if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 < score <= 1:
                problems.append(f"{pwhere}: score must be a number above 0 and at most 1")
                score = 0.5
            if not isinstance(regex, str) or not regex:
                problems.append(f"{pwhere}: regex is required")
                continue
            if len(regex) > MAX_REGEX_CHARS:
                problems.append(f"{pwhere}: regex longer than {MAX_REGEX_CHARS} characters")
                continue
            try:
                c = _compile(regex, flags)
            except Exception as exc:  # noqa: BLE001 - re.error and regex.error
                problems.append(f"{pwhere}: regex does not compile: {exc}")
                continue
            if c.search(""):
                problems.append(f"{pwhere}: regex matches empty text")
                continue
            patterns.append(PatternSpec(pname, regex, float(score)))
            compiled.append((pname, c))
        if not patterns and not any(name in pr for pr in problems):
            problems.append(f"{where}: needs at least one pattern")

        # Speed: hostile input must not cause catastrophic backtracking.
        for pname, c in compiled:
            for text in _HOSTILE:
                t0 = time.perf_counter()
                try:
                    _timed_search(c, text, MAX_PATTERN_MS / 1000 * 4)
                except TimeoutError:
                    problems.append(f"{where} pattern {pname!r}: timed out on hostile input "
                                    "(catastrophic backtracking); rewrite the regex")
                    break
                ms = (time.perf_counter() - t0) * 1000
                if ms > MAX_PATTERN_MS:
                    problems.append(f"{where} pattern {pname!r}: took {ms:.0f} ms on hostile input "
                                    f"(limit {MAX_PATTERN_MS} ms); rewrite the regex")
                    break
        if rx is None and compiled:
            warnings.append("speed check skipped: install the 'regex' package to enable it")

        # Declared behaviour: the recognizer's own test samples.
        tests = r.get("tests") or {}
        matches, no_matches = tests.get("match") or [], tests.get("no_match") or []
        if enabled and not matches:
            problems.append(f"{where}: tests.match needs at least one sample the recognizer must find")
        exercised: set[str] = set()
        for sample in matches:
            hits = [pn for pn, c in compiled if c.search(sample)]
            exercised.update(hits)
            if compiled and not hits:
                problems.append(f"{where}: test sample not detected: {sample!r}")
        for sample in no_matches:
            hits = [pn for pn, c in compiled if c.search(sample)]
            if hits:
                problems.append(f"{where}: no_match sample detected by {', '.join(hits)}: {sample!r}")
        untested = [pn for pn, _ in compiled if pn not in exercised]
        if enabled and matches and untested:
            warnings.append(f"{where}: no test sample exercises pattern(s) {', '.join(untested)}")

        canonical = json.dumps({k: v for k, v in r.items()}, sort_keys=True, separators=(",", ":"))
        recognizers.append(RecognizerSpec(
            name=name, entity=entity, patterns=tuple(patterns), context=tuple(context), flags=flags,
            group=str(r.get("group") or ""), description=str(r.get("description") or ""),
            enabled=bool(enabled), raw=canonical,
        ))

    if problems:
        raise RulesError(problems)
    return RuleSet(
        version=version, sha256=hashlib.sha256(data).hexdigest(),
        updated_at=str(doc.get("updated_at") or ""), updated_by=str(doc["updated_by"]),
        change_note=str(doc["change_note"]), language=language,
        recognizers=recognizers, path=path, warnings=warnings,
    )


def load_file(path: str) -> RuleSet:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise RulesError([f"cannot read {path}: {exc}"]) from exc
    return parse(data, path)


def diff(old: RuleSet | None, new: RuleSet) -> dict:
    """Which recognizers were added, removed or changed between two versions."""
    before = {r.name: r.raw for r in (old.recognizers if old else [])}
    after = {r.name: r.raw for r in new.recognizers}
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(n for n in set(before) & set(after) if before[n] != after[n]),
    }


class RuleArchive:
    """Keeps a copy of every version the server has accepted, named <version>__<sha12>.json.

    The archive answers "which exact patterns made this decision?" for any audit
    event, and lets the server refuse a file that reuses an old version string
    for different content.
    """

    def __init__(self, directory: str | None):
        self.directory = directory
        if directory:
            os.makedirs(directory, exist_ok=True)

    def conflict(self, ruleset: RuleSet) -> str | None:
        if not self.directory:
            return None
        prefix = ruleset.version + "__"
        for name in os.listdir(self.directory):
            if name.startswith(prefix) and not name.startswith(prefix + ruleset.sha256[:12]):
                return (f"version {ruleset.version} was already used for different content "
                        f"(archived as {name}); give the new file a new version")
        return None

    def save(self, ruleset: RuleSet, data: bytes) -> str | None:
        if not self.directory:
            return None
        target = os.path.join(self.directory, f"{ruleset.version}__{ruleset.sha256[:12]}.json")
        if not os.path.exists(target):
            tmp = target + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, target)
        return target


class RuleStore:
    """Watches the rules file. poll() reports a new valid version, a rejected one, or nothing."""

    def __init__(self, path: str, archive_dir: str | None = None):
        self.path = path
        self.archive = RuleArchive(archive_dir)
        self._lock = threading.Lock()
        self._stamp: tuple | None = None
        self.current: RuleSet | None = None
        self.last_error: dict | None = None
        self.history: list[dict] = []        # in-memory, newest last; the archive is durable
        self._pending: tuple | None = None

    def _file_stamp(self):
        st = os.stat(self.path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _read(self) -> tuple[RuleSet, bytes]:
        with open(self.path, "rb") as fh:
            data = fh.read()
        try:
            ruleset = parse(data, self.path)
        except RulesError as exc:
            # Name the rejected file in the audit event even though it is invalid.
            exc.sha256 = hashlib.sha256(data).hexdigest()
            try:
                exc.version = str(json.loads(data).get("version") or "") or None
            except Exception:  # noqa: BLE001 - not JSON, or not an object
                exc.version = None
            raise
        problems = []
        if self.current and ruleset.sha256 != self.current.sha256 and ruleset.version == self.current.version:
            problems.append(f"content changed but version is still {ruleset.version}; "
                            "give the new file a new version")
        clash = self.archive.conflict(ruleset)
        if clash:
            problems.append(clash)
        if problems:
            exc = RulesError(problems)
            exc.version, exc.sha256 = ruleset.version, ruleset.sha256
            raise exc
        return ruleset, data

    def load_initial(self) -> RuleSet:
        """First load at start-up. Any problem is fatal: the server must not run without rules."""
        with self._lock:
            ruleset, data = self._read()
            self._stamp = self._file_stamp()
            return self._accept(ruleset, data)

    def poll(self) -> tuple[str, RuleSet | None, dict | None]:
        """("unchanged" | "candidate" | "rejected", ruleset, error).

        A "candidate" is valid but not yet in force: call commit() once the
        engine has built it, or reject() if building failed.
        """
        try:
            stamp = self._file_stamp()
        except OSError as exc:
            problems = [f"cannot read {self.path}: {exc}"]
            if self.last_error and self.last_error["problems"] == problems:
                return "unchanged", None, None      # already reported
            return self._reject_stamp(None, problems)
        if stamp == self._stamp:
            return "unchanged", None, None
        with self._lock:
            if stamp == self._stamp:          # another request handled it
                return "unchanged", None, None
            try:
                ruleset, data = self._read()
            except (RulesError, OSError) as exc:
                problems = exc.problems if isinstance(exc, RulesError) else [str(exc)]
                return self._reject_stamp(stamp, problems, version=getattr(exc, "version", None),
                                          sha256=getattr(exc, "sha256", None))
            if self.current and ruleset.sha256 == self.current.sha256:
                self._stamp = stamp            # touched or re-saved, same content
                return "unchanged", None, None
            self._pending = (stamp, data)
            return "candidate", ruleset, None

    def commit(self, ruleset: RuleSet) -> RuleSet:
        with self._lock:
            stamp, data = self._pending
            self._stamp = stamp
            return self._accept(ruleset, data)

    def reject(self, ruleset: RuleSet, problems: list[str]) -> dict:
        with self._lock:
            stamp, _ = self._pending
            return self._reject_stamp(stamp, problems, version=ruleset.version, sha256=ruleset.sha256)[2]

    def _accept(self, ruleset: RuleSet, data: bytes) -> RuleSet:
        ruleset.loaded_at = datetime.now(timezone.utc).isoformat()
        changes = diff(self.current, ruleset)
        archived = self.archive.save(ruleset, data)
        previous = self.current
        self.current = ruleset
        self.last_error = None
        self.history.append({
            "version": ruleset.version, "sha256": ruleset.sha256, "loaded_at": ruleset.loaded_at,
            "previous_version": previous.version if previous else None, **changes,
        })
        self.history = self.history[-50:]
        ruleset._changes = changes            # type: ignore[attr-defined]
        ruleset._archived = archived          # type: ignore[attr-defined]
        ruleset._previous = previous.version if previous else None  # type: ignore[attr-defined]
        return ruleset

    def _reject_stamp(self, stamp, problems, version=None, sha256=None):
        # Remember the bad file's stamp so it is reported once, not on every request.
        if stamp is not None:
            self._stamp = stamp
        self.last_error = {
            "at": datetime.now(timezone.utc).isoformat(), "problems": problems,
            "rejected_version": version, "rejected_sha256": sha256,
            "in_force_version": self.current.version if self.current else None,
        }
        return "rejected", None, self.last_error
