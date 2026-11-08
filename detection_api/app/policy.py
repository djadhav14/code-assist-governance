"""Policy loading and decision logic.

The policy file is re-read whenever its modification time changes, so admins
can edit policy.yaml (or a mounted copy) without restarting the service.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import os
import threading
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import yaml

SEVERITY = {"allow": 0, "mask": 1, "pseudonymize": 2, "warn": 3, "block": 4}
VALID_ACTIONS = set(SEVERITY)


@dataclass
class EntityRule:
    action: str
    min_score: float | None = None
    channels: list[str] | None = None


@dataclass
class Policy:
    version: int = 1
    score_threshold: float = 0.5
    default_action: str = "allow"
    entities: dict[str, EntityRule] = field(default_factory=dict)
    disabled_entities: list[str] = field(default_factory=list)
    block_globs: list[str] = field(default_factory=list)
    allow_globs: list[str] = field(default_factory=list)
    user_overrides: list[dict] = field(default_factory=list)
    unscannable_action: str = "warn"


def _parse(raw: dict) -> Policy:
    entities = {}
    for name, rule in (raw.get("entities") or {}).items():
        if isinstance(rule, str):
            rule = {"action": rule}
        action = rule.get("action", "allow")
        if action not in VALID_ACTIONS:
            raise ValueError(f"policy: entity {name} has invalid action {action!r}")
        entities[name] = EntityRule(
            action=action,
            min_score=rule.get("min_score"),
            channels=rule.get("channels"),
        )
    default_action = raw.get("default_action", "allow")
    if default_action not in VALID_ACTIONS:
        raise ValueError(f"policy: invalid default_action {default_action!r}")
    for o in raw.get("user_overrides") or []:
        if o.get("action") not in VALID_ACTIONS:
            raise ValueError(f"policy: override for {o.get('user')} has invalid action")
        for key in ("user", "entity", "reason", "approved_by", "expires"):
            if not o.get(key):
                raise ValueError(f"policy: override is missing required field {key!r}")
    path_rules = raw.get("path_rules") or {}
    return Policy(
        version=raw.get("version", 1),
        score_threshold=float(raw.get("score_threshold", 0.5)),
        default_action=default_action,
        entities=entities,
        disabled_entities=list(raw.get("disabled_entities") or []),
        block_globs=list(path_rules.get("block_globs") or []),
        allow_globs=list(path_rules.get("allow_globs") or []),
        user_overrides=list(raw.get("user_overrides") or []),
        unscannable_action=raw.get("unscannable_action", "warn"),
    )


class PolicyStore:
    """Watches policy.yaml and reloads it on change.

    A bad edit (YAML error, unknown action, missing field, file deleted) never
    takes the service down: the previous policy stays in force, the problem is
    recorded in last_error, and on_rejected(error) is called once per bad
    version so it can be logged for the SOC. At start-up there is no previous
    policy, so a bad file is fatal (fail closed).
    """

    def __init__(self, path: str, on_rejected=None):
        self.path = path
        self._lock = threading.Lock()
        self._stamp = None
        self._policy: Policy | None = None
        self.last_error: str | None = None
        self.on_rejected = on_rejected
        self.reload_if_changed()

    def _file_stamp(self):
        st = os.stat(self.path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def reload_if_changed(self) -> Policy:
        try:
            stamp = self._file_stamp()
        except OSError as exc:
            stamp, problem = None, f"policy file not readable: {self.path} ({exc})"
        else:
            problem = None
        with self._lock:
            if problem is None and stamp == self._stamp:
                return self._policy
            if problem is None:
                try:
                    with open(self.path, encoding="utf-8") as fh:
                        policy = _parse(yaml.safe_load(fh) or {})
                except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
                    problem = f"{type(exc).__name__}: {exc}"
                else:
                    self._policy, self._stamp, self.last_error = policy, stamp, None
                    return policy
            if self._policy is None:          # start-up: never run without a policy
                raise RuntimeError(f"policy rejected, server not started: {problem}")
            if problem != self.last_error:    # report each distinct problem once
                self.last_error = problem
                if self.on_rejected:
                    self.on_rejected(problem, self._policy.version)
            if stamp is not None:
                self._stamp = stamp
            return self._policy


def _glob_match(path: str, pattern: str) -> bool:
    p = path.replace("\\", "/")
    # fnmatch's * already crosses "/", so "**/" is reduced to "*" and we also try
    # the pattern without its leading "**/" so that "**/.env" matches ".env".
    candidates = {pattern, pattern.replace("**/", "*"), pattern.replace("**/", "")}
    name = PurePosixPath(p).name
    return any(fnmatch.fnmatch(p, c) or fnmatch.fnmatch(name, c) for c in candidates)


def path_blocked(policy: Policy, path: str | None) -> str | None:
    """Return the matching block glob, or None if the path is not blocked."""
    if not path:
        return None
    if any(_glob_match(path, g) for g in policy.allow_globs):
        return None
    for g in policy.block_globs:
        if _glob_match(path, g):
            return g
    return None


def _active_override(policy: Policy, user: str, entity: str) -> dict | None:
    today = dt.date.today()
    for o in policy.user_overrides:
        if o["user"].lower() != (user or "").lower() or o["entity"] != entity:
            continue
        try:
            expires = dt.date.fromisoformat(str(o["expires"]))
        except ValueError:
            continue
        if expires >= today:
            return o
    return None


def resolve(policy: Policy, entity: str, score: float, channel: str, user: str):
    """Return (action, policy_source) for one finding, or None if it is ignored."""
    rule = policy.entities.get(entity)
    threshold = rule.min_score if rule and rule.min_score is not None else policy.score_threshold
    if score < threshold:
        return None
    if rule and rule.channels and channel not in rule.channels:
        return None
    action = rule.action if rule else policy.default_action
    source = "admin"
    override = _active_override(policy, user, entity)
    if override:
        action, source = override["action"], "user_override"
    return action, source


def overall(actions: list[str]) -> str:
    return max(actions, key=SEVERITY.__getitem__) if actions else "allow"
