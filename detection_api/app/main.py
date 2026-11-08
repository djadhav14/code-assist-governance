"""AI coding-assistant governance: detection and policy API.

Endpoints
  GET  /healthz          liveness plus loaded policy version and model
  POST /v1/scan          scan text (prompt, tool input, tool output)
  POST /v1/scan-batch    scan several texts as one decision (e.g. fields of a tool output)
  POST /v1/scan-file     scan a file's bytes (text, PDF, image) with path rules
  GET  /v1/rules         detection rules version in force, its recognizers, last rejection

Every decision is logged as a governance.decision event (see audit.py) that names
the rules version and policy version it was made under. A changed rules file is
logged as governance.rules_loaded or governance.rules_rejected.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import audit
from . import policy as pol
from . import rules as rl
from .engine import Engine, Finding, b64decode
from .identity import Authenticator, Identity, same_person
from .settings import Settings, load_settings

# Fail at import time (before serving any request) if configuration is incomplete.
settings: Settings = load_settings()

app = FastAPI(title="AI Governance Detection API", version="0.7.0")
engine: Engine | None = None
policies: pol.PolicyStore | None = None
rules: rl.RuleStore | None = None

Channel = Literal["prompt", "attachment", "file_read", "tool_input", "tool_output", "command"]


class Context(BaseModel):
    user: str = Field("unknown", description="User identity, e.g. Entra UPN or OS user")
    host: str = ""
    device_id: str = ""
    agent: str = Field("unknown", description="claude-code | kiro-ide | gateway")
    hook_event: str = ""
    session_id: str = ""
    tool_name: str = ""
    cwd: str = ""
    justification: str = ""


class ScanRequest(Context):
    text: str
    channel: Channel = "prompt"


class ScanBatchRequest(Context):
    texts: list[str]
    channel: Channel = "tool_output"


class ScanFileRequest(Context):
    file_path: str
    content_b64: str | None = None
    channel: Channel = "file_read"


class FindingOut(BaseModel):
    entity: str
    score: float
    action: str
    policy_source: str
    value_hash: str
    start: int
    end: int


class ScanResponse(BaseModel):
    decision: Literal["allow", "mask", "pseudonymize", "warn", "warn_allow", "block"]
    reason: str
    findings: list[FindingOut]
    redacted_text: str | None = None
    redacted_texts: list[str] | None = None
    redacted_image_b64: str | None = None
    extraction: str | None = None
    event_id: str
    latency_ms: int


authenticator = Authenticator(settings)
_logger = logging.getLogger("uvicorn.error")


def require_auth(x_gov_token: str = Header(default=""), authorization: str = Header(default="")) -> Identity:
    """Shared token and/or verified user access token, per GOV_AUTH_MODE (see identity.py).
    The shared token is compared in constant time."""
    return authenticator(x_gov_token, authorization)


def _with_identity(req, ident: Identity):
    """Use the verified user for policy and audit; keep the desktop name as user.claimed."""
    claimed = req.user
    fields = {"user.claimed": claimed, "user.verified": ident.verified}
    if not ident.verified:
        return req, fields
    mismatch = not same_person(claimed, ident.user)
    fields.update({"user.subject_id": ident.subject_id, "identity.mismatch": mismatch})
    if mismatch and settings.identity_mismatch == "block":
        audit.emit({"user.id": ident.user, **fields, "host.name": req.host, "agent": req.agent,
                    "decision": "block", "reason": "desktop user does not match signed-in account"},
                   name="governance.identity_mismatch")
        raise HTTPException(status_code=403, detail=f"desktop user {claimed!r} does not match "
                                                    f"signed-in account {ident.user!r}")
    return req.model_copy(update={"user": ident.user}), fields


@app.on_event("startup")
def _startup():
    global engine, policies, rules
    audit.init_otel(settings)
    audit.init_file(settings)
    for w in settings.warnings:
        _logger.warning(w)
    _logger.info("auth mode %s, secrets from %s%s", settings.auth_mode, settings.secrets_source,
                   f", OIDC issuer {settings.oidc_issuer}" if "oidc" in settings.auth_mode else "")
    policies = pol.PolicyStore(settings.policy_path, on_rejected=_policy_rejected)
    rules = rl.RuleStore(settings.recognizers_path, settings.rules_archive_dir)
    try:
        ruleset = rules.load_initial()
    except (rl.RulesError, OSError) as exc:
        # Fail closed: without valid rules the server must not answer "allow".
        problems = exc.problems if isinstance(exc, rl.RulesError) else [str(exc)]
        audit.emit({"rules.path": settings.recognizers_path, "rules.problems": problems},
                   name="governance.rules_rejected")
        raise RuntimeError("Detection rules rejected, server not started:\n  - "
                           + "\n  - ".join(problems)) from exc
    t0 = time.perf_counter()
    engine = Engine(settings, ruleset)
    _rules_loaded(ruleset, int((time.perf_counter() - t0) * 1000))


def _policy_rejected(problem: str, in_force_version) -> None:
    """A bad policy.yaml edit: the previous policy stays in force (fail safe, not fail open)."""
    _logger.error("policy.yaml rejected, version %s stays in force: %s", in_force_version, problem)
    audit.emit({"policy.path": settings.policy_path, "policy.problem": problem,
                "policy.in_force_version": in_force_version, "process.pid": os.getpid()},
               name="governance.policy_rejected")


def _policy_warnings(ruleset: rl.RuleSet) -> list[str]:
    """Entities in the rules file that policy.yaml doesn't mention fall back to default_action."""
    p = policies.reload_if_changed()
    missing = sorted({r.entity for r in ruleset.enabled} - set(p.entities))
    return [f"no policy.yaml rule for {', '.join(missing)}: default_action {p.default_action!r} applies"] if missing else []


def _rules_loaded(ruleset: rl.RuleSet, build_ms: int) -> None:
    ruleset.warnings = ruleset.warnings + _policy_warnings(ruleset)
    changes = getattr(ruleset, "_changes", {})
    audit.emit({
        "rules.version": ruleset.version, "rules.sha256": ruleset.sha256,
        "rules.previous_version": getattr(ruleset, "_previous", None),
        "rules.updated_by": ruleset.updated_by, "rules.updated_at": ruleset.updated_at,
        "rules.change_note": ruleset.change_note,
        "rules.added": changes.get("added"), "rules.removed": changes.get("removed"),
        "rules.changed": changes.get("changed"),
        "rules.recognizers": len(ruleset.enabled), "rules.warnings": ruleset.warnings,
        "rules.archived_as": os.path.basename(getattr(ruleset, "_archived", None) or "") or None,
        "rules.path": ruleset.path,
        "process.pid": os.getpid(),    # each server worker loads the file itself
        "rules.build_ms": build_ms,
    }, name="governance.rules_loaded")


def _refresh_rules() -> None:
    """Called on every request: one stat() call unless the rules file changed."""
    status, ruleset, error = rules.poll()
    if status == "candidate":
        t0 = time.perf_counter()
        try:
            engine.apply_rules(ruleset)
        except rl.RulesError as exc:
            error = rules.reject(ruleset, exc.problems)
            status = "rejected"
        else:
            _rules_loaded(rules.commit(ruleset), int((time.perf_counter() - t0) * 1000))
            return
    if status == "rejected":
        audit.emit({
            "rules.path": settings.recognizers_path, "rules.problems": error["problems"],
            "rules.version": error.get("rejected_version"), "rules.sha256": error.get("rejected_sha256"),
            "rules.in_force_version": error["in_force_version"],
            "process.pid": os.getpid(),
        }, name="governance.rules_rejected")


@app.get("/healthz")
def healthz():
    p = policies.reload_if_changed()
    _refresh_rules()
    return {
        "status": "ok",
        "policy_version": p.version,
        "rules_version": engine.rules_version,
        "rules_last_error": bool(rules.last_error),
        "policy_last_error": bool(policies.last_error),
        "nlp_model": settings.nlp_model,
        "auth": "disabled" if settings.auth_disabled else settings.auth_mode,
        "secrets_source": settings.secrets_source,
        "entities": engine.supported_entities,
    }


@app.get("/v1/rules", dependencies=[Depends(require_auth)])
def rules_info():
    """Which detection rules are in force, and the last rejected file, if any."""
    _refresh_rules()
    current = rules.current
    return {
        **current.summary(),
        "recognizers": [
            {"name": r.name, "entity": r.entity, "group": r.group, "enabled": r.enabled,
             "description": r.description, "patterns": [p.name for p in r.patterns],
             "context": list(r.context)}
            for r in current.recognizers
        ],
        "builtin_recognizers": sorted(engine.builtin_names),
        "last_error": rules.last_error,
        "history": rules.history,
        "policy_version": policies.reload_if_changed().version,
        "policy_last_error": policies.last_error,
    }


def _summarise(findings: list[Finding]) -> dict:
    by_entity: dict[str, int] = {}
    for f in findings:
        by_entity[f.entity] = by_entity.get(f.entity, 0) + 1
    return by_entity


def _decide(findings: list[Finding], channel: str, justification: str) -> tuple[str, str]:
    decision = pol.overall([f.action for f in findings])
    found = _summarise([f for f in findings if f.action == decision]) if findings else {}
    names = ", ".join(f"{k} x{v}" for k, v in sorted(found.items()))
    if decision == "allow":
        return "allow", "no restricted data found" if not findings else "only allowed entities found"
    if decision == "warn":
        if channel != "prompt":
            return "warn_allow", f"allowed and logged: {names}"
        if justification.strip():
            return "warn_allow", f"allowed with user justification: {names}"
        return "warn", f"justification required for: {names}"
    return decision, f"{decision}: {names}"


def _safe_justification(text: str) -> str | None:
    """The justification is free text typed by the user, so it can itself contain PII.
    Mask every finding in it before it reaches any log."""
    if not text:
        return None
    found = engine.scan_text(text, policies.reload_if_changed(), "prompt", "")
    if not found:
        return text
    for f in found:
        f.action = "mask"
    return engine.redact(text, found)


def _log(req: Context, channel: str, decision: str, reason: str, findings, latency_ms: int, **extra):
    return audit.emit(
        {
            "user.id": req.user,
            "host.name": req.host,
            "device.id": req.device_id,
            "agent": req.agent,
            "hook.event": req.hook_event,
            "session.id": req.session_id,
            "tool.name": req.tool_name,
            "channel": channel,
            "decision": decision,
            "reason": reason,
            "justification": _safe_justification(req.justification),
            "data_classes": sorted({f.entity for f in findings}),
            "policy_sources": sorted({f.policy_source for f in findings}),
            "findings": [
                {"entity": f.entity, "score": f.score, "action": f.action,
                 "policy_source": f.policy_source, "value_hash": f.value_hash,
                 "recognizer": f.recognizer, "pattern": f.pattern}
                for f in findings
            ],
            "rules.version": engine.rules_version,
            "policy.version": policies.reload_if_changed().version,
            "latency_ms": latency_ms,
            **extra,
        }
    )


def _out(findings: list[Finding]) -> list[FindingOut]:
    return [
        FindingOut(entity=f.entity, score=f.score, action=f.action, policy_source=f.policy_source,
                   value_hash=f.value_hash, start=f.start, end=f.end)
        for f in findings
    ]


@app.post("/v1/scan", response_model=ScanResponse)
def scan(req: ScanRequest, ident: Identity = Depends(require_auth)):
    t0 = time.perf_counter()
    req, who = _with_identity(req, ident)
    _refresh_rules()
    p = policies.reload_if_changed()
    findings = engine.scan_text(req.text, p, req.channel, req.user)
    decision, reason = _decide(findings, req.channel, req.justification)
    redacted = engine.redact(req.text, findings) if findings else req.text
    ms = int((time.perf_counter() - t0) * 1000)
    event_id = _log(req, req.channel, decision, reason, findings, ms, **{"text.length": len(req.text)}, **who)
    return ScanResponse(decision=decision, reason=reason, findings=_out(findings),
                        redacted_text=redacted, event_id=event_id, latency_ms=ms)


@app.post("/v1/scan-batch", response_model=ScanResponse)
def scan_batch(req: ScanBatchRequest, ident: Identity = Depends(require_auth)):
    t0 = time.perf_counter()
    req, who = _with_identity(req, ident)
    _refresh_rules()
    p = policies.reload_if_changed()
    all_findings: list[Finding] = []
    redacted: list[str] = []
    for text in req.texts:
        f = engine.scan_text(text, p, req.channel, req.user)
        all_findings.extend(f)
        redacted.append(engine.redact(text, f) if f else text)
    decision, reason = _decide(all_findings, req.channel, req.justification)
    ms = int((time.perf_counter() - t0) * 1000)
    event_id = _log(req, req.channel, decision, reason, all_findings, ms, **{"batch.size": len(req.texts)}, **who)
    return ScanResponse(decision=decision, reason=reason, findings=_out(all_findings),
                        redacted_texts=redacted, event_id=event_id, latency_ms=ms)


@app.post("/v1/scan-file", response_model=ScanResponse)
def scan_file(req: ScanFileRequest, ident: Identity = Depends(require_auth)):
    t0 = time.perf_counter()
    req, who = _with_identity(req, ident)
    _refresh_rules()
    p = policies.reload_if_changed()
    extra = {"file.path": req.file_path}

    glob = pol.path_blocked(p, req.file_path)
    if glob:
        reason = f"block: path matches restricted pattern {glob}"
        ms = int((time.perf_counter() - t0) * 1000)
        eid = _log(req, req.channel, "block", reason, [], ms, **extra, **{"path_rule": glob}, **who)
        return ScanResponse(decision="block", reason=reason, findings=[], event_id=eid, latency_ms=ms)

    if req.content_b64 is None:
        ms = int((time.perf_counter() - t0) * 1000)
        eid = _log(req, req.channel, "allow", "path allowed; no content supplied", [], ms, **extra, **who)
        return ScanResponse(decision="allow", reason="path allowed; no content supplied",
                            findings=[], event_id=eid, latency_ms=ms)

    data = b64decode(req.content_b64)
    ext = os.path.splitext(req.file_path.lower())[1]

    if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}:
        findings, redacted_png = engine.scan_image(data, p, "attachment", req.user)
        decision, reason = _decide(findings, req.channel, req.justification)
        ms = int((time.perf_counter() - t0) * 1000)
        eid = _log(req, req.channel, decision, reason, findings, ms, **extra, **{"extraction": "ocr"}, **who)
        return ScanResponse(
            decision=decision, reason=reason, findings=_out(findings), extraction="ocr",
            redacted_image_b64=base64.b64encode(redacted_png).decode() if redacted_png else None,
            event_id=eid, latency_ms=ms,
        )

    text, method = engine.extract_text(req.file_path, data)
    extra["extraction"] = method
    if text is None:
        action = p.unscannable_action
        decision = "warn_allow" if action == "warn" else action
        reason = f"{decision}: file could not be scanned ({method})"
        ms = int((time.perf_counter() - t0) * 1000)
        eid = _log(req, req.channel, decision, reason, [], ms, **extra, **who)
        return ScanResponse(decision=decision, reason=reason, findings=[], extraction=method,
                            event_id=eid, latency_ms=ms)

    # PDFs and images are attachments; NER-heavy entities (PERSON) apply to them.
    channel = "attachment" if method.startswith("pdf") else req.channel
    findings = engine.scan_text(text, p, channel, req.user)
    decision, reason = _decide(findings, req.channel, req.justification)
    redacted = engine.redact(text, findings) if findings else None
    ms = int((time.perf_counter() - t0) * 1000)
    eid = _log(req, req.channel, decision, reason, findings, ms, **extra, **{"text.length": len(text)}, **who)
    return ScanResponse(decision=decision, reason=reason, findings=_out(findings),
                        redacted_text=redacted, extraction=method, event_id=eid, latency_ms=ms)
