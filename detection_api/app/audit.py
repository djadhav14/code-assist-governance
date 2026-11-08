"""Decision events: JSON lines on stdout plus OpenTelemetry logs when configured.

Raw matched values are never logged. Each finding carries a keyed hash of the
value instead, so repeated leaks of the same value can be correlated.

Three sinks:
  * stdout: one JSON line per decision (container logs).
  * OpenTelemetry logs, when OTEL_EXPORTER_OTLP_ENDPOINT is set
    (e.g. http://otel-collector:4318).
  * An audit file, when GOV_AUDIT_FILE is set: one *flat* JSON object per line,
    all fields under a top-level "governance" key and lists joined into
    comma-separated strings. That shape is what Wazuh's built-in JSON decoder
    (and most log shippers) handle best; see siem/wazuh/.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

_stdout = logging.getLogger("governance.stdout")
_stdout.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("%(message)s"))
_stdout.addHandler(_h)
_stdout.propagate = False

_otel = logging.getLogger("governance.decision")
_otel.setLevel(logging.INFO)
_otel.propagate = False
_otel_enabled = False

_file = logging.getLogger("governance.file")
_file.setLevel(logging.INFO)
_file.propagate = False
_file_enabled = False


def init_file(settings) -> None:
    """Append flat JSON lines to GOV_AUDIT_FILE. WatchedFileHandler reopens the file
    if logrotate moves it, so rotation can be handled outside the server."""
    global _file_enabled
    if not settings.audit_file or _file_enabled:
        return
    from logging.handlers import WatchedFileHandler

    os.makedirs(os.path.dirname(os.path.abspath(settings.audit_file)), exist_ok=True)
    handler = WatchedFileHandler(settings.audit_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _file.addHandler(handler)
    _file_enabled = True


def init_otel(settings) -> None:
    global _otel_enabled
    endpoint = settings.otlp_endpoint
    if not endpoint or _otel_enabled:
        return
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource

    provider = LoggerProvider(
        resource=Resource.create(
            {
                "service.name": settings.otel_service_name,
                "deployment.environment": settings.environment,
            }
        )
    )
    provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter(endpoint=endpoint.rstrip("/") + "/v1/logs"))
    )
    _otel.addHandler(LoggingHandler(level=logging.INFO, logger_provider=provider))
    _otel_enabled = True


def _flatten(event: dict) -> dict:
    """OTel attributes must be primitives or lists of primitives."""
    flat = {}
    for k, v in event.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            flat[k] = v
        elif isinstance(v, list) and all(isinstance(i, (str, int, float, bool)) for i in v):
            flat[k] = v
        else:
            flat[k] = json.dumps(v, separators=(",", ":"))
    return flat


_FILE_KEYS = {  # event key -> flat key under "governance"
    "event.name": "event", "event.id": "event_id", "timestamp": "timestamp",
    "user.id": "user_id", "user.claimed": "user_claimed", "user.verified": "user_verified",
    "user.subject_id": "user_subject_id", "identity.mismatch": "identity_mismatch",
    "host.name": "host_name", "device.id": "device_id", "agent": "agent",
    "hook.event": "hook_event", "session.id": "session_id", "tool.name": "tool_name",
    "channel": "channel", "decision": "decision", "reason": "reason", "justification": "justification",
    "file.path": "file_path", "path_rule": "path_rule", "extraction": "extraction",
    "text.length": "text_length", "batch.size": "batch_size", "latency_ms": "latency_ms",
    "rules.version": "rules_version", "policy.version": "policy_version",
    # governance.rules_loaded / governance.rules_rejected
    "rules.sha256": "rules_sha256", "rules.previous_version": "rules_previous_version",
    "rules.updated_by": "rules_updated_by", "rules.change_note": "rules_change_note",
    "rules.archived_as": "rules_archived_as", "rules.problems": "rules_problems",
    "rules.in_force_version": "rules_in_force_version", "rules.warnings": "rules_warnings",
    "rules.path": "rules_path", "rules.updated_at": "rules_updated_at",
    "policy.path": "policy_path", "policy.problem": "policy_problem",
    "policy.in_force_version": "policy_in_force_version",
    "rules.recognizers": "rules_recognizer_count", "process.pid": "process_pid", "rules.build_ms": "rules_build_ms",
    "rules.added": "rules_added", "rules.removed": "rules_removed", "rules.changed": "rules_changed",
}


def flat_record(event: dict) -> dict:
    """One-level record for line-based SIEM ingestion (no arrays, no dotted keys)."""
    g = {}
    for old, new in _FILE_KEYS.items():
        value = event.get(old)
        if value in (None, "", []):
            continue
        g[new] = "; ".join(map(str, value)) if isinstance(value, list) else value
    if event.get("event.name") != "governance.decision":
        return {"governance": g}
    findings = event.get("findings") or []
    g["finding_count"] = len(findings)
    g["data_classes"] = ",".join(event.get("data_classes") or [])
    g["policy_sources"] = ",".join(event.get("policy_sources") or [])
    g["actions"] = ",".join(sorted({f["action"] for f in findings}))
    g["value_hashes"] = ",".join(f["value_hash"] for f in findings)
    g["patterns"] = ",".join(sorted({f"{f.get('recognizer', '')}.{f['pattern']}" for f in findings if f.get("pattern")}))
    return {"governance": g}


def emit(event: dict, name: str = "governance.decision") -> str:
    """name: governance.decision, or governance.rules_loaded / governance.rules_rejected
    when the detection rules file changes."""
    event = {
        "event.name": name,
        "event.id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    _stdout.info(json.dumps(event, separators=(",", ":")))
    if _otel_enabled:
        _otel.info(name, extra=_flatten(event))
    if _file_enabled:
        _file.info(json.dumps(flat_record(event), separators=(",", ":")))
    return event["event.id"]
