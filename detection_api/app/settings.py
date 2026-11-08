"""Server configuration.

Resolution order for every setting (highest first):
  1. Process environment variables (Docker/ECS inject these).
  2. For secrets, NAME_FILE pointing to a file that holds the value
     (Docker / Compose secrets mounted at /run/secrets/..., Kubernetes secrets).
  3. A .env file: the path in GOV_ENV_FILE, else ./.env if present. Values in
     the file never override variables already set in the environment.
  4. A documented default, for non-secret tuning values only.

Secrets (GOV_API_TOKEN, GOV_HASH_KEY) have no defaults: the server refuses to
start without them, unless GOV_AUTH_DISABLED=true is set for local development
(which disables the token check only; GOV_HASH_KEY is always required).

On AWS, set GOV_AWS_SECRET_ID instead: both secrets are then read from one AWS
Secrets Manager secret (a JSON object with GOV_API_TOKEN and GOV_HASH_KEY), using
the instance or task role's credentials. Setting the secrets any other way at
the same time is refused, so there is never doubt about which value is in force.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

_TRUE = {"1", "true", "yes", "on"}
_ENV_DIR: str | None = None  # folder of the loaded .env; relative *_FILE paths resolve against it


def parse_env_file(path: str) -> dict[str, str]:
    """Minimal .env parser: KEY=VALUE, optional 'export ', quotes, # comments."""
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            elif " #" in value:
                value = value.split(" #", 1)[0].rstrip()
            values[key] = value
    return values


def load_env_file() -> str | None:
    global _ENV_DIR
    path = os.getenv("GOV_ENV_FILE") or (".env" if os.path.isfile(".env") else "")
    if not path:
        return None
    if not os.path.isfile(path):
        raise RuntimeError(f"GOV_ENV_FILE points to a missing file: {path}")
    for key, value in parse_env_file(path).items():
        os.environ.setdefault(key, value)
    _ENV_DIR = os.path.dirname(os.path.abspath(path))
    return path


def _get(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _secret(name: str) -> str | None:
    path = _get(f"{name}_FILE")
    if path and not os.path.isabs(path) and _ENV_DIR:
        path = os.path.join(_ENV_DIR, path)
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip() or None
        except OSError as exc:
            raise RuntimeError(f"{name}_FILE could not be read: {path} ({exc})") from exc
    return _get(name)


def _resolve_path(path: str | None) -> str | None:
    """Relative paths resolve against the loaded .env file's folder."""
    if path and not os.path.isabs(path) and _ENV_DIR:
        return os.path.join(_ENV_DIR, path)
    return path


def _int(name: str, default: int) -> int:
    raw = _get(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


AUTH_MODES = ("token", "token+oidc", "oidc")


def _list(name: str, default: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in (_get(name, default) or "").split(",") if x.strip())


def load_aws_secret(secret_id: str, region: str | None) -> tuple[dict[str, str], list[str]]:
    """Read GOV_API_TOKEN / GOV_HASH_KEY from one Secrets Manager secret.

    Credentials come from boto3's default chain: on EC2 the instance profile
    role, on ECS the task role, on a laptop an `aws sso login` profile. Long-term
    IAM user keys work but are flagged, because they don't expire.
    """
    warnings = []
    key_id = os.getenv("AWS_ACCESS_KEY_ID", "")
    if key_id.startswith("AKIA"):
        warnings.append("AWS credentials are long-term IAM user keys (AKIA...). Use an EC2 instance "
                        "profile or ECS task role instead; see docs/detection-api.md")
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:
        raise RuntimeError("GOV_AWS_SECRET_ID is set but boto3 is not installed (pip install boto3)") from exc
    try:
        client = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
        raw = client.get_secret_value(SecretId=secret_id)["SecretString"]
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Cannot read AWS Secrets Manager secret {secret_id!r}: {exc}") from exc
    except KeyError as exc:
        raise RuntimeError(f"Secret {secret_id!r} has no SecretString (binary secrets are not supported)") from exc
    try:
        values = json.loads(raw)
        assert isinstance(values, dict)
    except (ValueError, AssertionError) as exc:
        raise RuntimeError(f"Secret {secret_id!r} must be a JSON object with GOV_API_TOKEN and "
                           "GOV_HASH_KEY") from exc
    return {k: str(v) for k, v in values.items()
            if k in ("GOV_API_TOKEN", "GOV_API_TOKEN_PREVIOUS", "GOV_HASH_KEY")}, warnings


@dataclass(frozen=True)
class Settings:
    api_token: str | None
    auth_disabled: bool
    auth_mode: str
    hash_key: bytes
    policy_path: str
    recognizers_path: str
    rules_archive_dir: str | None
    nlp_model: str
    chunk_chars: int
    max_text_chars: int
    max_pdf_ocr_pages: int
    cache_size: int
    environment: str
    otlp_endpoint: str | None
    otel_service_name: str
    host: str
    port: int
    workers: int
    log_level: str
    audit_file: str | None
    secrets_source: str = "environment"
    api_token_previous: str | None = None   # accepted too, during a token rotation
    oidc_issuer: str | None = None
    oidc_audience: tuple[str, ...] = ()
    oidc_jwks_url: str | None = None
    oidc_algorithms: tuple[str, ...] = ("RS256",)
    oidc_user_claims: tuple[str, ...] = ("preferred_username", "upn", "unique_name", "email")
    oidc_id_claims: tuple[str, ...] = ("oid", "sub")
    identity_mismatch: str = "log"
    warnings: tuple[str, ...] = field(default_factory=tuple)


def load_settings() -> Settings:
    env_file = load_env_file()
    auth_disabled = (_get("GOV_AUTH_DISABLED", "false") or "").lower() in _TRUE
    auth_mode = (_get("GOV_AUTH_MODE", "token") or "").lower()
    problems: list[str] = []
    warnings: list[str] = []
    secrets_source = "environment"

    aws_secret_id = _get("GOV_AWS_SECRET_ID")
    if aws_secret_id:
        clash = [n for n in ("GOV_API_TOKEN", "GOV_API_TOKEN_FILE", "GOV_HASH_KEY", "GOV_HASH_KEY_FILE",
                             "GOV_API_TOKEN_PREVIOUS", "GOV_API_TOKEN_PREVIOUS_FILE") if _get(n)]
        if clash:
            raise RuntimeError("Configuration error: GOV_AWS_SECRET_ID is set, so remove "
                               + ", ".join(clash) + " (secrets must come from one place)")
        values, aws_warnings = load_aws_secret(aws_secret_id, _get("GOV_AWS_REGION") or _get("AWS_REGION"))
        warnings.extend(aws_warnings)
        token, hash_key = values.get("GOV_API_TOKEN"), values.get("GOV_HASH_KEY")
        previous = values.get("GOV_API_TOKEN_PREVIOUS")
        secrets_source = "aws-secrets-manager"
    else:
        token = _secret("GOV_API_TOKEN")
        hash_key = _secret("GOV_HASH_KEY")
        previous = _secret("GOV_API_TOKEN_PREVIOUS")
    if previous and len(previous) < 16:
        problems.append("GOV_API_TOKEN_PREVIOUS must be at least 16 characters")
    if previous:
        warnings.append("GOV_API_TOKEN_PREVIOUS is set: the old API token is still accepted. "
                        "Remove it once every device has the new token.")

    if auth_mode not in AUTH_MODES:
        problems.append(f"GOV_AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got {auth_mode!r}")
    needs_token = auth_mode in ("token", "token+oidc")
    if needs_token and not token and not auth_disabled:
        problems.append("GOV_API_TOKEN (or GOV_API_TOKEN_FILE) is not set; "
                        "set GOV_AUTH_DISABLED=true only for local development")
    if token and len(token) < 16:
        problems.append("GOV_API_TOKEN must be at least 16 characters")
    if not hash_key:
        problems.append("GOV_HASH_KEY (or GOV_HASH_KEY_FILE) is not set")
    elif len(hash_key) < 16:
        problems.append("GOV_HASH_KEY must be at least 16 characters")

    oidc = {}
    if "oidc" in auth_mode:
        if auth_disabled:
            problems.append("GOV_AUTH_DISABLED=true cannot be combined with GOV_AUTH_MODE=" + auth_mode)
        oidc = {
            "oidc_issuer": _get("GOV_OIDC_ISSUER"),
            "oidc_audience": _list("GOV_OIDC_AUDIENCE", ""),
            "oidc_jwks_url": _get("GOV_OIDC_JWKS_URL"),
            "oidc_algorithms": _list("GOV_OIDC_ALGORITHMS", "RS256"),
            "oidc_user_claims": _list("GOV_OIDC_USER_CLAIMS", "preferred_username,upn,unique_name,email"),
            "oidc_id_claims": _list("GOV_OIDC_ID_CLAIMS", "oid,sub"),
            "identity_mismatch": (_get("GOV_IDENTITY_MISMATCH", "log") or "").lower(),
        }
        for key, name in (("oidc_issuer", "GOV_OIDC_ISSUER"), ("oidc_audience", "GOV_OIDC_AUDIENCE"),
                          ("oidc_jwks_url", "GOV_OIDC_JWKS_URL")):
            if not oidc[key]:
                problems.append(f"{name} is required for GOV_AUTH_MODE={auth_mode}")
        jwks = oidc["oidc_jwks_url"] or ""
        host = jwks.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if jwks and not (jwks.startswith("https://") or
                         (jwks.startswith("http://") and host in ("127.0.0.1", "localhost", "::1"))):
            problems.append("GOV_OIDC_JWKS_URL must be https:// (http:// only for a loopback test server)")
        if any(a.upper().startswith("HS") or a.lower() == "none" for a in oidc["oidc_algorithms"]):
            problems.append("GOV_OIDC_ALGORITHMS must be asymmetric (e.g. RS256); HS* and none are refused")
        if oidc["identity_mismatch"] not in ("log", "block"):
            problems.append("GOV_IDENTITY_MISMATCH must be log or block")

    if problems:
        where = f" (also checked {env_file})" if env_file else ""
        raise RuntimeError("Configuration error" + where + ":\n  - " + "\n  - ".join(problems))

    here = os.path.dirname(os.path.abspath(__file__))
    return Settings(
        api_token=token,
        auth_disabled=auth_disabled,
        auth_mode=auth_mode,
        hash_key=hash_key.encode(),
        policy_path=os.path.abspath(_get("GOV_POLICY_PATH", os.path.join(here, "..", "policy.yaml"))),
        recognizers_path=os.path.abspath(_resolve_path(_get("GOV_RECOGNIZERS_PATH"))
                                         or os.path.join(here, "..", "rules", "recognizers.json")),
        rules_archive_dir=_resolve_path(_get("GOV_RULES_ARCHIVE_DIR")),
        nlp_model=_get("GOV_NLP_MODEL", "en_core_web_lg"),
        chunk_chars=_int("GOV_CHUNK_CHARS", 100_000),
        max_text_chars=_int("GOV_MAX_TEXT_CHARS", 2_000_000),
        max_pdf_ocr_pages=_int("GOV_MAX_PDF_OCR_PAGES", 10),
        cache_size=_int("GOV_CACHE_SIZE", 4096),
        environment=_get("GOV_ENVIRONMENT", "local"),
        otlp_endpoint=_get("OTEL_EXPORTER_OTLP_ENDPOINT"),
        otel_service_name=_get("OTEL_SERVICE_NAME", "ai-governance-detection"),
        host=_get("GOV_HOST", "127.0.0.1"),
        port=_int("GOV_PORT", 8088),
        workers=_int("GOV_WORKERS", 2),
        log_level=_get("GOV_LOG_LEVEL", "info"),
        audit_file=_resolve_path(_get("GOV_AUDIT_FILE")),
        secrets_source=secrets_source,
        api_token_previous=previous,
        warnings=tuple(warnings),
        **oidc,
    )
