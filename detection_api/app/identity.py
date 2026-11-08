"""Who is calling: the shared API token, and optionally a verified user identity.

GOV_AUTH_MODE decides what a request must present:

  token        X-Gov-Token only (default). The user name in the request is
               self-reported by the hook (desktop user name), so the audit log
               records it as claimed, not verified.
  token+oidc   X-Gov-Token AND "Authorization: Bearer <access token>" from your
               identity provider (Microsoft Entra ID, Okta, ...). The token
               proves the managed install; the access token proves the person.
  oidc         Bearer access token only.

An access token is accepted only if (per the identity provider's validation
rules) its signature verifies against a key from GOV_OIDC_JWKS_URL selected by
the token's `kid`, `iss` matches GOV_OIDC_ISSUER exactly, `aud` is one of
GOV_OIDC_AUDIENCE, and it hasn't expired.

The verified user name then replaces the desktop user name for policy
decisions (per-user overrides) and the audit log. The desktop name is still
logged as user.claimed, and a mismatch between the two is flagged.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

import jwt
from fastapi import HTTPException

from .settings import Settings


@dataclass(frozen=True)
class Identity:
    verified: bool
    user: str | None = None          # verified sign-in name, e.g. deepak@corp.example
    subject_id: str | None = None    # immutable ID, e.g. Entra object ID (oid)
    issuer: str | None = None


def same_person(claimed: str, verified: str) -> bool:
    """Does the desktop user name plausibly belong to the verified account?

    deepak, CORP\\deepak and deepak@corp.example all match deepak@corp.example.
    """
    c = (claimed or "").strip().lower()
    v = (verified or "").strip().lower()
    if not c or c == "unknown":
        return True                    # nothing claimed, nothing to contradict
    local = v.split("@", 1)[0]
    c_local = c.split("\\")[-1].split("@", 1)[0]
    return c in (v, local) or c_local == local


class Authenticator:
    def __init__(self, settings: Settings):
        self.s = settings
        self.mode = settings.auth_mode
        self._jwks = None
        if "oidc" in self.mode:
            # Keys are cached; an unknown `kid` (key rotation) triggers a refetch.
            self._jwks = jwt.PyJWKClient(settings.oidc_jwks_url, cache_keys=True, lifespan=3600,
                                         timeout=5)

    def _check_token(self, presented: str) -> None:
        # Constant-time comparison; during a rotation the previous token is accepted too.
        given = (presented or "").encode()
        valid = [t for t in (self.s.api_token, self.s.api_token_previous) if t]
        if not any(hmac.compare_digest(given, t.encode()) for t in valid):
            raise HTTPException(status_code=401, detail="invalid governance token")

    def _verify_bearer(self, authorization: str) -> Identity:
        scheme, _, raw = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not raw.strip():
            raise HTTPException(status_code=401, detail="user access token required (Authorization: Bearer)",
                                headers={"WWW-Authenticate": "Bearer"})
        raw = raw.strip()
        try:
            key = self._jwks.get_signing_key_from_jwt(raw)
            claims = jwt.decode(
                raw, key.key, algorithms=list(self.s.oidc_algorithms),
                audience=list(self.s.oidc_audience), issuer=self.s.oidc_issuer,
                options={"require": ["exp", "iss", "aud"]}, leeway=60,
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="user access token expired",
                                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}) from None
        except jwt.PyJWKClientConnectionError as exc:
            # Can't fetch the identity provider's keys: fail closed, but say why.
            raise HTTPException(status_code=503, detail=f"cannot reach identity provider keys: {exc}") from None
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail=f"user access token rejected: {exc}",
                                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}) from None
        user = next((str(claims[c]) for c in self.s.oidc_user_claims if claims.get(c)), None)
        subject = next((str(claims[c]) for c in self.s.oidc_id_claims if claims.get(c)), None)
        if not user:
            raise HTTPException(status_code=401, detail="user access token has no user name claim ("
                                + ", ".join(self.s.oidc_user_claims) + ")")
        return Identity(verified=True, user=user, subject_id=subject, issuer=claims.get("iss"))

    def __call__(self, x_gov_token: str, authorization: str) -> Identity:
        if self.s.auth_disabled:
            return Identity(verified=False)
        if self.mode in ("token", "token+oidc"):
            self._check_token(x_gov_token)
        if self.mode in ("oidc", "token+oidc"):
            return self._verify_bearer(authorization)
        return Identity(verified=False)
