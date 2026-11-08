"""AWS Secrets Manager as the source of GOV_API_TOKEN / GOV_HASH_KEY (GOV_AWS_SECRET_ID).

Runs against a simulated AWS (moto), so it needs no AWS account:
    pip install boto3 "moto[secretsmanager]"
    python3 tests/test_aws_secrets.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection_api"))
results: list[bool] = []

try:
    import boto3
    from moto import mock_aws
except ImportError:
    print("SKIP  boto3 / moto not installed (pip install boto3 'moto[secretsmanager]')")
    sys.exit(0)


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(("PASS" if ok else "FAIL"), f" {name}" + (f"  -> {detail}" if detail and not ok else ""))


CLEAR = ("GOV_API_TOKEN", "GOV_API_TOKEN_FILE", "GOV_HASH_KEY", "GOV_HASH_KEY_FILE", "GOV_AWS_SECRET_ID",
         "GOV_AUTH_MODE", "GOV_AUTH_DISABLED", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE")


def load(**env):
    from app import settings as st
    for k in CLEAR:
        os.environ.pop(k, None)
    os.environ.update({"GOV_ENV_FILE": "", "AWS_DEFAULT_REGION": "ap-south-1",
                       # moto accepts any credentials; these look like temporary (role) keys
                       "AWS_ACCESS_KEY_ID": "ASIATESTTESTTESTTEST", "AWS_SECRET_ACCESS_KEY": "test"})
    os.environ.update(env)
    return st.load_settings()


@mock_aws
def main() -> int:
    import tempfile
    os.chdir(tempfile.mkdtemp(prefix="gov-aws-"))   # no ./.env here, so only the test's settings apply
    sm = boto3.client("secretsmanager", region_name="ap-south-1")
    good = {"GOV_API_TOKEN": "aws-token-0123456789abcdef", "GOV_HASH_KEY": "aws-hash-key-0123456789abcdef"}
    sm.create_secret(Name="ai-governance/test", SecretString=json.dumps(good))
    sm.create_secret(Name="ai-governance/not-json", SecretString="just-a-string")
    sm.create_secret(Name="ai-governance/missing-key", SecretString=json.dumps({"GOV_API_TOKEN": good["GOV_API_TOKEN"]}))

    s = load(GOV_AWS_SECRET_ID="ai-governance/test", GOV_AWS_REGION="ap-south-1")
    check("secrets read from Secrets Manager",
          s.api_token == good["GOV_API_TOKEN"] and s.hash_key == good["GOV_HASH_KEY"].encode())
    check("secrets_source reported as aws-secrets-manager", s.secrets_source == "aws-secrets-manager", s.secrets_source)
    check("temporary (role) credentials give no warning", not s.warnings, str(s.warnings))

    arn = sm.describe_secret(SecretId="ai-governance/test")["ARN"]
    s = load(GOV_AWS_SECRET_ID=arn)
    check("secret ARN accepted; region from AWS_DEFAULT_REGION", s.api_token == good["GOV_API_TOKEN"])

    s = load(GOV_AWS_SECRET_ID="ai-governance/test", AWS_ACCESS_KEY_ID="AKIATESTTESTTESTTEST")
    check("long-term IAM user keys flagged", any("long-term" in w for w in s.warnings), str(s.warnings))

    for name, env, needle in [
        ("missing secret refused", {"GOV_AWS_SECRET_ID": "ai-governance/nope"}, "Cannot read"),
        ("non-JSON secret refused", {"GOV_AWS_SECRET_ID": "ai-governance/not-json"}, "JSON object"),
        ("secret without GOV_HASH_KEY refused", {"GOV_AWS_SECRET_ID": "ai-governance/missing-key"}, "GOV_HASH_KEY"),
        ("secret plus GOV_API_TOKEN at the same time refused",
         {"GOV_AWS_SECRET_ID": "ai-governance/test", "GOV_API_TOKEN": "x" * 20}, "one place"),
    ]:
        try:
            load(**env)
            check(name, False, "accepted")
        except RuntimeError as exc:
            check(name, needle in str(exc), str(exc))

    # Token rotation: the previous token stays valid until removed from the secret
    sm.create_secret(Name="ai-governance/rotating", SecretString=json.dumps(
        {**good, "GOV_API_TOKEN": "new-token-0123456789abcdef", "GOV_API_TOKEN_PREVIOUS": good["GOV_API_TOKEN"]}))
    s = load(GOV_AWS_SECRET_ID="ai-governance/rotating")
    from app.identity import Authenticator
    from fastapi import HTTPException
    auth = Authenticator(s)

    def accepted(tok):
        try:
            auth(tok, "")
            return True
        except HTTPException:
            return False
    check("rotation: new token accepted", accepted("new-token-0123456789abcdef"))
    check("rotation: previous token still accepted", accepted(good["GOV_API_TOKEN"]))
    check("rotation: any other token refused", not accepted("wrong-token-0123456789abcdef"))
    check("rotation: warning logged while the previous token is set", any("PREVIOUS" in w for w in s.warnings))

    print(f"\n{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
