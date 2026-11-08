#!/usr/bin/env bash
# Runs every automated check the way GitHub Actions does (.github/workflows/ci.yml).
# Without Docker: the server runs from a Python environment with en_core_web_sm.
#
#   bash scripts/ci.sh              # installs packages first (CI)
#   bash scripts/ci.sh --no-install # use the packages already installed (local venv)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${GOV_PORT:-8088}"

if [ "${1:-}" != "--no-install" ]; then
  python3 -m pip install --quiet -r detection_api/requirements.txt "moto[secretsmanager]"
  python3 -m spacy download en_core_web_sm --quiet || python3 -m spacy download en_core_web_sm
fi

echo "== offline checks"
python3 scripts/validate_rules.py
python3 tests/test_rules.py
python3 tests/test_policy.py
python3 tests/test_aws_secrets.py
(cd detection_api && python3 ../tests/test_offline_suffix.py)

echo "== server"
[ -f .env ] || python3 scripts/init_secrets.py
(cd detection_api && GOV_ENV_FILE=../.env GOV_NLP_MODEL=en_core_web_sm GOV_WORKERS=1 GOV_PORT="$PORT" \
   python3 -m app.serve > ../logs/ci-server.log 2>&1) &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 120); do
  curl -fs "http://127.0.0.1:$PORT/healthz" > /dev/null && break
  kill -0 $SERVER 2>/dev/null || { tail -50 logs/ci-server.log; exit 1; }
  sleep 1
done
curl -fs "http://127.0.0.1:$PORT/healthz" > /dev/null || { tail -50 logs/ci-server.log; exit 1; }

echo "== online checks"
python3 scripts/doctor.py --local
python3 tests/test_api.py
python3 tests/test_hooks.py
python3 tests/test_rules.py --live detection_api/rules/recognizers.json
python3 tests/test_identity.py
git diff --quiet -- detection_api/rules/recognizers.json 2>/dev/null || [ ! -d .git ] || {
  echo "rules file was not restored by the live test"; exit 1; }
echo "== all checks passed"
