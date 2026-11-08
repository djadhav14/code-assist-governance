# AI governance detection API: Presidio + India recognizers + secrets + OCR
FROM python:3.12-slim

ARG NLP_MODEL=en_core_web_lg
# GOV_HOST=0.0.0.0 listens on all interfaces inside the container; compose publishes
# the port on GOV_BIND_ADDRESS (127.0.0.1 by default).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOV_NLP_MODEL=${NLP_MODEL} \
    GOV_POLICY_PATH=/app/policy.yaml \
    GOV_RECOGNIZERS_PATH=/app/rules/recognizers.json \
    GOV_HOST=0.0.0.0 \
    GOV_PORT=8088 \
    GOV_WORKERS=2

RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng curl \
 && rm -rf /var/lib/apt/lists/*

# pip waits up to 120 s per read and retries 10 times, so a slow mirror
# doesn't abort a long build.
ENV PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

WORKDIR /app
COPY requirements.txt .
# Python packages in their own layer: once this succeeds, Docker caches it and a
# failed model download below doesn't make you download these again.
RUN pip install --no-cache-dir -r requirements.txt

# spaCy model. If a matching wheel is in detection_api/models/ (see the README
# there), it is installed from that file with no download. Otherwise it is
# downloaded from GitHub, with up to 5 attempts.
COPY models/ /tmp/models/
RUN set -e; \
    whl=$(ls /tmp/models/${NLP_MODEL}-*.whl 2>/dev/null | head -n 1 || true); \
    if [ -n "$whl" ]; then \
      echo "Installing spaCy model from $whl"; \
      pip install --no-cache-dir --no-deps "$whl"; \
    else \
      for i in 1 2 3 4 5; do \
        python -m spacy download ${NLP_MODEL} && break; \
        echo "spaCy model download failed (attempt $i of 5), retrying in $((i * 15)) s"; \
        sleep $((i * 15)); \
      done; \
    fi; \
    python -c "import spacy; spacy.load('${NLP_MODEL}'); print('spaCy model ${NLP_MODEL} OK')"; \
    rm -rf /tmp/models
# No tldextract cache: the server uses the bundled public-suffix list and never
# writes under /app, so it runs as any uid (compose uses yours, GOV_UID).

COPY app ./app
COPY policy.yaml .
# Detection rules: the copy baked in here is replaced by the compose mount.
COPY rules ./rules

RUN useradd --create-home --uid 10001 gov && chown -R gov /app
USER gov

EXPOSE 8088
# Port and workers come from GOV_PORT / GOV_WORKERS; secrets are never baked into the image.
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${GOV_PORT}/healthz" > /dev/null || exit 1

CMD ["python", "-m", "app.serve"]
