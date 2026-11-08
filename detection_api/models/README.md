# Offline spaCy model (optional)

Use this when the Docker build can't download the spaCy model (for example
"504 Gateway Time-out" from github.com).

1. Download the wheel for the model set in `.env` (`GOV_NLP_MODEL`) with a browser or a
   resumable download, into this folder:

   ```bash
   cd detection_api/models
   # small model, about 13 MB
   curl -fL -C - --retry 20 --retry-all-errors -O https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
   # large model, about 400 MB (only if GOV_NLP_MODEL=en_core_web_lg)
   curl -fL -C - --retry 20 --retry-all-errors -O https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
   ```
   `--retry-all-errors` also retries on "504 Gateway Time-out" (GitHub often returns several before succeeding), and `-C -` resumes an interrupted download. If it still stops, run the same command again.

2. Build as usual: `docker compose build detection-api`. The build log shows
   "Installing spaCy model from /tmp/models/...", and no download happens.

The version must match spaCy 3.8 (model 3.8.x). Wheels in this folder are not
committed (`.gitignore`) and are not part of the package zip.
