#!/usr/bin/env bash
# One-shot setup: Python venv, datasets, model training, frontend deps.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
"$PY" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
"$PY" -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
[ -f ml/data/KDDTrain+.txt ] || ./scripts/download_data.sh
.venv/bin/python ml/train.py
(cd frontend && npm install)
echo "Setup complete. See README.md -> Run."
