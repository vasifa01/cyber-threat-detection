#!/usr/bin/env bash
# Downloads the public datasets used for training into ml/data/.
set -euo pipefail
cd "$(dirname "$0")/../ml/data"
BASE=https://raw.githubusercontent.com
curl -fSL -o KDDTrain+.txt "$BASE/defcom17/NSL_KDD/master/KDDTrain+.txt"
curl -fSL -o KDDTest+.txt  "$BASE/defcom17/NSL_KDD/master/KDDTest+.txt"
curl -fSL -o urls.csv      "$BASE/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"
echo "Datasets saved to $(pwd)"
