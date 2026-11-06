import os
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))

MODELS_DIR = REPO / "ml" / "models"
MODELS_PRESENT = all(
    (MODELS_DIR / f).exists()
    for f in ("traffic_model.joblib", "anomaly_model.joblib", "url_model.joblib")
)

# A real DoS (neptune SYN flood) and a normal row taken from KDDTest+.
NEPTUNE_ROW = "0,tcp,private,REJ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,0.00,0.00,1.00,1.00,0.04,0.06,0.00,255,10,0.04,0.06,0.00,0.00,0.00,0.00,1.00,1.00"
NORMAL_ROW = "0,tcp,http,SF,267,14515,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,4,4,0.00,0.00,0.00,0.00,1.00,0.00,0.00,155,255,1.00,0.00,0.01,0.03,0.01,0.00,0.00,0.00"


def row_to_features(row: str) -> dict:
    from app.ml.traffic import FEATURE_COLUMNS

    return dict(zip(FEATURE_COLUMNS, row.split(",")))


@pytest.fixture()
def client(tmp_path):
    if not MODELS_PRESENT:
        pytest.skip("trained models missing; run ml/train.py")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_path / 'test.db'}"
    from app.config import get_settings

    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()
