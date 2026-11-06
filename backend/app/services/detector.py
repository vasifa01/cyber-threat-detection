"""Loads the trained models once and turns raw input into a Prediction."""

import logging
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import pandas as pd

from app.ml import traffic, url_features

log = logging.getLogger(__name__)

URL_DESCRIPTIONS = {
    "Benign": "No malicious indicators found",
    "Phishing": "Likely phishing / credential-theft URL",
    "Malware": "Likely malware download URL",
}


@dataclass(frozen=True)
class Prediction:
    source: str
    model: str
    label: str
    confidence: float
    is_threat: bool
    description: str
    anomaly: bool = False
    indicators: dict = field(default_factory=dict)


class Detector:
    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self.traffic_model = self._load("traffic_model.joblib")
        self.anomaly_model = self._load("anomaly_model.joblib")
        self.url_model = self._load("url_model.joblib")

    def _load(self, name: str):
        path = self.models_dir / name
        if not path.exists():
            raise FileNotFoundError(
                f"Model file {path} not found. Run `python ml/train.py` first."
            )
        log.info("Loading %s", path)
        return joblib.load(path)

    def predict_traffic(self, features: dict) -> Prediction:
        row = pd.DataFrame([features], columns=traffic.FEATURE_COLUMNS)
        probs = self.traffic_model.predict_proba(row)[0]
        classes = list(self.traffic_model.classes_)
        best = int(probs.argmax())
        label = classes[best]
        anomaly = bool(self.anomaly_model.predict(row)[0] == -1)
        # Classifier says Normal but the anomaly model disagrees -> possible
        # novel ("zero-day") attack the classifier was never trained on.
        if label == "Normal" and anomaly:
            return Prediction(
                source="traffic", model="IsolationForest", label="Anomaly",
                confidence=round(1 - float(probs[best]), 4), is_threat=True,
                description="Unusual traffic pattern not seen during training",
                anomaly=True,
            )
        return Prediction(
            source="traffic", model=type(self.traffic_model[-1]).__name__,
            label=label, confidence=round(float(probs[best]), 4),
            is_threat=label != "Normal",
            description=traffic.CATEGORY_DESCRIPTIONS[label], anomaly=anomaly,
        )

    def predict_url(self, url: str) -> Prediction:
        row = pd.DataFrame({"url": [url]})
        probs = self.url_model.predict_proba(row)[0]
        classes = list(self.url_model.classes_)
        p_malicious = float(probs[classes.index("Malicious")])
        is_threat = p_malicious >= 0.5
        label = url_features.malicious_subtype(url) if is_threat else "Benign"
        indicators = {k: v for k, v in url_features.extract(url).items() if v}
        return Prediction(
            source="url", model="UrlLogisticRegression", label=label,
            confidence=round(p_malicious if is_threat else 1 - p_malicious, 4),
            is_threat=is_threat, description=URL_DESCRIPTIONS[label],
            indicators=indicators,
        )
