"""Train and evaluate the threat-detection models.

Usage (from repo root):
    .venv/bin/python ml/train.py

Outputs:
    ml/models/traffic_model.joblib   - best network-intrusion classifier
    ml/models/anomaly_model.joblib   - IsolationForest trained on normal traffic
    ml/models/url_model.joblib       - malicious-URL classifier
    ml/models/metrics.json           - all evaluation numbers
    docs/model_report.md             - human-readable comparison for the report
"""

import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.ml import traffic, url_features  # noqa: E402

DATA_DIR = ROOT / "ml" / "data"
MODELS_DIR = ROOT / "ml" / "models"
REPORT_PATH = ROOT / "docs" / "model_report.md"
RANDOM_STATE = 42

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("train")


# --------------------------------------------------------------------------- #
# Network traffic (NSL-KDD)
# --------------------------------------------------------------------------- #
def load_nsl_kdd(name: str) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(DATA_DIR / name, names=traffic.RAW_COLUMNS)
    y = df["attack"].map(traffic.to_category)
    return df[traffic.FEATURE_COLUMNS], y


def traffic_preprocessor() -> ColumnTransformer:
    return ColumnTransformer(
        [
            ("cat", OneHotEncoder(handle_unknown="ignore"), traffic.CATEGORICAL_COLUMNS),
            ("num", StandardScaler(), traffic.NUMERIC_COLUMNS),
        ]
    )


def traffic_candidates() -> dict:
    return {
        "LogisticRegression": LogisticRegression(
            max_iter=2000, class_weight="balanced"
        ),
        "DecisionTree": DecisionTreeClassifier(
            class_weight="balanced", random_state=RANDOM_STATE
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced_subsample",
            n_jobs=-1, random_state=RANDOM_STATE,
        ),
    }


def evaluate(name: str, model, x_test, y_test, labels: list) -> dict:
    pred = model.predict(x_test)
    return {
        "model": name,
        "accuracy": float((pred == y_test).mean()),
        "macro_f1": float(f1_score(y_test, pred, average="macro")),
        "weighted_f1": float(f1_score(y_test, pred, average="weighted")),
        "report": classification_report(
            y_test, pred, labels=labels, output_dict=True, zero_division=0
        ),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_test, pred, labels=labels).tolist(),
    }


def train_traffic() -> dict:
    x_train, y_train = load_nsl_kdd("KDDTrain+.txt")
    x_test, y_test = load_nsl_kdd("KDDTest+.txt")
    labels = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    log.info("NSL-KDD train=%d test=%d", len(x_train), len(x_test))
    log.info("Train class counts: %s", y_train.value_counts().to_dict())

    results, fitted = [], {}
    for name, clf in traffic_candidates().items():
        start = time.time()
        pipe = Pipeline([("prep", traffic_preprocessor()), ("clf", clf)])
        pipe.fit(x_train, y_train)
        result = evaluate(name, pipe, x_test, y_test, labels)
        result["train_seconds"] = round(time.time() - start, 1)
        log.info("%-18s acc=%.3f macroF1=%.3f", name, result["accuracy"], result["macro_f1"])
        results.append(result)
        fitted[name] = pipe

    best = max(results, key=lambda r: r["macro_f1"])
    joblib.dump(fitted[best["model"]], MODELS_DIR / "traffic_model.joblib")
    log.info("Best traffic model: %s", best["model"])

    # Anomaly detector: learns only "normal", flags anything unfamiliar.
    normal = x_train[y_train == "Normal"]
    anomaly = Pipeline(
        [
            ("prep", traffic_preprocessor()),
            ("iso", IsolationForest(
                n_estimators=200, contamination="auto", random_state=RANDOM_STATE
            )),
        ]
    )
    anomaly.fit(normal)
    flagged = anomaly.predict(x_test) == -1
    is_attack = (y_test != "Normal").to_numpy()
    anomaly_metrics = {
        "attack_detection_rate": float(flagged[is_attack].mean()),
        "false_positive_rate": float(flagged[~is_attack].mean()),
    }
    joblib.dump(anomaly, MODELS_DIR / "anomaly_model.joblib")
    log.info("Anomaly detector: %s", anomaly_metrics)

    return {"candidates": results, "best": best["model"], "anomaly": anomaly_metrics}


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #
def load_urls() -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(DATA_DIR / "urls.csv", on_bad_lines="skip")
    df = df.dropna(subset=["url", "label"])
    df = df[df["label"].isin(["good", "bad"])].drop_duplicates(subset=["url"])
    y = df["label"].map({"good": "Benign", "bad": "Malicious"})
    return df[["url"]].astype(str), y


def url_pipeline() -> Pipeline:
    features = ColumnTransformer(
        [
            ("ngrams", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5),
                min_df=3, max_features=200_000, sublinear_tf=True,
            ), "url"),
            ("lexical", Pipeline([
                ("extract", FunctionTransformer(url_features.extract_matrix)),
                ("scale", StandardScaler()),
            ]), ["url"]),
        ]
    )
    clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=5.0)
    return Pipeline([("features", features), ("clf", clf)])


def train_urls() -> dict:
    x, y = load_urls()
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    log.info("URLs train=%d test=%d classes=%s", len(x_train), len(x_test),
             y.value_counts().to_dict())
    start = time.time()
    model = url_pipeline().fit(x_train, y_train)
    result = evaluate("CharNgram+Lexical LogisticRegression", model, x_test, y_test,
                      ["Benign", "Malicious"])
    result["train_seconds"] = round(time.time() - start, 1)
    log.info("URL model acc=%.3f macroF1=%.3f", result["accuracy"], result["macro_f1"])
    joblib.dump(model, MODELS_DIR / "url_model.joblib", compress=3)
    return result


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _cm_table(labels: list, matrix: list) -> str:
    head = "| actual \\ predicted | " + " | ".join(labels) + " |"
    sep = "|---" * (len(labels) + 1) + "|"
    rows = [f"| **{lab}** | " + " | ".join(str(v) for v in row) + " |"
            for lab, row in zip(labels, matrix)]
    return "\n".join([head, sep, *rows])


def write_report(traffic_metrics: dict, url_metrics: dict) -> None:
    lines = ["# Model Evaluation Report", "",
             "_Generated by `ml/train.py`. Do not edit by hand._", "",
             "## 1. Network intrusion classifier (NSL-KDD)", "",
             "Trained on `KDDTrain+`, evaluated on the official `KDDTest+` split, "
             "which contains attack types never seen in training.", "",
             "| Model | Accuracy | Macro F1 | Weighted F1 | Train time (s) |",
             "|---|---|---|---|---|"]
    for r in traffic_metrics["candidates"]:
        lines.append(f"| {r['model']} | {r['accuracy']:.3f} | {r['macro_f1']:.3f} | "
                     f"{r['weighted_f1']:.3f} | {r['train_seconds']} |")
    best = next(r for r in traffic_metrics["candidates"]
                if r["model"] == traffic_metrics["best"])
    lines += ["", f"**Selected:** {best['model']} (highest macro F1).", "",
              "### Per-class results (selected model)", "",
              "| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|"]
    for lab in best["labels"]:
        c = best["report"][lab]
        lines.append(f"| {lab} | {c['precision']:.3f} | {c['recall']:.3f} | "
                     f"{c['f1-score']:.3f} | {int(c['support'])} |")
    lines += ["", "### Confusion matrix", "", _cm_table(best["labels"], best["confusion_matrix"]),
              "", "### Anomaly detector (IsolationForest, trained on normal traffic only)", "",
              f"- Attack detection rate: {traffic_metrics['anomaly']['attack_detection_rate']:.3f}",
              f"- False positive rate: {traffic_metrics['anomaly']['false_positive_rate']:.3f}",
              "", "## 2. Malicious URL classifier", "",
              f"Model: {url_metrics['model']} (character 3-5 grams + 17 lexical features).", "",
              f"- Accuracy: {url_metrics['accuracy']:.3f}",
              f"- Macro F1: {url_metrics['macro_f1']:.3f}", "",
              "| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|"]
    for lab in url_metrics["labels"]:
        c = url_metrics["report"][lab]
        lines.append(f"| {lab} | {c['precision']:.3f} | {c['recall']:.3f} | "
                     f"{c['f1-score']:.3f} | {int(c['support'])} |")
    lines += ["", "### Confusion matrix", "",
              _cm_table(url_metrics["labels"], url_metrics["confusion_matrix"]), ""]
    REPORT_PATH.write_text("\n".join(lines))


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    np.random.seed(RANDOM_STATE)
    traffic_metrics = train_traffic()
    url_metrics = train_urls()
    (MODELS_DIR / "metrics.json").write_text(
        json.dumps({"traffic": traffic_metrics, "url": url_metrics}, indent=2)
    )
    write_report(traffic_metrics, url_metrics)
    log.info("Done. Models in %s, report in %s", MODELS_DIR, REPORT_PATH)


if __name__ == "__main__":
    main()
