from __future__ import annotations

from pathlib import Path
from typing import Tuple
import os

import joblib
import numpy as np

from sentinelti.ml.features import extract_features

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def get_model_path(model_name: str) -> Path:
    return MODELS_DIR / f"url_classifier_{model_name}.joblib"


def load_model(prefer: str = "xgb"):
    order = ["xgb", "logreg"]
    if prefer == "logreg":
        order = ["logreg", "xgb"]

    last_error: Exception | None = None

    for model_name in order:
        path = get_model_path(model_name)
        if not path.exists():
            continue

        try:
            artifact = joblib.load(path)
        except Exception as exc:
            last_error = exc
            continue

        return (
            artifact["model"],
            artifact["feature_names"],
            artifact.get("model_type", model_name),
        )

    if last_error is not None:
        raise RuntimeError("Failed to load any trained URL model") from last_error
    raise FileNotFoundError("No trained URL model artifacts found")


DEFAULT_MALICIOUS_THRESHOLD = 0.75


def get_malicious_threshold() -> float:
    raw = os.getenv("SENTINELTI_MALICIOUS_THRESHOLD")
    if raw is None:
        return DEFAULT_MALICIOUS_THRESHOLD

    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_MALICIOUS_THRESHOLD

    if 0.0 <= value <= 1.0:
        return value
    return DEFAULT_MALICIOUS_THRESHOLD


def predict_url(url: str) -> Tuple[int, float]:
    """
    Return (predicted_label, probability_of_malicious).
    label: 1 = malicious, 0 = benign.
    """
    model, feature_names, _model_type = load_model()

    feat_dict = extract_features(url)
    x = np.array([[feat_dict[k] for k in feature_names]], dtype=float)

    prob_malicious = float(model.predict_proba(x)[0][1])
    threshold = get_malicious_threshold()
    label = int(prob_malicious >= threshold)
    return label, prob_malicious