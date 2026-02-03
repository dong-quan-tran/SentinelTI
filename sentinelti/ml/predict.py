from __future__ import annotations

from pathlib import Path
from typing import Tuple

import joblib
import numpy as np

from sentinelti.ml.features import extract_features


MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODELS_DIR / "url_classifier.joblib"


def load_model():
    artifact = joblib.load(MODEL_PATH)
    return artifact["model"], artifact["feature_names"]


def predict_url(url: str) -> Tuple[int, float]:
    """
    Return (predicted_label, probability_of_malicious).
    label: 1 = malicious, 0 = benign (based on training labels).
    """
    model, feature_names = load_model()

    feat_dict = extract_features(url)
    x = np.array([[feat_dict[k] for k in feature_names]], dtype=float)

    prob_malicious = float(model.predict_proba(x)[0][1])
    label = int(prob_malicious >= 0.5)
    return label, prob_malicious
