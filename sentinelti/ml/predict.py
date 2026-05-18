from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple
import os

import joblib
import numpy as np

from sentinelti.ml.features import extract_features


MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
DEFAULT_MALICIOUS_THRESHOLD = 0.75


def get_model_path(model_name: str) -> Path:
    return MODELS_DIR / f"url_classifier_{model_name}.joblib"


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

        _validate_artifact(artifact, path)

        metadata = {
            "model_type": artifact.get("model_type", model_name),
            "trained_at": artifact.get("trained_at"),
            "dataset_name": artifact.get("dataset_name"),
            "metrics": artifact.get("metrics", {}),
            "threshold": artifact.get("threshold", get_malicious_threshold()),
            "feature_version": artifact.get("feature_version", "v2"),
            "artifact_path": str(path),
        }

        return (
            artifact["model"],
            artifact["feature_names"],
            metadata,
        )

    if last_error is not None:
        raise RuntimeError("Failed to load any trained URL model") from last_error
    raise FileNotFoundError("No trained URL model artifacts found")


def get_loaded_model_metadata(prefer: str = "xgb") -> Dict[str, Any]:
    _model, _feature_names, metadata = load_model(prefer=prefer)
    return metadata


def predict_url(url: str) -> Tuple[int, float]:
    model, feature_names, metadata = load_model()

    feat_dict = extract_features(url)
    missing_features = [name for name in feature_names if name not in feat_dict]
    if missing_features:
        raise RuntimeError(
            "Feature extraction is missing expected model features: "
            + ", ".join(missing_features)
        )

    x = np.array([[feat_dict[k] for k in feature_names]], dtype=float)

    prob_malicious = float(model.predict_proba(x)[0][1])
    threshold = float(metadata.get("threshold", get_malicious_threshold()))
    label = int(prob_malicious >= threshold)
    return label, prob_malicious


def predict_url_with_metadata(url: str) -> Dict[str, Any]:
    model, feature_names, metadata = load_model()

    feat_dict = extract_features(url)
    missing_features = [name for name in feature_names if name not in feat_dict]
    if missing_features:
        raise RuntimeError(
            "Feature extraction is missing expected model features: "
            + ", ".join(missing_features)
        )

    x = np.array([[feat_dict[k] for k in feature_names]], dtype=float)
    prob_malicious = float(model.predict_proba(x)[0][1])
    threshold = float(metadata.get("threshold", get_malicious_threshold()))
    label = int(prob_malicious >= threshold)

    return {
        "label": label,
        "prob_malicious": prob_malicious,
        "threshold": threshold,
        "model_meta": metadata,
    }


def _validate_artifact(artifact: Dict[str, Any], path: Path) -> None:
    if not isinstance(artifact, dict):
        raise RuntimeError(f"Invalid model artifact format in {path}")
    if "model" not in artifact:
        raise RuntimeError(f"Model artifact missing 'model' in {path}")
    if "feature_names" not in artifact:
        raise RuntimeError(f"Model artifact missing 'feature_names' in {path}")
    if not isinstance(artifact["feature_names"], list):
        raise RuntimeError(f"Model artifact 'feature_names' must be a list in {path}")