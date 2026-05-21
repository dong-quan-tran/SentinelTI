from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np

from sentinelti.ml.features import extract_features

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
DEFAULT_MALICIOUS_THRESHOLD = 0.75
DEFAULT_FEATURE_VERSION = "v2"


def get_model_path(model_name: str) -> Path:
    return MODELS_DIR / f"url_classifier_{model_name}.joblib"


def get_malicious_threshold() -> float:
    """
    Public helper used by other modules (e.g. tests, API metadata).

    This function keeps the original behavior: it looks only at the
    SENTINELTI_MALICIOUS_THRESHOLD env var and falls back to the
    DEFAULT_MALICIOUS_THRESHOLD.
    """
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


def _normalize_metadata(
    artifact: Dict[str, Any],
    model_name: str,
    path: Path,
) -> Dict[str, Any]:
    nested = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}

    threshold = nested.get("threshold")
    if threshold is None:
        threshold = artifact.get("threshold")

    normalized = {
        "artifact_version": artifact.get("artifact_version", "legacy"),
        "model_type": nested.get("model_type", artifact.get("model_type", model_name)),
        "trained_at": nested.get("trained_at", artifact.get("trained_at")),
        "dataset_name": nested.get("dataset_name", artifact.get("dataset_name")),
        "dataset_source": nested.get("dataset_source", artifact.get("dataset_source", {})),
        "metrics": nested.get("metrics", artifact.get("metrics", {})),
        "feature_version": nested.get(
            "feature_version",
            artifact.get("feature_version", DEFAULT_FEATURE_VERSION),
        ),
        "class_labels": nested.get("class_labels", artifact.get("class_labels", {})),
        "class_counts": nested.get("class_counts", artifact.get("class_counts", {})),
        "training_params": nested.get("training_params", artifact.get("training_params", {})),
        "top_features": nested.get("top_features", artifact.get("top_features", [])),
        "artifact_path": str(path),
    }

    if threshold is not None:
        try:
            normalized["threshold"] = float(threshold)
        except (TypeError, ValueError):
            pass

    return normalized


def _validate_artifact(artifact: Dict[str, Any], path: Path) -> None:
    if not isinstance(artifact, dict):
        raise RuntimeError(f"Invalid model artifact format in {path}")
    if "model" not in artifact:
        raise RuntimeError(f"Model artifact missing 'model' in {path}")
    if "feature_names" not in artifact:
        raise RuntimeError(f"Model artifact missing 'feature_names' in {path}")
    if not isinstance(artifact["feature_names"], list):
        raise RuntimeError(f"Model artifact 'feature_names' must be a list in {path}")


def _load_artifact(prefer: str = "xgb"):
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
        except Exception as exc:  # pragma: no cover - defensive
            last_error = exc
            continue

        _validate_artifact(artifact, path)
        metadata = _normalize_metadata(artifact, model_name, path)
        return artifact["model"], artifact["feature_names"], metadata

    if last_error is not None:
        raise RuntimeError("Failed to load any trained URL model") from last_error
    raise FileNotFoundError("No trained URL model artifacts found")


def load_model(prefer: str = "xgb"):
    """
    Primary loader.

    Returns:
        tuple[model, feature_names, metadata]
    """
    return _load_artifact(prefer=prefer)


def load_model_legacy(prefer: str = "xgb"):
    """
    Backward-compatible loader for older tests/code.

    Returns:
        tuple[model, feature_names, model_type]
    """
    model, feature_names, metadata = _load_artifact(prefer=prefer)
    return model, feature_names, str(metadata.get("model_type", prefer))


def get_loaded_model_metadata(prefer: str = "xgb") -> Dict[str, Any]:
    _model, _feature_names, metadata = load_model(prefer=prefer)
    if isinstance(metadata, dict):
        if "threshold" not in metadata:
            metadata = {
                **metadata,
                "threshold": get_malicious_threshold(),
            }
        return metadata
    return {
        "model_type": str(metadata),
        "threshold": get_malicious_threshold(),
        "feature_version": DEFAULT_FEATURE_VERSION,
        "metrics": {},
    }


def get_loaded_model_type(prefer: str = "xgb") -> str:
    _model, _feature_names, metadata = load_model(prefer=prefer)
    if isinstance(metadata, dict):
        return str(metadata.get("model_type", prefer))
    return str(metadata)


def _build_feature_vector(url: str, feature_names: list[str]) -> np.ndarray:
    feat_dict = extract_features(url)
    missing_features = [name for name in feature_names if name not in feat_dict]
    if missing_features:
        raise RuntimeError(
            "Feature extraction is missing expected model features: "
            + ", ".join(missing_features)
        )

    return np.array([[feat_dict[name] for name in feature_names]], dtype=float)


def _coerce_metadata(metadata: Any, prefer: str = "xgb") -> Dict[str, Any]:
    if isinstance(metadata, dict):
        return metadata
    return {
        "model_type": str(metadata),
        "feature_version": DEFAULT_FEATURE_VERSION,
        "metrics": {},
    }


def _effective_threshold_with_source(metadata: Dict[str, Any]) -> tuple[float, str]:
    """
    Compute the threshold for classification, along with its provenance:

    Returns:
        (threshold_value, source)
        where source is one of: "metadata", "env", "default".
    """
    meta_value = metadata.get("threshold")
    try:
        if meta_value is not None:
            mv = float(meta_value)
            if 0.0 <= mv <= 1.0:
                return mv, "metadata"
    except (TypeError, ValueError):
        pass

    raw_env = os.getenv("SENTINELTI_MALICIOUS_THRESHOLD")
    if raw_env is not None:
        try:
            ev = float(raw_env)
        except ValueError:
            ev = None
        if ev is not None and 0.0 <= ev <= 1.0:
            return ev, "env"

    return DEFAULT_MALICIOUS_THRESHOLD, "default"


def _score_url(url: str, prefer: str = "xgb") -> Dict[str, Any]:
    model, feature_names, metadata = load_model(prefer=prefer)
    metadata = _coerce_metadata(metadata, prefer=prefer)

    x = _build_feature_vector(url, feature_names)

    prob_malicious = float(model.predict_proba(x)[0][1])
    threshold, threshold_source = _effective_threshold_with_source(metadata)
    label = int(prob_malicious >= threshold)

    # also expose the effective threshold back onto metadata for API consumers
    metadata["threshold"] = threshold
    metadata["threshold_source"] = threshold_source

    return {
        "label": label,
        "prob_malicious": prob_malicious,
        "threshold": threshold,
        "threshold_source": threshold_source,
        "model_meta": metadata,
    }


def predict_url(url: str) -> Tuple[int, float]:
    result = _score_url(url)
    return int(result["label"]), float(result["prob_malicious"])


def predict_url_with_metadata(url: str) -> Dict[str, Any]:
    return _score_url(url)