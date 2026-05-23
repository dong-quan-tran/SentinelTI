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
    """
    Normalize raw artifact metadata into a consistent dict.

    Notes on thresholds:
    - `threshold` is the model's suggested decision boundary and is the first
      candidate for the effective classification threshold, as long as it is
      a valid float between 0.0 and 1.0.
    - `recommended_threshold` is advisory-only metadata which may come from
      external analysis or grid search; it does *not* affect the effective
      threshold used for classification.
    - Invalid values for either field (wrong type or out of range) are
      ignored and omitted from the normalized result.
    """
    nested = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}

    threshold = nested.get("threshold")
    if threshold is None:
        threshold = artifact.get("threshold")

    recommended_threshold = nested.get("recommended_threshold")
    if recommended_threshold is None:
        recommended_threshold = artifact.get("recommended_threshold")

    recommended_threshold_source = nested.get("recommended_threshold_source")
    if recommended_threshold_source is None:
        recommended_threshold_source = artifact.get("recommended_threshold_source")

    normalized: Dict[str, Any] = {
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
        "recommended_threshold_source": recommended_threshold_source,
    }

    if threshold is not None:
        try:
            tv = float(threshold)
        except (TypeError, ValueError):
            tv = None
        if tv is not None and 0.0 <= tv <= 1.0:
            normalized["threshold"] = tv

    if recommended_threshold is not None:
        try:
            rv = float(recommended_threshold)
        except (TypeError, ValueError):
            rv = None
        if rv is not None and 0.0 <= rv <= 1.0:
            normalized["recommended_threshold"] = rv

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

    The returned `metadata` is the normalized artifact metadata and may
    include advisory fields such as `recommended_threshold` in addition
    to core fields like `model_type`, `metrics`, and `threshold`.
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


def _coerce_metadata(metadata: Any, prefer: str = "xgb") -> Dict[str, Any]:
    if isinstance(metadata, dict):
        return dict(metadata)
    return {
        "model_type": str(metadata),
        "feature_version": DEFAULT_FEATURE_VERSION,
        "metrics": {},
    }


def _effective_threshold_with_source(metadata: Dict[str, Any]) -> tuple[float, str]:
    """
    Compute the effective threshold for classification, with provenance.

    Precedence:
    1. Valid `threshold` in model metadata (0.0 <= t <= 1.0).
    2. Valid SENTINELTI_MALICIOUS_THRESHOLD env var.
    3. DEFAULT_MALICIOUS_THRESHOLD.

    Note:
        `recommended_threshold` is *not* used here and remains advisory-only.
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


def get_effective_model_metadata(prefer: str = "xgb") -> Dict[str, Any]:
    """
    Load the currently active model and return enriched metadata.

    The returned dict includes:
    - `threshold`: the effective classification threshold after applying
      metadata/env/default precedence.
    - `threshold_source`: one of "metadata", "env", or "default".
    - `recommended_threshold`: advisory threshold if present and valid,
      otherwise None.
    - `recommended_threshold_source`: provenance for the advisory threshold,
      if provided by the artifact.
    - `feature_count`: number of features expected by the model.
    """
    _model, feature_names, metadata = load_model(prefer=prefer)
    metadata = _coerce_metadata(metadata, prefer=prefer)

    threshold, threshold_source = _effective_threshold_with_source(metadata)

    enriched = dict(metadata)
    enriched["threshold"] = threshold
    enriched["threshold_source"] = threshold_source
    enriched["feature_count"] = len(feature_names)

    if "recommended_threshold" not in enriched:
        enriched["recommended_threshold"] = None
    if "recommended_threshold_source" not in enriched:
        enriched["recommended_threshold_source"] = None

    return enriched


def get_loaded_model_metadata(prefer: str = "xgb") -> Dict[str, Any]:
    return get_effective_model_metadata(prefer=prefer)


def get_loaded_model_type(prefer: str = "xgb") -> str:
    _model, _feature_names, metadata = load_model(prefer=prefer)
    if isinstance(metadata, dict):
        return str(metadata.get("model_type", prefer))
    return str(metadata)


def _build_feature_vector(url: str, feature_names: list[str]) -> np.ndarray:
    """
    Build a feature vector for the given URL.

    Contract:
        - `extract_features(url)` must return values for all feature names
          listed in `feature_names`.
        - It may return additional keys, which are ignored.
        - If any expected feature is missing, this function raises
          RuntimeError with a clear message.
    """
    feat_dict = extract_features(url)
    missing_features = [name for name in feature_names if name not in feat_dict]
    if missing_features:
        raise RuntimeError(
            "Feature extraction is missing expected model features: "
            + ", ".join(missing_features)
        )

    return np.array([[feat_dict[name] for name in feature_names]], dtype=float)


def _score_url(url: str, prefer: str = "xgb") -> Dict[str, Any]:
    """
    Score a single URL using the preferred model.

    Notes:
        - The classification label is determined solely by the effective
          `threshold` computed from model metadata, environment overrides,
          and defaults.
        - Any `recommended_threshold` present in model metadata is included
          in `model_meta` for observability but does not influence the
          label or score.
    """
    model, feature_names, _metadata = load_model(prefer=prefer)
    metadata = get_effective_model_metadata(prefer=prefer)

    x = _build_feature_vector(url, feature_names)

    prob_malicious = float(model.predict_proba(x)[0][1])
    threshold = float(metadata["threshold"])
    threshold_source = str(metadata["threshold_source"])
    label = int(prob_malicious >= threshold)

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