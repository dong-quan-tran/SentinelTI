from __future__ import annotations

from typing import Any


def coerce_top_features(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []

    cleaned: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        feature = item.get("feature")
        importance = item.get("importance")
        if feature is None or importance is None:
            continue

        try:
            cleaned.append(
                {
                    "feature": str(feature),
                    "importance": float(importance),
                }
            )
        except (TypeError, ValueError):
            continue

    return cleaned


def coerce_training_notes(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []

    cleaned: list[str] = []
    for item in raw:
        if item is None:
            continue

        text = str(item).strip()
        if text:
            cleaned.append(text)

    return cleaned


def build_model_meta(metadata: dict[str, Any]) -> dict[str, Any]:
    metadata = metadata or {}
    metrics = metadata.get("metrics", {}) or {}

    threshold = float(metadata.get("threshold", 0.75))
    threshold_source = metadata.get("threshold_source")
    if threshold_source not in ("metadata", "env", "default"):
        threshold_source = "metadata"

    return {
        "artifact_version": metadata.get("artifact_version"),
        "model_type": metadata.get("model_type", "unknown"),
        "trained_at": metadata.get("trained_at"),
        "dataset_name": metadata.get("dataset_name"),
        "dataset_source": metadata.get("dataset_source", {}),
        "feature_version": metadata.get("feature_version"),
        "threshold": threshold,
        "threshold_source": threshold_source,
        "recommended_threshold": metadata.get("recommended_threshold"),
        "recommended_threshold_source": metadata.get("recommended_threshold_source"),
        "metrics": {
            "roc_auc": metrics.get("roc_auc"),
            "average_precision": metrics.get("average_precision"),
        },
        "class_labels": metadata.get("class_labels", {}),
        "class_counts": metadata.get("class_counts", {}),
        "training_params": metadata.get("training_params", {}),
        "training_notes": coerce_training_notes(
            metadata.get("training_notes", metrics.get("training_notes", []))
        ),
        "top_features": coerce_top_features(
            metadata.get("top_features", metadata.get("top_feature_importance", []))
        ),
        "artifact_path": metadata.get("artifact_path"),
        "model_summary": {
            "model_type": metadata.get("model_type", "unknown"),
            "dataset_name": metadata.get("dataset_name"),
            "trained_at": metadata.get("trained_at"),
            "top_features": coerce_top_features(
                metadata.get("top_features", metadata.get("top_feature_importance", []))
            )[:3],
        },
    }