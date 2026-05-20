from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

MODELS_DIR = Path("sentinelti/models")
OUTPUT_DIR = Path("docs/model_metrics")
DEFAULT_STEPS = 81


def _positive_proba(model, X):
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        if getattr(proba, "ndim", 1) == 2 and proba.shape[1] >= 2:
            return proba[:, 1]
        return np.asarray(proba).reshape(-1)

    if hasattr(model, "decision_function"):
        scores = np.asarray(model.decision_function(X)).reshape(-1)
        return 1.0 / (1.0 + np.exp(-scores))

    raise ValueError("Model must support predict_proba() or decision_function().")


def _compute_rows(y_true, y_proba, thresholds):
    rows = []
    for threshold in thresholds:
        y_pred = (y_proba >= threshold).astype(int)
        rows.append(
            {
                "threshold": round(float(threshold), 6),
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                "f1": float(f1_score(y_true, y_pred, zero_division=0)),
                "predicted_positive_rate": float(np.mean(y_pred)),
            }
        )
    return pd.DataFrame(rows)


def _choose_best_threshold(df: pd.DataFrame, optimize_for: str) -> float:
    if optimize_for not in {"f1", "precision", "recall", "accuracy"}:
        raise ValueError(f"Unsupported optimize_for={optimize_for}")

    ranked = df.sort_values(
        by=[optimize_for, "precision", "recall", "threshold"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)
    return float(ranked.iloc[0]["threshold"])


def _top_feature_importance(model, feature_names, top_k=10):
    if not hasattr(model, "feature_importances_"):
        return []

    importances = np.asarray(model.feature_importances_).reshape(-1)
    if len(importances) != len(feature_names):
        return []

    pairs = sorted(
        zip(feature_names, importances),
        key=lambda item: item[1],
        reverse=True,
    )[:top_k]

    return [
        {"feature": str(name), "importance": float(score)}
        for name, score in pairs
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Analyze classification thresholds for a trained SentinelTI model artifact."
    )
    parser.add_argument(
        "--artifact",
        required=True,
        help="Path to a saved .joblib model artifact.",
    )
    parser.add_argument(
        "--optimize-for",
        default="f1",
        choices=["f1", "precision", "recall", "accuracy"],
        help="Metric used to pick the recommended threshold.",
    )
    parser.add_argument(
        "--steps",
        type=int,
        default=DEFAULT_STEPS,
        help="Number of threshold points between 0.10 and 0.90 inclusive.",
    )
    args = parser.parse_args()

    artifact_path = Path(args.artifact)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    artifact = joblib.load(artifact_path)
    model = artifact["model"]
    X_test = artifact["X_test"]
    y_test = np.asarray(artifact["y_test"]).astype(int)
    feature_names = artifact.get("feature_names", [])
    metadata = artifact.get("metadata", {}) or {}

    y_proba = _positive_proba(model, X_test)
    thresholds = np.linspace(0.10, 0.90, args.steps)
    threshold_df = _compute_rows(y_test, y_proba, thresholds)
    best_threshold = _choose_best_threshold(threshold_df, args.optimize_for)

    summary = {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "artifact_path": str(artifact_path),
        "model_type": metadata.get("model_type", "unknown"),
        "source": metadata.get("source", "unknown"),
        "feature_version": metadata.get("feature_version", "v2"),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "recommended_threshold": best_threshold,
        "optimized_for": args.optimize_for,
        "top_feature_importance": _top_feature_importance(model, feature_names, top_k=10),
        "threshold_metrics": threshold_df.to_dict(orient="records"),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_name = (
        f"threshold_analysis_"
        f"{metadata.get('model_type', 'model')}_"
        f"{metadata.get('source', 'source')}.json"
    )
    out_path = OUTPUT_DIR / out_name
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Saved threshold analysis to {out_path}")
    print(f"Recommended threshold ({args.optimize_for}): {best_threshold:.4f}")


if __name__ == "__main__":
    main()