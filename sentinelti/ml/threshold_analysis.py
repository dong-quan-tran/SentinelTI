from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

OUTPUT_DIR = Path("docs/model_metrics")
DEFAULT_STEPS = 81
DEFAULT_MIN_THRESHOLD = 0.10
DEFAULT_MAX_THRESHOLD = 0.90


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_artifact(artifact: dict[str, Any], artifact_path: Path) -> None:
    if not isinstance(artifact, dict):
        raise RuntimeError(f"Invalid artifact format in {artifact_path}")
    if "model" not in artifact:
        raise RuntimeError(f"Artifact missing 'model' in {artifact_path}")
    if "X_test" not in artifact:
        raise RuntimeError(f"Artifact missing 'X_test' in {artifact_path}")
    if "y_test" not in artifact:
        raise RuntimeError(f"Artifact missing 'y_test' in {artifact_path}")


def _positive_proba(model, X) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        if getattr(proba, "ndim", 1) == 2 and proba.shape[1] >= 2:
            return np.asarray(proba[:, 1]).reshape(-1)
        return np.asarray(proba).reshape(-1)

    if hasattr(model, "decision_function"):
        scores = np.asarray(model.decision_function(X)).reshape(-1)
        return 1.0 / (1.0 + np.exp(-scores))

    raise ValueError("Model must support predict_proba() or decision_function().")


def _safe_roc_auc(y_true: np.ndarray, y_proba: np.ndarray) -> float | None:
    try:
        return float(roc_auc_score(y_true, y_proba))
    except ValueError:
        return None


def _confusion_counts(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, int]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def _compute_rows(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    thresholds: np.ndarray,
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []

    for threshold in thresholds:
        y_pred = (y_proba >= threshold).astype(int)
        cm = _confusion_counts(y_true, y_pred)

        rows.append(
            {
                "threshold": round(float(threshold), 6),
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                "f1": float(f1_score(y_true, y_pred, zero_division=0)),
                "predicted_positive_rate": float(np.mean(y_pred)),
                "tn": cm["tn"],
                "fp": cm["fp"],
                "fn": cm["fn"],
                "tp": cm["tp"],
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


def _top_feature_importance(model, feature_names: list[str], top_k: int = 10) -> list[dict[str, Any]]:
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


def main() -> None:
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

    if args.steps < 2:
        raise ValueError("--steps must be at least 2")

    artifact_path = Path(args.artifact)
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    artifact = joblib.load(artifact_path)
    _validate_artifact(artifact, artifact_path)

    model = artifact["model"]
    X_test = artifact["X_test"]
    y_test = np.asarray(artifact["y_test"]).astype(int)
    feature_names = list(artifact.get("feature_names", []))
    metadata = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}

    y_proba = _positive_proba(model, X_test)
    thresholds = np.linspace(DEFAULT_MIN_THRESHOLD, DEFAULT_MAX_THRESHOLD, args.steps)
    threshold_df = _compute_rows(y_test, y_proba, thresholds)
    best_threshold = _choose_best_threshold(threshold_df, args.optimize_for)

    dataset_name = metadata.get("dataset_name", metadata.get("source", "unknown"))
    roc_auc = _safe_roc_auc(y_test, y_proba)

    recommended_row = (
        threshold_df.loc[threshold_df["threshold"] == best_threshold]
        .head(1)
        .to_dict(orient="records")
    )
    recommended_metrics = recommended_row[0] if recommended_row else {}

    summary = {
        "analyzed_at": _utc_now_iso(),
        "artifact_path": str(artifact_path),
        "artifact_version": artifact.get("artifact_version", "unknown"),
        "model_type": metadata.get("model_type", "unknown"),
        "dataset_name": dataset_name,
        "feature_version": metadata.get("feature_version", "v2"),
        "artifact_threshold": metadata.get("threshold"),
        "roc_auc": roc_auc,
        "recommended_threshold": best_threshold,
        "optimized_for": args.optimize_for,
        "recommended_threshold_metrics": recommended_metrics,
        "top_feature_importance": _top_feature_importance(model, feature_names, top_k=10),
        "threshold_metrics": threshold_df.to_dict(orient="records"),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_name = (
        f"threshold_analysis_"
        f"{metadata.get('model_type', 'model')}_"
        f"{dataset_name}.json"
    )
    out_path = OUTPUT_DIR / out_name
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Saved threshold analysis to {out_path}")
    print(f"Recommended threshold ({args.optimize_for}): {best_threshold:.4f}")
    if roc_auc is not None:
        print(f"ROC AUC: {roc_auc:.4f}")
    else:
        print("ROC AUC: unavailable (test labels did not support ROC AUC calculation)")


if __name__ == "__main__":
    main()