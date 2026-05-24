from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from sentinelti.ml.dataset import (
    build_dummy_dataset,
    build_real_dataset,
    build_urlhaus_plus_benign_dataset,
)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)

METRICS_DIR = Path("docs/model_metrics")
METRICS_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_THRESHOLD = 0.75
FEATURE_VERSION = "v2"
ARTIFACT_VERSION = "1.0"


def get_model_path(model_name: str) -> Path:
    return MODELS_DIR / f"url_classifier_{model_name}.joblib"


def load_url_model(prefer: str = "xgb"):
    """
    Backward-compatible loader used by older tests/code paths.

    Returns:
        tuple[model, feature_names]
    """
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

        model = artifact.get("model")
        feature_names = artifact.get("feature_names", [])
        return model, feature_names

    if last_error is not None:
        raise RuntimeError("Failed to load any URL model artifact") from last_error
    raise FileNotFoundError("No trained URL model artifacts found")


def load_dataset_for_training(
    use_real_data: bool = False,
    csv_path: str | None = None,
    max_samples: int | None = None,
    use_urlhaus: bool = False,
    urlhaus_max_malicious: int | None = 1000,
    urlhaus_max_benign: int | None = 1000,
):
    if use_urlhaus:
        if csv_path is None:
            raise ValueError("csv_path is required when use_urlhaus=True (for benigns)")
        X, y, feature_names = build_urlhaus_plus_benign_dataset(
            benign_csv_path=csv_path,
            max_malicious=urlhaus_max_malicious,
            max_benign=urlhaus_max_benign,
        )
    elif use_real_data:
        if csv_path is None:
            raise ValueError("csv_path is required when use_real_data=True")
        X, y, feature_names = build_real_dataset(
            csv_path=csv_path,
            url_column="url",
            label_column="label",
            benign_label_value="benign",
            malicious_label_value="malicious",
            max_samples=max_samples,
        )
    else:
        X, y, feature_names = build_dummy_dataset()

    return X, y, feature_names


def _dataset_name(use_real_data: bool, use_urlhaus: bool) -> str:
    if use_urlhaus:
        return "urlhaus"
    if use_real_data:
        return "kaggle"
    return "dummy"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _to_builtin(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _to_builtin(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_builtin(v) for v in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return str(value)
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    return str(value)


def _safe_roc_auc(y_true, y_prob) -> float | None:
    try:
        return float(roc_auc_score(y_true, y_prob))
    except ValueError:
        return None


def _safe_average_precision(y_true, y_prob) -> float | None:
    try:
        return float(average_precision_score(y_true, y_prob))
    except ValueError:
        return None


def _extract_estimator(clf: Any) -> Any:
    if isinstance(clf, Pipeline):
        return clf.named_steps.get("classifier", clf)
    return clf


def _top_feature_importances(
    clf: Any,
    feature_names: list[str],
    top_k: int = 10,
) -> list[dict[str, Any]]:
    estimator = _extract_estimator(clf)

    if hasattr(estimator, "feature_importances_"):
        importances = np.asarray(estimator.feature_importances_).reshape(-1)
    elif hasattr(estimator, "coef_"):
        coef = np.asarray(estimator.coef_)
        if coef.ndim == 2:
            importances = np.mean(np.abs(coef), axis=0)
        else:
            importances = np.abs(coef).reshape(-1)
    else:
        return []

    if len(importances) != len(feature_names):
        return []

    ranked = sorted(
        zip(feature_names, importances),
        key=lambda item: item[1],
        reverse=True,
    )[:top_k]

    return [
        {"feature": str(name), "importance": float(score)}
        for name, score in ranked
    ]


def _recommended_threshold_metadata() -> dict[str, Any]:
    return {
        "recommended_threshold": DEFAULT_THRESHOLD,
        "recommended_threshold_source": "artifact",
    }


def _build_metadata(
    *,
    model_name: str,
    clf: Any,
    feature_names: list[str],
    use_real_data: bool,
    csv_path: str | None,
    max_samples: int | None,
    use_urlhaus: bool,
    urlhaus_max_malicious: int | None,
    urlhaus_max_benign: int | None,
    y_train,
    y_test,
    y_pred,
    y_prob,
) -> dict[str, Any]:
    report_dict = classification_report(
        y_test,
        y_pred,
        output_dict=True,
        zero_division=0,
    )
    roc_auc = _safe_roc_auc(y_test, y_prob)
    average_precision = _safe_average_precision(y_test, y_prob)

    metadata = {
        "model_type": model_name,
        "trained_at": _utc_now_iso(),
        "dataset_name": _dataset_name(use_real_data, use_urlhaus),
        "dataset_source": {
            "use_real_data": use_real_data,
            "use_urlhaus": use_urlhaus,
            "csv_path": csv_path,
            "max_samples": max_samples,
            "urlhaus_max_malicious": urlhaus_max_malicious,
            "urlhaus_max_benign": urlhaus_max_benign,
        },
        "feature_version": FEATURE_VERSION,
        "threshold": DEFAULT_THRESHOLD,
        "class_labels": {
            "benign": 0,
            "malicious": 1,
        },
        "class_counts": {
            "train_0": int((y_train == 0).sum()),
            "train_1": int((y_train == 1).sum()),
            "test_0": int((y_test == 0).sum()),
            "test_1": int((y_test == 1).sum()),
        },
        "metrics": {
            "classification_report": _to_builtin(report_dict),
            "roc_auc": roc_auc,
            "average_precision": average_precision,
        },
        "training_params": _to_builtin(clf.get_params()),
        "top_features": _top_feature_importances(clf, feature_names, top_k=10),
        **_recommended_threshold_metadata(),
    }
    return metadata


def _save_metrics_json(model_name: str, metadata: dict[str, Any]) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    metrics_path = METRICS_DIR / f"url_model_{model_name}_{metadata['dataset_name']}_{ts}.json"

    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "model": model_name,
        "trained_at": metadata["trained_at"],
        "dataset_name": metadata["dataset_name"],
        "dataset_source": metadata["dataset_source"],
        "feature_version": metadata["feature_version"],
        "threshold": metadata["threshold"],
        "recommended_threshold": metadata.get("recommended_threshold"),
        "recommended_threshold_source": metadata.get("recommended_threshold_source"),
        "class_labels": metadata["class_labels"],
        "class_counts": metadata["class_counts"],
        "metrics": metadata["metrics"],
        "training_params": metadata["training_params"],
        "top_features": metadata.get("top_features", []),
        # New field: a place to surface convergence or other training notes.
        "training_notes": metadata.get("metrics", {}).get("training_notes", []),
    }

    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return metrics_path


def _save_artifact(
    model_name: str,
    clf: Any,
    feature_names: list[str],
    X_test,
    y_test,
    metadata: dict[str, Any],
) -> Path:
    artifact = {
        "artifact_version": ARTIFACT_VERSION,
        "model": clf,
        "feature_names": list(feature_names),
        "X_test": X_test,
        "y_test": y_test,
        "metadata": metadata,
    }

    model_path = get_model_path(model_name)
    joblib.dump(artifact, model_path)
    return model_path


def _train_and_save(
    *,
    model_name: str,
    clf: Any,
    use_real_data: bool,
    csv_path: str | None,
    max_samples: int | None,
    use_urlhaus: bool,
    urlhaus_max_malicious: int | None,
    urlhaus_max_benign: int | None,
) -> None:
    X, y, feature_names = load_dataset_for_training(
        use_real_data=use_real_data,
        csv_path=csv_path,
        max_samples=max_samples,
        use_urlhaus=use_urlhaus,
        urlhaus_max_malicious=urlhaus_max_malicious,
        urlhaus_max_benign=urlhaus_max_benign,
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y,
    )

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    print(f"Evaluation on holdout set ({model_name}):")
    print(classification_report(y_test, y_pred, zero_division=0))

    metadata = _build_metadata(
        model_name=model_name,
        clf=clf,
        feature_names=feature_names,
        use_real_data=use_real_data,
        csv_path=csv_path,
        max_samples=max_samples,
        use_urlhaus=use_urlhaus,
        urlhaus_max_malicious=urlhaus_max_malicious,
        urlhaus_max_benign=urlhaus_max_benign,
        y_train=y_train,
        y_test=y_test,
        y_pred=y_pred,
        y_prob=y_prob,
    )

    metrics_path = _save_metrics_json(model_name, metadata)
    print(f"Saved metrics to {metrics_path}")

    model_path = _save_artifact(
        model_name=model_name,
        clf=clf,
        feature_names=feature_names,
        X_test=X_test,
        y_test=y_test,
        metadata=metadata,
    )
    print(f"Saved model to {model_path}")


def train_url_model(
    use_real_data: bool = False,
    csv_path: str | None = None,
    max_samples: int | None = None,
    use_urlhaus: bool = False,
    urlhaus_max_malicious: int | None = 1000,
    urlhaus_max_benign: int | None = 1000,
) -> None:
    clf = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    max_iter=4000,
                    solver="lbfgs",
                ),
            ),
        ]
    )
    _train_and_save(
        model_name="logreg",
        clf=clf,
        use_real_data=use_real_data,
        csv_path=csv_path,
        max_samples=max_samples,
        use_urlhaus=use_urlhaus,
        urlhaus_max_malicious=urlhaus_max_malicious,
        urlhaus_max_benign=urlhaus_max_benign,
    )


def train_url_model_xgb(
    use_real_data: bool = False,
    csv_path: str | None = None,
    max_samples: int | None = None,
    use_urlhaus: bool = False,
    urlhaus_max_malicious: int | None = 1000,
    urlhaus_max_benign: int | None = 1000,
) -> None:
    X, y, _ = load_dataset_for_training(
        use_real_data=use_real_data,
        csv_path=csv_path,
        max_samples=max_samples,
        use_urlhaus=use_urlhaus,
        urlhaus_max_malicious=urlhaus_max_malicious,
        urlhaus_max_benign=urlhaus_max_benign,
    )

    X_train, _, y_train, _ = train_test_split(
        X,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y,
    )

    scale_pos_weight = float((y_train == 0).sum()) / max(float((y_train == 1).sum()), 1.0)

    clf = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
    )

    _train_and_save(
        model_name="xgb",
        clf=clf,
        use_real_data=use_real_data,
        csv_path=csv_path,
        max_samples=max_samples,
        use_urlhaus=use_urlhaus,
        urlhaus_max_malicious=urlhaus_max_malicious,
        urlhaus_max_benign=urlhaus_max_benign,
    )


def main():
    parser = argparse.ArgumentParser(description="Train SentinelTI URL model")
    parser.add_argument(
        "--model",
        choices=["logreg", "xgb"],
        default="xgb",
        help="Which model to train (logreg or xgb)",
    )
    parser.add_argument(
        "--source",
        choices=["kaggle", "urlhaus", "dummy"],
        default="kaggle",
        help="Which data source to use",
    )
    parser.add_argument(
        "--csv-path",
        default="data/urldata.csv",
        help="Path to Kaggle/benign CSV file (used for kaggle/urlhaus sources)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Optional max samples for Kaggle/dataset",
    )
    parser.add_argument(
        "--urlhaus-max-malicious",
        type=int,
        default=1000,
        help="Max malicious samples from URLhaus",
    )
    parser.add_argument(
        "--urlhaus-max-benign",
        type=int,
        default=1000,
        help="Max benign samples from Kaggle when using URLhaus",
    )

    args = parser.parse_args()

    use_real_data = args.source == "kaggle"
    use_urlhaus = args.source == "urlhaus"

    if args.model == "logreg":
        train_url_model(
            use_real_data=use_real_data,
            csv_path=args.csv_path if args.source in ("kaggle", "urlhaus") else None,
            max_samples=args.max_samples,
            use_urlhaus=use_urlhaus,
            urlhaus_max_malicious=args.urlhaus_max_malicious,
            urlhaus_max_benign=args.urlhaus_max_benign,
        )
    else:
        train_url_model_xgb(
            use_real_data=use_real_data,
            csv_path=args.csv_path if args.source in ("kaggle", "urlhaus") else None,
            max_samples=args.max_samples,
            use_urlhaus=use_urlhaus,
            urlhaus_max_malicious=args.urlhaus_max_malicious,
            urlhaus_max_benign=args.urlhaus_max_benign,
        )


if __name__ == "__main__":
    main()