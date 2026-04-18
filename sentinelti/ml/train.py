from __future__ import annotations

from pathlib import Path
import argparse

from xgboost import XGBClassifier

from datetime import datetime
import json
import os

from typing import Tuple, Any

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from sentinelti.ml.dataset import build_dummy_dataset, build_real_dataset, build_urlhaus_plus_benign_dataset



MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


def get_model_path(model_name: str) -> Path:
    return MODELS_DIR / f"url_classifier_{model_name}.joblib"

def load_url_model(prefer: str = "xgb") -> Tuple[Any, list[str]]:
    """
    Load a trained URL model artifact.

    Preference order (by default):
    - Try XGBoost artifact.
    - Fallback to Logistic Regression artifact.
    """
    # Map logical names to filenames
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

def train_url_model(
    use_real_data: bool = False,
    csv_path: str | None = None,
    max_samples: int | None = None,
    use_urlhaus: bool = False,
    urlhaus_max_malicious: int | None = 1000,
    urlhaus_max_benign: int | None = 1000,
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

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("Evaluation on holdout set (LogisticRegression):")
    print(classification_report(y_test, y_pred))

    report_dict = classification_report(y_test, y_pred, output_dict=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    os.makedirs("docs/model_metrics", exist_ok=True)
    source = "urlhaus" if use_urlhaus else ("kaggle" if use_real_data else "dummy")
    metrics_path = f"docs/model_metrics/url_model_{ts}.json"

    metrics = {
        "model": "logreg",  # or "xgb" in train_url_model_xgb
        "train_source": {
            "use_real_data": use_real_data,
            "use_urlhaus": use_urlhaus,
            "csv_path": csv_path,
        },
        "class_counts": {
            "train_0": int((y_train == 0).sum()),
            "train_1": int((y_train == 1).sum()),
            "test_0": int((y_test == 0).sum()),
            "test_1": int((y_test == 1).sum()),
        },
        "report": report_dict,
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved metrics to {metrics_path}")


    artifact = {
        "model_type": "logreg",
        "model": clf,
        "feature_names": feature_names,
    }
    model_path = get_model_path("logreg")
    joblib.dump(artifact, model_path)
    print(f"Saved model to {model_path}")

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


def train_url_model_xgb(
    use_real_data: bool = False,
    csv_path: str | None = None,
    max_samples: int | None = None,
    use_urlhaus: bool = False,
    urlhaus_max_malicious: int | None = 1000,
    urlhaus_max_benign: int | None = 1000,
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

    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()

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

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("Evaluation on holdout set (XGBoost):")
    print(classification_report(y_test, y_pred))

    report_dict = classification_report(y_test, y_pred, output_dict=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    os.makedirs("docs/model_metrics", exist_ok=True)
    source = "urlhaus" if use_urlhaus else ("kaggle" if use_real_data else "dummy")
    metrics_path = f"docs/model_metrics/url_model_{ts}.json"

    metrics = {
        "model": "xgb",  # or "xgb" in train_url_model_xgb
        "train_source": {
            "use_real_data": use_real_data,
            "use_urlhaus": use_urlhaus,
            "csv_path": csv_path,
        },
        "class_counts": {
            "train_0": int((y_train == 0).sum()),
            "train_1": int((y_train == 1).sum()),
            "test_0": int((y_test == 0).sum()),
            "test_1": int((y_test == 1).sum()),
        },
        "report": report_dict,
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved metrics to {metrics_path}")


    artifact = {
        "model_type": "xgb",
        "model": clf,
        "feature_names": feature_names,
    }
    model_path = get_model_path("xgb")
    joblib.dump(artifact, model_path)
    print(f"Saved model to {model_path}")


def main():
    parser = argparse.ArgumentParser(description="Train SentinelTi URL model")
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


