from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from sentinelti.ml.dataset import (
    build_dummy_dataset,
    build_real_dataset,
    build_urlhaus_plus_benign_dataset,
)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def _load_dataset(
    use_real_data: bool,
    csv_path: str | None,
    max_samples: int | None,
    use_urlhaus: bool,
    urlhaus_max_malicious: int | None,
    urlhaus_max_benign: int | None,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
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


def _load_artifact(model_name: str) -> Dict[str, Any]:
    path = MODELS_DIR / f"url_classifier_{model_name}.joblib"
    if not path.exists():
        raise FileNotFoundError(f"Model artifact not found for {model_name}: {path}")
    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or "model" not in artifact:
        raise RuntimeError(f"Invalid model artifact format for {model_name} in {path}")
    return artifact


def _evaluate_model_on_split(
    model_name: str,
    artifact: Dict[str, Any],
    X_train,
    X_test,
    y_train,
    y_test,
) -> Dict[str, Any]:
    model = artifact["model"]

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    report = classification_report(
        y_test,
        y_pred,
        output_dict=True,
        zero_division=0,
    )
    roc_auc = float(roc_auc_score(y_test, y_prob))
    avg_precision = float(average_precision_score(y_test, y_prob))

    return {
        "model": model_name,
        "roc_auc": roc_auc,
        "average_precision": avg_precision,
        "classification_report": report,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare URL models on a shared split")
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
    parser.add_argument(
        "--models",
        nargs="*",
        default=["logreg", "xgb", "lgbm"],
        help="Model names to compare (default: logreg xgb lgbm)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to save JSON summary",
    )

    args = parser.parse_args()

    use_real_data = args.source == "kaggle"
    use_urlhaus = args.source == "urlhaus"

    X, y, _feature_names = _load_dataset(
        use_real_data=use_real_data,
        csv_path=args.csv_path if args.source in ("kaggle", "urlhaus") else None,
        max_samples=args.max_samples,
        use_urlhaus=use_urlhaus,
        urlhaus_max_malicious=args.urlhaus_max_malicious,
        urlhaus_max_benign=args.urlhaus_max_benign,
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y,
    )

    results: Dict[str, Any] = {}
    for name in args.models:
        try:
            artifact = _load_artifact(name)
        except FileNotFoundError as exc:
            print(f"[warn] {exc}")
            continue

        metrics = _evaluate_model_on_split(
            model_name=name,
            artifact=artifact,
            X_train=X_train,
            X_test=X_test,
            y_train=y_train,
            y_test=y_test,
        )
        results[name] = metrics
        print(f"\n=== {name} ===")
        print(f"ROC AUC: {metrics['roc_auc']:.4f}")
        print(f"Average precision: {metrics['average_precision']:.4f}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved comparison summary to {out_path}")


if __name__ == "__main__":
    main()