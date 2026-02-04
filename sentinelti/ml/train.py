from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from sentinelti.ml.dataset import build_dummy_dataset, build_real_dataset



MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODELS_DIR / "url_classifier.joblib"


def train_url_model(
    use_real_data: bool = False,
    csv_path: str | None = None,
    max_samples: int | None = None,
) -> None:
    if use_real_data:
        if csv_path is None:
            raise ValueError("csv_path is required when use_real_data=True")
        X, y, feature_names = build_real_dataset(
            csv_path,
            url_column="url",
            label_column="label",
            benign_label_value="benign",
            malicious_label_value="malicious",
            max_samples=max_samples,
        )
    else:
        X, y, feature_names = build_dummy_dataset()

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
    print("Evaluation on holdout set:")
    print(classification_report(y_test, y_pred))

    artifact = {
        "model": clf,
        "feature_names": feature_names,
    }
    joblib.dump(artifact, MODEL_PATH)
    print(f"Saved model to {MODEL_PATH}")


if __name__ == "__main__":
    train_url_model(
        use_real_data=True,
        csv_path="data/urldata.csv",
        max_samples=1000,
    )

