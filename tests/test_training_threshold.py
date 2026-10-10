import numpy as np

from sentinelti.ml import train


def test_training_report_uses_production_threshold(monkeypatch):
    captured = {}

    class FakeClassifier:
        def fit(self, X, y):
            return self

        def predict(self, X):
            raise AssertionError("Do not use the estimator default threshold")

        def predict_proba(self, X):
            threshold = train.DEFAULT_THRESHOLD
            probabilities = np.array([
                np.nextafter(threshold, -np.inf),
                threshold,
                np.nextafter(threshold, np.inf),
            ])
            return np.column_stack([1 - probabilities, probabilities])

    def capture_metadata(**kwargs):
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(train, "_build_metadata", capture_metadata)
    monkeypatch.setattr(train, "_save_metrics_json", lambda *args: "unused.json")
    monkeypatch.setattr(
        train, "_save_artifact", lambda **kwargs: "unused.joblib"
    )

    X = np.zeros((3, 1))
    y = np.array([0, 1, 1])

    train._train_and_save_from_split(
        model_name="xgb",
        clf=FakeClassifier(),
        feature_names=["fixture"],
        X_train=X,
        X_test=X,
        y_train=y,
        y_test=y,
        use_real_data=True,
        csv_path="unused.csv",
        max_samples=None,
        use_urlhaus=False,
        urlhaus_max_malicious=None,
        urlhaus_max_benign=None,
    )

    np.testing.assert_array_equal(captured["y_pred"], [0, 1, 1])
