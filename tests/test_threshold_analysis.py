from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

from sentinelti.ml.threshold_analysis import _choose_best_threshold


def test_choose_best_threshold_returns_best_metric_value():
    import pandas as pd

    df = pd.DataFrame(
        [
            {"threshold": 0.3, "f1": 0.70, "precision": 0.60, "recall": 0.85, "accuracy": 0.72},
            {"threshold": 0.5, "f1": 0.81, "precision": 0.80, "recall": 0.82, "accuracy": 0.80},
            {"threshold": 0.7, "f1": 0.79, "precision": 0.91, "recall": 0.70, "accuracy": 0.78},
        ]
    )

    best = _choose_best_threshold(df, "f1")

    assert best == 0.5


def test_threshold_analysis_artifact_shape(tmp_path: Path):
    X = np.array(
        [
            [0.0, 0.0],
            [0.1, 0.2],
            [0.8, 0.9],
            [0.9, 0.8],
            [0.2, 0.1],
            [0.7, 0.8],
        ]
    )
    y = np.array([0, 0, 1, 1, 0, 1])

    model = LogisticRegression().fit(X, y)

    artifact_path = tmp_path / "artifact.joblib"
    joblib.dump(
        {
            "model": model,
            "feature_names": ["f1", "f2"],
            "X_test": X,
            "y_test": y,
            "metadata": {
                "model_type": "logreg",
                "source": "dummy",
                "feature_version": "v2",
            },
        },
        artifact_path,
    )

    artifact = joblib.load(artifact_path)

    assert "model" in artifact
    assert "feature_names" in artifact
    assert "X_test" in artifact
    assert "y_test" in artifact
    assert artifact["metadata"]["model_type"] == "logreg"