from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pytest

from sentinelti.ml import train as train_module


@pytest.fixture
def temp_train_dirs(tmp_path, monkeypatch):
    models_dir = tmp_path / "models"
    metrics_dir = tmp_path / "docs" / "model_metrics"
    models_dir.mkdir(parents=True)
    metrics_dir.mkdir(parents=True)

    monkeypatch.setattr(train_module, "MODELS_DIR", models_dir)
    monkeypatch.setattr(train_module, "METRICS_DIR", metrics_dir)

    return models_dir, metrics_dir


@pytest.fixture
def tiny_training_dataset():
    feature_names = ["f1", "f2", "f3"]

    X = np.array(
        [
            [0.0, 0.1, 0.0],
            [0.1, 0.2, 0.1],
            [0.2, 0.1, 0.0],
            [0.9, 0.8, 1.0],
            [0.8, 0.9, 0.9],
            [1.0, 0.7, 0.8],
            [0.05, 0.0, 0.1],
            [0.95, 1.0, 0.85],
            [0.15, 0.1, 0.05],
            [0.85, 0.75, 0.95],
        ],
        dtype=float,
    )
    y = np.array([0, 0, 0, 1, 1, 1, 0, 1, 0, 1], dtype=int)

    return X, y, feature_names


def test_dataset_name_helper():
    assert train_module._dataset_name(use_real_data=False, use_urlhaus=False) == "dummy"
    assert train_module._dataset_name(use_real_data=True, use_urlhaus=False) == "kaggle"
    assert train_module._dataset_name(use_real_data=False, use_urlhaus=True) == "urlhaus"


def test_to_builtin_converts_numpy_like_values():
    payload = {
        "int_value": np.int64(3),
        "float_value": np.float64(1.25),
        "nested": {
            "items": [np.int64(1), np.float64(2.5)],
        },
    }

    result = train_module._to_builtin(payload)

    assert result == {
        "int_value": 3,
        "float_value": 1.25,
        "nested": {"items": [1, 2.5]},
    }


def test_save_artifact_writes_expected_shape(temp_train_dirs):
    models_dir, _metrics_dir = temp_train_dirs

    clf = {"kind": "dummy-model"}
    feature_names = ["f1", "f2"]
    X_test = np.array([[0.1, 0.2], [0.8, 0.9]], dtype=float)
    y_test = np.array([0, 1], dtype=int)
    metadata = {
        "model_type": "logreg",
        "trained_at": "2026-05-19T00:00:00Z",
        "dataset_name": "dummy",
        "dataset_source": {"use_real_data": False, "use_urlhaus": False},
        "feature_version": "v2",
        "threshold": 0.75,
        "class_labels": {"benign": 0, "malicious": 1},
        "class_counts": {"train_0": 3, "train_1": 3, "test_0": 1, "test_1": 1},
        "metrics": {"roc_auc": 1.0, "average_precision": 1.0},
        "training_params": {"max_iter": 2000},
        "top_features": [],
        "recommended_threshold": 0.75,
        "recommended_threshold_source": "artifact",
    }

    path = train_module._save_artifact(
        "logreg",
        clf,
        feature_names,
        X_test,
        y_test,
        metadata,
    )

    assert path == models_dir / "url_classifier_logreg.joblib"
    assert path.exists()

    artifact = joblib.load(path)
    assert artifact["artifact_version"] == train_module.ARTIFACT_VERSION
    assert artifact["model"] == clf
    assert artifact["feature_names"] == feature_names
    assert np.array_equal(artifact["X_test"], X_test)
    assert np.array_equal(artifact["y_test"], y_test)
    assert artifact["metadata"] == metadata


def test_save_metrics_json_writes_expected_payload(temp_train_dirs):
    _models_dir, metrics_dir = temp_train_dirs

    metadata = {
        "model_type": "xgb",
        "trained_at": "2026-05-19T00:00:00Z",
        "dataset_name": "dummy",
        "dataset_source": {
            "use_real_data": False,
            "use_urlhaus": False,
            "csv_path": None,
            "max_samples": None,
            "urlhaus_max_malicious": 1000,
            "urlhaus_max_benign": 1000,
        },
        "feature_version": "v2",
        "threshold": 0.75,
        "class_labels": {"benign": 0, "malicious": 1},
        "class_counts": {"train_0": 3, "train_1": 3, "test_0": 1, "test_1": 1},
        "metrics": {
            "classification_report": {"0": {"precision": 1.0}, "1": {"precision": 1.0}},
            "roc_auc": 1.0,
            "average_precision": 1.0,
        },
        "training_params": {"n_estimators": 400},
        "top_features": [],
        "recommended_threshold": 0.75,
        "recommended_threshold_source": "artifact",
    }

    path = train_module._save_metrics_json("xgb", metadata)

    assert path.exists()
    assert path.parent == metrics_dir
    assert path.name.startswith("url_model_xgb_")
    assert path.suffix == ".json"

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "artifact_version": train_module.ARTIFACT_VERSION,
        "model": "xgb",
        "trained_at": "2026-05-19T00:00:00Z",
        "dataset_name": "dummy",
        "dataset_source": {
            "use_real_data": False,
            "use_urlhaus": False,
            "csv_path": None,
            "max_samples": None,
            "urlhaus_max_malicious": 1000,
            "urlhaus_max_benign": 1000,
        },
        "feature_version": "v2",
        "threshold": 0.75,
        "recommended_threshold": 0.75,
        "recommended_threshold_source": "artifact",
        "class_labels": {"benign": 0, "malicious": 1},
        "class_counts": {"train_0": 3, "train_1": 3, "test_0": 1, "test_1": 1},
        "metrics": {
            "classification_report": {"0": {"precision": 1.0}, "1": {"precision": 1.0}},
            "roc_auc": 1.0,
            "average_precision": 1.0,
        },
        "training_params": {"n_estimators": 400},
        "top_features": [],
    }


def test_load_dataset_for_training_uses_dummy_builder(monkeypatch, tiny_training_dataset):
    monkeypatch.setattr(
        train_module,
        "build_dummy_dataset",
        lambda: tiny_training_dataset,
    )

    X, y, feature_names = train_module.load_dataset_for_training()

    assert X.shape == (10, 3)
    assert y.shape == (10,)
    assert feature_names == ["f1", "f2", "f3"]


def test_load_dataset_for_training_requires_csv_for_real_data():
    with pytest.raises(ValueError, match="csv_path is required when use_real_data=True"):
        train_module.load_dataset_for_training(use_real_data=True, csv_path=None)


def test_load_dataset_for_training_requires_csv_for_urlhaus():
    with pytest.raises(ValueError, match="csv_path is required when use_urlhaus=True"):
        train_module.load_dataset_for_training(use_urlhaus=True, csv_path=None)


def test_load_dataset_for_training_uses_real_builder(monkeypatch, tiny_training_dataset):
    calls = {}

    def fake_build_real_dataset(
        csv_path,
        url_column,
        label_column,
        benign_label_value,
        malicious_label_value,
        max_samples,
    ):
        calls["args"] = {
            "csv_path": csv_path,
            "url_column": url_column,
            "label_column": label_column,
            "benign_label_value": benign_label_value,
            "malicious_label_value": malicious_label_value,
            "max_samples": max_samples,
        }
        return tiny_training_dataset

    monkeypatch.setattr(train_module, "build_real_dataset", fake_build_real_dataset)

    X, y, feature_names = train_module.load_dataset_for_training(
        use_real_data=True,
        csv_path="data/urldata.csv",
        max_samples=123,
    )

    assert X.shape == (10, 3)
    assert y.shape == (10,)
    assert feature_names == ["f1", "f2", "f3"]
    assert calls["args"] == {
        "csv_path": "data/urldata.csv",
        "url_column": "url",
        "label_column": "label",
        "benign_label_value": "benign",
        "malicious_label_value": "malicious",
        "max_samples": 123,
    }


def test_load_dataset_for_training_uses_urlhaus_builder(monkeypatch, tiny_training_dataset):
    calls = {}

    def fake_build_urlhaus_plus_benign_dataset(
        benign_csv_path,
        max_malicious,
        max_benign,
    ):
        calls["args"] = {
            "benign_csv_path": benign_csv_path,
            "max_malicious": max_malicious,
            "max_benign": max_benign,
        }
        return tiny_training_dataset

    monkeypatch.setattr(
        train_module,
        "build_urlhaus_plus_benign_dataset",
        fake_build_urlhaus_plus_benign_dataset,
    )

    X, y, feature_names = train_module.load_dataset_for_training(
        use_urlhaus=True,
        csv_path="data/urldata.csv",
        urlhaus_max_malicious=50,
        urlhaus_max_benign=75,
    )

    assert X.shape == (10, 3)
    assert y.shape == (10,)
    assert feature_names == ["f1", "f2", "f3"]
    assert calls["args"] == {
        "benign_csv_path": "data/urldata.csv",
        "max_malicious": 50,
        "max_benign": 75,
    }


def test_train_url_model_writes_metrics_and_artifact(
    temp_train_dirs, monkeypatch, tiny_training_dataset
):
    models_dir, metrics_dir = temp_train_dirs

    monkeypatch.setattr(
        train_module,
        "load_dataset_for_training",
        lambda **kwargs: tiny_training_dataset,
    )

    train_module.train_url_model(use_real_data=False)

    model_path = models_dir / "url_classifier_logreg.joblib"
    assert model_path.exists()

    artifact = joblib.load(model_path)
    assert artifact["artifact_version"] == train_module.ARTIFACT_VERSION
    assert artifact["feature_names"] == ["f1", "f2", "f3"]

    metadata = artifact["metadata"]
    assert metadata["model_type"] == "logreg"
    assert metadata["dataset_name"] == "dummy"
    assert metadata["feature_version"] == train_module.FEATURE_VERSION
    assert metadata["threshold"] == train_module.DEFAULT_THRESHOLD
    assert metadata["recommended_threshold"] == train_module.DEFAULT_THRESHOLD
    assert metadata["recommended_threshold_source"] == "artifact"
    assert metadata["class_labels"] == {"benign": 0, "malicious": 1}
    assert set(metadata["class_counts"].keys()) == {"train_0", "train_1", "test_0", "test_1"}
    assert "roc_auc" in metadata["metrics"]
    assert "average_precision" in metadata["metrics"]
    assert "classification_report" in metadata["metrics"]
    assert isinstance(metadata["training_params"], dict)

    metrics_files = list(metrics_dir.glob("url_model_logreg_*.json"))
    assert len(metrics_files) == 1

    payload = json.loads(metrics_files[0].read_text(encoding="utf-8"))
    assert payload["artifact_version"] == train_module.ARTIFACT_VERSION
    assert payload["model"] == "logreg"
    assert payload["dataset_name"] == "dummy"
    assert payload["feature_version"] == train_module.FEATURE_VERSION
    assert payload["threshold"] == train_module.DEFAULT_THRESHOLD
    assert payload["recommended_threshold"] == train_module.DEFAULT_THRESHOLD
    assert payload["recommended_threshold_source"] == "artifact"


def test_train_url_model_xgb_writes_metrics_and_artifact(
    temp_train_dirs, monkeypatch, tiny_training_dataset
):
    models_dir, metrics_dir = temp_train_dirs

    monkeypatch.setattr(
        train_module,
        "load_dataset_for_training",
        lambda **kwargs: tiny_training_dataset,
    )

    train_module.train_url_model_xgb(use_real_data=False)

    model_path = models_dir / "url_classifier_xgb.joblib"
    assert model_path.exists()

    artifact = joblib.load(model_path)
    assert artifact["artifact_version"] == train_module.ARTIFACT_VERSION
    assert artifact["feature_names"] == ["f1", "f2", "f3"]

    metadata = artifact["metadata"]
    assert metadata["model_type"] == "xgb"
    assert metadata["dataset_name"] == "dummy"
    assert metadata["feature_version"] == train_module.FEATURE_VERSION
    assert metadata["threshold"] == train_module.DEFAULT_THRESHOLD
    assert metadata["recommended_threshold"] == train_module.DEFAULT_THRESHOLD
    assert metadata["recommended_threshold_source"] == "artifact"
    assert metadata["class_labels"] == {"benign": 0, "malicious": 1}
    assert set(metadata["class_counts"].keys()) == {"train_0", "train_1", "test_0", "test_1"}
    assert "roc_auc" in metadata["metrics"]
    assert "average_precision" in metadata["metrics"]
    assert "classification_report" in metadata["metrics"]
    assert isinstance(metadata["training_params"], dict)

    metrics_files = list(metrics_dir.glob("url_model_xgb_*.json"))
    assert len(metrics_files) == 1

    payload = json.loads(metrics_files[0].read_text(encoding="utf-8"))
    assert payload["artifact_version"] == train_module.ARTIFACT_VERSION
    assert payload["model"] == "xgb"
    assert payload["dataset_name"] == "dummy"
    assert payload["feature_version"] == train_module.FEATURE_VERSION
    assert payload["threshold"] == train_module.DEFAULT_THRESHOLD
    assert payload["recommended_threshold"] == train_module.DEFAULT_THRESHOLD
    assert payload["recommended_threshold_source"] == "artifact"


def test_load_url_model_reads_saved_logreg_artifact(
    temp_train_dirs, monkeypatch, tiny_training_dataset
):
    models_dir, _metrics_dir = temp_train_dirs

    monkeypatch.setattr(
        train_module,
        "load_dataset_for_training",
        lambda **kwargs: tiny_training_dataset,
    )

    train_module.train_url_model(use_real_data=False)

    assert (models_dir / "url_classifier_logreg.joblib").exists()

    model, feature_names = train_module.load_url_model(prefer="logreg")

    assert model is not None
    assert feature_names == ["f1", "f2", "f3"]


def test_load_url_model_falls_back_when_preferred_missing(temp_train_dirs):
    models_dir, _metrics_dir = temp_train_dirs

    artifact = {
        "model": {"kind": "xgb"},
        "feature_names": ["f1", "f2"],
    }
    joblib.dump(artifact, models_dir / "url_classifier_xgb.joblib")

    model, feature_names = train_module.load_url_model(prefer="logreg")

    assert model == {"kind": "xgb"}
    assert feature_names == ["f1", "f2"]


def test_load_url_model_raises_when_no_artifacts_exist(temp_train_dirs):
    with pytest.raises(FileNotFoundError, match="No trained URL model artifacts found"):
        train_module.load_url_model(prefer="xgb")


class DummyEstimator:
    def __repr__(self) -> str:
        return "DummyEstimator(repr)"


def test_to_builtin_stringifies_non_serializable_objects():
    estimator = DummyEstimator()
    payload = {
        "name": "model",
        "params": {
            "estimator": estimator,
            "max_iter": np.int64(100),
        },
    }

    result = train_module._to_builtin(payload)

    assert result["name"] == "model"
    assert result["params"]["max_iter"] == 100
    assert isinstance(result["params"]["estimator"], str)
    assert "DummyEstimator" in result["params"]["estimator"]