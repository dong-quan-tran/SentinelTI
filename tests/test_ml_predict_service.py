from __future__ import annotations

from pathlib import Path

import joblib
import pytest

from sentinelti.ml import predict as predict_module
from sentinelti.ml import service as service_module


class DummyModel:
    def __init__(self, prob: float):
        self.prob = prob

    def predict_proba(self, x):
        return [[1.0 - self.prob, self.prob] for _ in range(len(x))]


@pytest.fixture
def temp_models_dir(tmp_path, monkeypatch):
    models_dir = tmp_path / "models"
    models_dir.mkdir()

    monkeypatch.setattr(predict_module, "MODELS_DIR", models_dir)
    return models_dir


def write_artifact(models_dir: Path, name: str, artifact: dict) -> Path:
    path = models_dir / f"url_classifier_{name}.joblib"
    joblib.dump(artifact, path)
    return path


def test_load_model_reads_new_metadata_artifact(temp_models_dir, monkeypatch):
    artifact = {
        "artifact_version": "1.0",
        "model": DummyModel(0.91),
        "feature_names": ["f1", "f2"],
        "metadata": {
            "model_type": "xgb",
            "trained_at": "2026-05-18T03:55:05Z",
            "dataset_name": "kaggle",
            "dataset_source": {"use_real_data": True},
            "metrics": {"roc_auc": 0.999},
            "threshold": 0.8,
            "feature_version": "v2",
            "class_labels": {"benign": 0, "malicious": 1},
            "class_counts": {"train_0": 10, "train_1": 5},
            "training_params": {"n_estimators": 400},
        },
    }
    write_artifact(temp_models_dir, "xgb", artifact)

    model, feature_names, metadata = predict_module.load_model(prefer="xgb")

    assert isinstance(model, DummyModel)
    assert feature_names == ["f1", "f2"]
    assert metadata["model_type"] == "xgb"
    assert metadata["trained_at"] == "2026-05-18T03:55:05Z"
    assert metadata["dataset_name"] == "kaggle"
    assert metadata["threshold"] == 0.8
    assert metadata["feature_version"] == "v2"
    assert metadata["metrics"]["roc_auc"] == 0.999
    assert metadata["artifact_path"].endswith("url_classifier_xgb.joblib")


def test_load_model_supports_legacy_artifact_shape(temp_models_dir):
    artifact = {
        "model_type": "logreg",
        "model": DummyModel(0.33),
        "feature_names": ["f1", "f2"],
        "threshold": 0.6,
        "feature_version": "v2",
    }
    write_artifact(temp_models_dir, "logreg", artifact)

    model, feature_names, metadata = predict_module.load_model(prefer="logreg")

    assert isinstance(model, DummyModel)
    assert feature_names == ["f1", "f2"]
    assert metadata["model_type"] == "logreg"
    assert metadata["threshold"] == 0.6
    assert metadata["feature_version"] == "v2"
    assert metadata["artifact_version"] == "legacy"


def test_predict_url_with_metadata_returns_expected_shape(temp_models_dir, monkeypatch):
    artifact = {
        "artifact_version": "1.0",
        "model": DummyModel(0.91),
        "feature_names": ["f1", "f2", "f3"],
        "metadata": {
            "model_type": "xgb",
            "threshold": 0.75,
            "feature_version": "v2",
            "metrics": {"roc_auc": 0.99},
        },
    }
    write_artifact(temp_models_dir, "xgb", artifact)

    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {"f1": 1.0, "f2": 2.0, "f3": 3.0},
    )

    result = predict_module.predict_url_with_metadata("http://example.com/login")

    assert set(result.keys()) == {"label", "prob_malicious", "threshold", "model_meta"}
    assert result["label"] == 1
    assert result["prob_malicious"] == 0.91
    assert result["threshold"] == 0.75
    assert result["model_meta"]["model_type"] == "xgb"


def test_predict_url_uses_artifact_threshold(temp_models_dir, monkeypatch):
    artifact = {
        "artifact_version": "1.0",
        "model": DummyModel(0.70),
        "feature_names": ["f1"],
        "metadata": {
            "model_type": "xgb",
            "threshold": 0.8,
            "feature_version": "v2",
        },
    }
    write_artifact(temp_models_dir, "xgb", artifact)

    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {"f1": 1.0},
    )
    monkeypatch.setenv("SENTINELTI_MALICIOUS_THRESHOLD", "0.2")

    label, prob = predict_module.predict_url("http://example.com")

    assert prob == 0.70
    assert label == 0


def test_predict_url_falls_back_to_env_threshold_when_artifact_has_none(temp_models_dir, monkeypatch):
    artifact = {
        "artifact_version": "1.0",
        "model": DummyModel(0.70),
        "feature_names": ["f1"],
        "metadata": {
            "model_type": "xgb",
            "feature_version": "v2",
        },
    }
    write_artifact(temp_models_dir, "xgb", artifact)

    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {"f1": 1.0},
    )
    monkeypatch.setenv("SENTINELTI_MALICIOUS_THRESHOLD", "0.65")

    label, prob = predict_module.predict_url("http://example.com")

    assert prob == 0.70
    assert label == 1


def test_predict_url_raises_when_features_are_missing(temp_models_dir, monkeypatch):
    artifact = {
        "artifact_version": "1.0",
        "model": DummyModel(0.90),
        "feature_names": ["f1", "f2"],
        "metadata": {
            "model_type": "xgb",
            "threshold": 0.75,
            "feature_version": "v2",
        },
    }
    write_artifact(temp_models_dir, "xgb", artifact)

    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {"f1": 1.0},
    )

    with pytest.raises(RuntimeError, match="Feature extraction is missing expected model features"):
        predict_module.predict_url("http://example.com")


def test_score_url_returns_expected_payload(monkeypatch):
    monkeypatch.setattr(
        service_module,
        "predict_url_with_metadata",
        lambda url: {
            "label": 1,
            "prob_malicious": 0.88,
            "threshold": 0.75,
            "model_meta": {"model_type": "xgb", "feature_version": "v2"},
        },
    )

    result = service_module.score_url("http://example.com")

    assert result == {
        "url": "http://example.com",
        "label": 1,
        "prob_malicious": 0.88,
        "threshold": 0.75,
        "model_meta": {"model_type": "xgb", "feature_version": "v2"},
    }


def test_score_urls_maps_over_inputs(monkeypatch):
    monkeypatch.setattr(
        service_module,
        "score_url",
        lambda url: {"url": url, "label": 0, "prob_malicious": 0.1, "threshold": 0.75, "model_meta": {}},
    )

    results = service_module.score_urls(["a", "b", "c"])

    assert [r["url"] for r in results] == ["a", "b", "c"]
    assert all("threshold" in r for r in results)