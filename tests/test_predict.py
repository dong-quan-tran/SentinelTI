from __future__ import annotations

import pytest
import joblib

from sentinelti.ml import predict


class DummyModel:
    def __init__(self, prob: float):
        self.prob = prob

    def predict_proba(self, x):
        return [[1.0 - self.prob, self.prob] for _ in range(len(x))]


def test_get_malicious_threshold_default(monkeypatch) -> None:
    monkeypatch.delenv("SENTINELTI_MALICIOUS_THRESHOLD", raising=False)
    assert predict.get_malicious_threshold() == 0.75


def test_load_model_prefers_xgb_when_present(monkeypatch) -> None:
    xgb_path = predict.get_model_path("xgb")
    logreg_path = predict.get_model_path("logreg")

    def fake_exists(self):
        return self == xgb_path or self == logreg_path

    def fake_load(path):
        if path == xgb_path:
            return {
                "model": DummyModel(0.91),
                "feature_names": ["f1", "f2"],
                "model_type": "xgb",
            }
        raise AssertionError("logreg should not be loaded when xgb is available")

    monkeypatch.setattr(type(xgb_path), "exists", fake_exists)
    monkeypatch.setattr(predict.joblib, "load", fake_load)

    model, feature_names, metadata = predict.load_model()

    assert isinstance(model, DummyModel)
    assert feature_names == ["f1", "f2"]
    assert metadata["model_type"] == "xgb"


def test_load_model_falls_back_to_logreg_when_xgb_missing(monkeypatch) -> None:
    xgb_path = predict.get_model_path("xgb")
    logreg_path = predict.get_model_path("logreg")

    def fake_exists(self):
        return self == logreg_path

    def fake_load(path):
        if path == logreg_path:
            return {
                "model": DummyModel(0.33),
                "feature_names": ["f1", "f2"],
                "model_type": "logreg",
            }
        raise AssertionError("only logreg should be loaded in this scenario")

    monkeypatch.setattr(type(xgb_path), "exists", fake_exists)
    monkeypatch.setattr(predict.joblib, "load", fake_load)

    model, feature_names, metadata = predict.load_model()

    assert isinstance(model, DummyModel)
    assert feature_names == ["f1", "f2"]
    assert metadata["model_type"] == "logreg"


def test_load_model_respects_prefer_logreg(monkeypatch) -> None:
    xgb_path = predict.get_model_path("xgb")
    logreg_path = predict.get_model_path("logreg")

    def fake_exists(self):
        return self == xgb_path or self == logreg_path

    def fake_load(path):
        if path == logreg_path:
            return {
                "model": DummyModel(0.20),
                "feature_names": ["f1"],
                "model_type": "logreg",
            }
        raise AssertionError("xgb should not be loaded when prefer='logreg' and logreg exists")

    monkeypatch.setattr(type(xgb_path), "exists", fake_exists)
    monkeypatch.setattr(predict.joblib, "load", fake_load)

    model, feature_names, metadata = predict.load_model(prefer="logreg")

    assert isinstance(model, DummyModel)
    assert feature_names == ["f1"]
    assert metadata["model_type"] == "logreg"


def test_load_model_legacy_returns_model_type_string(monkeypatch) -> None:
    xgb_path = predict.get_model_path("xgb")

    def fake_exists(self):
        return self == xgb_path

    def fake_load(path):
        return {
            "model": DummyModel(0.91),
            "feature_names": ["f1", "f2"],
            "model_type": "xgb",
        }

    monkeypatch.setattr(type(xgb_path), "exists", fake_exists)
    monkeypatch.setattr(predict.joblib, "load", fake_load)

    model, feature_names, model_type = predict.load_model_legacy()

    assert isinstance(model, DummyModel)
    assert feature_names == ["f1", "f2"]
    assert model_type == "xgb"


def test_predict_url_returns_label_and_probability(monkeypatch) -> None:
    dummy_model = DummyModel(0.80)

    def fake_load_model(prefer="xgb"):
        return dummy_model, ["f1", "f2"], {"model_type": "xgb", "threshold": 0.75}

    def fake_extract_features(url: str):
        assert url == "http://example.com/login"
        return {"f1": 1.0, "f2": 2.0}

    monkeypatch.setattr(predict, "load_model", fake_load_model)
    monkeypatch.setattr(predict, "extract_features", fake_extract_features)

    label, prob = predict.predict_url("http://example.com/login")

    assert label == 1
    assert abs(prob - 0.80) < 1e-9


def test_predict_url_returns_benign_below_threshold(monkeypatch) -> None:
    dummy_model = DummyModel(0.30)

    def fake_load_model(prefer="xgb"):
        return dummy_model, ["f1"], {"model_type": "logreg", "threshold": 0.75}

    def fake_extract_features(url: str):
        return {"f1": 5.0}

    monkeypatch.setattr(predict, "load_model", fake_load_model)
    monkeypatch.setattr(predict, "extract_features", fake_extract_features)

    label, prob = predict.predict_url("http://example.com")

    assert label == 0
    assert abs(prob - 0.30) < 1e-9


def test_predict_url_raises_if_features_missing(monkeypatch) -> None:
    dummy_model = DummyModel(0.5)

    def fake_load_model(prefer="xgb"):
        return dummy_model, ["f1", "f2"], {"model_type": "xgb", "threshold": 0.75}

    def fake_extract_features(url: str):
        return {"f1": 1.0}

    monkeypatch.setattr(predict, "load_model", fake_load_model)
    monkeypatch.setattr(predict, "extract_features", fake_extract_features)

    with pytest.raises(RuntimeError, match="Feature extraction is missing expected model features"):
        predict.predict_url("http://example.com")


import pytest

import sentinelti.ml.predict as predict_module


class DummyModel:
    def __init__(self, prob=0.9):
        self.prob = prob

    def predict_proba(self, x):
        return [[1.0 - self.prob, self.prob]]


def test_build_feature_vector_raises_runtime_error_for_missing_features(monkeypatch):
    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {
            "url_length": 42,
            "has_ip": 0,
        },
    )

    with pytest.raises(RuntimeError) as excinfo:
        predict_module._build_feature_vector(
            "https://example.com",
            ["url_length", "has_ip", "num_dots"],
        )

    message = str(excinfo.value)
    assert "missing expected model features" in message.lower()
    assert "num_dots" in message


def test_build_feature_vector_ignores_extra_features(monkeypatch):
    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {
            "url_length": 42,
            "has_ip": 0,
            "num_dots": 3,
            "unused_extra_feature": 999,
        },
    )

    vector = predict_module._build_feature_vector(
        "https://example.com",
        ["url_length", "has_ip", "num_dots"],
    )

    assert vector.shape == (1, 3)
    assert vector.tolist() == [[42.0, 0.0, 3.0]]


def test_score_url_propagates_feature_extraction_runtime_error(monkeypatch):
    monkeypatch.setattr(
        predict_module,
        "load_model",
        lambda prefer="xgb": (
            DummyModel(prob=0.95),
            ["url_length", "has_ip", "num_dots"],
            {
                "model_type": "xgb",
                "threshold": 0.75,
            },
        ),
    )

    monkeypatch.setattr(
        predict_module,
        "get_effective_model_metadata",
        lambda prefer="xgb": {
            "model_type": "xgb",
            "threshold": 0.75,
            "threshold_source": "metadata",
            "recommended_threshold": None,
            "recommended_threshold_source": None,
            "feature_count": 3,
        },
    )

    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {
            "url_length": 42,
            "has_ip": 0,
        },
    )

    with pytest.raises(RuntimeError) as excinfo:
        predict_module._score_url("https://example.com")

    message = str(excinfo.value)
    assert "missing expected model features" in message.lower()
    assert "num_dots" in message


def test_score_url_uses_effective_threshold_not_recommended_threshold(monkeypatch):
    monkeypatch.setattr(
        predict_module,
        "load_model",
        lambda prefer="xgb": (
            DummyModel(prob=0.80),
            ["url_length"],
            {
                "model_type": "xgb",
                "threshold": 0.75,
                "recommended_threshold": 0.95,
            },
        ),
    )

    monkeypatch.setattr(
        predict_module,
        "get_effective_model_metadata",
        lambda prefer="xgb": {
            "model_type": "xgb",
            "threshold": 0.75,
            "threshold_source": "metadata",
            "recommended_threshold": 0.95,
            "recommended_threshold_source": "artifact_metadata",
            "feature_count": 1,
        },
    )

    monkeypatch.setattr(
        predict_module,
        "extract_features",
        lambda url: {"url_length": 42},
    )

    result = predict_module._score_url("https://example.com")

    assert result["prob_malicious"] == 0.80
    assert result["threshold"] == 0.75
    assert result["label"] == 1
    assert result["model_meta"]["recommended_threshold"] == 0.95


def test_get_effective_model_metadata_sets_missing_recommended_fields(monkeypatch):
    monkeypatch.setattr(
        predict_module,
        "load_model",
        lambda prefer="xgb": (
            DummyModel(prob=0.80),
            ["url_length", "has_ip"],
            {
                "model_type": "xgb",
                "threshold": 0.75,
            },
        ),
    )

    metadata = predict_module.get_effective_model_metadata()

    assert metadata["threshold"] == 0.75
    assert metadata["threshold_source"] == "metadata"
    assert metadata["feature_count"] == 2
    assert metadata["recommended_threshold"] is None
    assert metadata["recommended_threshold_source"] is None

import types

from sentinelti.ml import predict as predict_module


def test_preferred_model_order_defaults_to_xgb_first():
    assert predict_module._preferred_model_order("xgb") == ["xgb", "lgbm", "logreg"]


def test_preferred_model_order_respects_logreg_and_lgbm():
    assert predict_module._preferred_model_order("logreg") == ["logreg", "xgb", "lgbm"]
    assert predict_module._preferred_model_order("lgbm") == ["lgbm", "xgb", "logreg"]


def test_get_loaded_model_type_uses_metadata_model_type(tmp_path, monkeypatch):
    artifact_path = tmp_path / "url_classifier_lgbm.joblib"
    artifact = {
        "model": object(),
        "feature_names": ["f1"],
        "metadata": {"model_type": "lgbm"},
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path)

    monkeypatch.setattr(predict_module, "MODELS_DIR", artifact_path.parent)

    model_type = predict_module.get_loaded_model_type(prefer="lgbm")
    assert model_type == "lgbm"

def test_preferred_model_order_defaults_to_xgb_first():
    assert predict_module._preferred_model_order("xgb") == ["xgb", "lgbm", "logreg"]


def test_preferred_model_order_respects_logreg_and_lgbm():
    assert predict_module._preferred_model_order("logreg") == ["logreg", "xgb", "lgbm"]
    assert predict_module._preferred_model_order("lgbm") == ["lgbm", "xgb", "logreg"]