from __future__ import annotations

import pytest

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