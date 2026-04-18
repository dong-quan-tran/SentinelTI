from sentinelti.ml.train import get_model_path, load_url_model
import joblib


def test_load_url_model_prefers_xgb_when_both_exist(tmp_path, monkeypatch):
    monkeypatch.setattr("sentinelti.ml.train.MODELS_DIR", tmp_path)

    # Fake artifacts
    xgb_path = get_model_path("xgb")
    logreg_path = get_model_path("logreg")

    xgb_artifact = {"model": "xgb_model", "feature_names": ["f1"]}
    logreg_artifact = {"model": "logreg_model", "feature_names": ["f1"]}

    joblib.dump(xgb_artifact, xgb_path)
    joblib.dump(logreg_artifact, logreg_path)

    model, feature_names = load_url_model()
    assert model == "xgb_model"
    assert feature_names == ["f1"]