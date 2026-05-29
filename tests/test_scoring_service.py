from __future__ import annotations

import pytest

import sentinelti.services.scoring_service as scoring_service_module


def test_build_model_meta_response_uses_model_metadata_builder(monkeypatch):
    raw_metadata = {
        "model_type": "xgb",
        "threshold": 0.75,
        "metrics": {"roc_auc": 0.99},
    }
    normalized_metadata = {
        "model_type": "xgb",
        "threshold": 0.75,
        "threshold_source": "metadata",
        "recommended_threshold": None,
        "recommended_threshold_source": None,
        "metrics": {
            "roc_auc": 0.99,
            "average_precision": None,
        },
        "class_labels": {
            "benign": None,
            "malicious": None,
        },
        "class_counts": {
            "train_0": None,
            "train_1": None,
            "test_0": None,
            "test_1": None,
        },
        "dataset_source": {},
        "training_params": {},
        "training_notes": [],
        "top_features": [],
        "model_summary": {
            "model_type": "xgb",
            "dataset_name": None,
            "trained_at": None,
            "top_features": [],
        },
    }

    monkeypatch.setattr(
        scoring_service_module.predict,
        "get_loaded_model_metadata",
        lambda: raw_metadata,
    )
    monkeypatch.setattr(
        scoring_service_module.model_metadata,
        "build_model_meta",
        lambda metadata: normalized_metadata,
    )

    result = scoring_service_module.build_model_meta_response()

    assert result == normalized_metadata


def test_build_score_response_returns_expected_combined_shape(monkeypatch):
    deterministic_result = {
        "url": "https://phishy.example/login",
        "label": 1,
        "prob_malicious": 0.91,
        "heuristic": {
            "score": 0.82,
            "reasons": ["Suspicious login keyword", "Nested redirect parameter"],
        },
        "final_label": "malicious",
        "risk": "high",
        "reasons": ["Model score above threshold", "Multiple phishing indicators"],
        "explanation": {
            "summary": "This URL looks likely malicious and should be treated as unsafe.",
            "why_flagged": "The machine-learning model assigned a very high malicious probability.",
            "user_action": "Do not open the link or enter credentials.",
            "technical_notes": [
                "Model score above threshold",
                "Multiple phishing indicators",
            ],
            "risk": "high",
            "final_label": "malicious",
        },
    }

    model_meta = {
        "artifact_version": "1.0",
        "model_type": "xgb",
        "trained_at": "2026-05-18T03:55:05Z",
        "dataset_name": "kaggle",
        "dataset_source": {"use_real_data": True},
        "feature_version": "v2",
        "threshold": 0.75,
        "threshold_source": "metadata",
        "recommended_threshold": 0.8,
        "recommended_threshold_source": "artifact",
        "metrics": {"roc_auc": 0.999, "average_precision": 0.998},
        "class_labels": {"benign": 0, "malicious": 1},
        "class_counts": {"train_0": 10, "train_1": 5, "test_0": 4, "test_1": 2},
        "training_params": {"n_estimators": 400},
        "training_notes": [],
        "top_features": [
            {"feature": "has_ip", "importance": 0.31},
            {"feature": "url_length", "importance": 0.22},
        ],
        "artifact_path": "sentinelti/models/url_classifier_xgb.joblib",
        "model_summary": {
            "model_type": "xgb",
            "dataset_name": "kaggle",
            "trained_at": "2026-05-18T03:55:05Z",
            "top_features": [
                {"feature": "has_ip", "importance": 0.31},
                {"feature": "url_length", "importance": 0.22},
            ],
        },
    }

    monkeypatch.setattr(
        scoring_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_result,
    )
    monkeypatch.setattr(
        scoring_service_module,
        "build_model_meta_response",
        lambda: model_meta,
    )

    result = scoring_service_module.build_score_response(
        "https://phishy.example/login"
    )

    assert result["schema_version"] == "1.2"
    assert result["url"] == "https://phishy.example/login"
    assert result["label"] == 1
    assert result["prob_malicious"] == 0.91
    assert result["threshold"] == 0.75
    assert result["heuristic"] == deterministic_result["heuristic"]
    assert result["final_label"] == "malicious"
    assert result["risk"] == "high"
    assert result["reasons"] == deterministic_result["reasons"]
    assert result["explanation"] == deterministic_result["explanation"]
    assert result["model_meta"] == model_meta


def test_build_score_response_uses_model_meta_threshold(monkeypatch):
    deterministic_result = {
        "url": "https://example.com",
        "label": 0,
        "prob_malicious": 0.70,
        "heuristic": {
            "score": 0.15,
            "reasons": [],
        },
        "final_label": "benign",
        "risk": "low",
        "reasons": ["Probability remains below effective model threshold"],
        "explanation": {
            "summary": "This URL currently appears low risk.",
            "why_flagged": "The effective threshold remains higher than the advisory threshold.",
            "user_action": "Proceed carefully.",
            "technical_notes": ["Probability remains below effective model threshold"],
            "risk": "low",
            "final_label": "benign",
        },
    }

    model_meta = {
        "model_type": "xgb",
        "threshold": 0.8,
        "threshold_source": "metadata",
        "recommended_threshold": 0.3,
        "recommended_threshold_source": "calibrated-grid",
        "metrics": {"roc_auc": 0.99, "average_precision": 0.98},
        "class_labels": {"benign": 0, "malicious": 1},
        "class_counts": {"train_0": 10, "train_1": 5, "test_0": 4, "test_1": 2},
        "dataset_source": {},
        "training_params": {},
        "training_notes": [],
        "top_features": [],
        "model_summary": {
            "model_type": "xgb",
            "dataset_name": None,
            "trained_at": None,
            "top_features": [],
        },
    }

    monkeypatch.setattr(
        scoring_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_result,
    )
    monkeypatch.setattr(
        scoring_service_module,
        "build_model_meta_response",
        lambda: model_meta,
    )

    result = scoring_service_module.build_score_response("https://example.com")

    assert result["threshold"] == 0.8
    assert result["prob_malicious"] == 0.70
    assert result["final_label"] == "benign"
    assert result["model_meta"]["threshold"] == 0.8
    assert result["model_meta"]["recommended_threshold"] == 0.3


def test_build_explanation_response_returns_only_explanation(monkeypatch):
    deterministic_result = {
        "url": "https://www.google.com/",
        "label": 0,
        "prob_malicious": 0.02,
        "heuristic": {
            "score": 0.0,
            "reasons": [],
        },
        "final_label": "benign",
        "risk": "low",
        "reasons": [
            "Model predicts benign with probability 0.98 (malicious probability 0.02).",
            "No strong malicious indicators detected by model or heuristics.",
        ],
        "explanation": {
            "summary": "This URL currently appears low risk, although no automated check is perfect.",
            "why_flagged": "The machine-learning model found relatively few malicious patterns.",
            "user_action": "Proceed carefully and still verify the domain manually before sharing sensitive information.",
            "technical_notes": [
                "Model predicts benign with probability 0.98 (malicious probability 0.02).",
                "No strong malicious indicators detected by model or heuristics.",
            ],
            "risk": "low",
            "final_label": "benign",
        },
    }

    monkeypatch.setattr(
        scoring_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_result,
    )

    result = scoring_service_module.build_explanation_response("https://www.google.com/")

    assert result == deterministic_result["explanation"]


def test_build_score_response_propagates_runtime_error_from_enrich_score(monkeypatch):
    def boom(_url):
        raise RuntimeError("feature extraction failed")

    monkeypatch.setattr(scoring_service_module.scoring, "enrich_score", boom)

    with pytest.raises(RuntimeError, match="feature extraction failed"):
        scoring_service_module.build_score_response("https://example.com")


def test_build_model_meta_response_propagates_runtime_error_from_metadata_loader(monkeypatch):
    def boom():
        raise RuntimeError("metadata load failed")

    monkeypatch.setattr(scoring_service_module.predict, "get_loaded_model_metadata", boom)

    with pytest.raises(RuntimeError, match="metadata load failed"):
        scoring_service_module.build_model_meta_response()