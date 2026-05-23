from __future__ import annotations

from fastapi.testclient import TestClient

import sentinelti.api as api_module

client = TestClient(api_module.app)


def _set_test_auth(monkeypatch):
    monkeypatch.setattr(api_module, "API_KEY", "test-key")
    api_module._rate_limit_store.clear()


def _mock_model_meta(monkeypatch, model_type: str = "xgb"):
    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "artifact_version": "1.0",
            "model_type": model_type,
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
            "top_features": [
                {"feature": "has_ip", "importance": 0.31},
                {"feature": "url_length", "importance": 0.22},
            ],
            "artifact_path": "sentinelti/models/url_classifier_xgb.joblib",
        },
    )


def test_health_returns_ok():
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_score_url_requires_api_key():
    response = client.post(
        "/score-url",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_explain_score_requires_api_key():
    response = client.post(
        "/explain-score",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_score_url_returns_typed_response_with_explanation(monkeypatch):
    _set_test_auth(monkeypatch)
    _mock_model_meta(monkeypatch, model_type="xgb")

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: {
            "url": url,
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
        },
    )

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://phishy.example/login"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["schema_version"] == "1.2"
    assert body["url"] == "https://phishy.example/login"
    assert body["label"] == 1
    assert body["prob_malicious"] == 0.91
    assert body["threshold"] == 0.75
    assert body["final_label"] == "malicious"
    assert body["risk"] == "high"

    assert body["heuristic"]["score"] == 0.82
    assert "Suspicious login keyword" in body["heuristic"]["reasons"]

    assert body["explanation"]["summary"] == (
        "This URL looks likely malicious and should be treated as unsafe."
    )
    assert body["explanation"]["risk"] == "high"
    assert body["explanation"]["final_label"] == "malicious"
    assert "Model score above threshold" in body["explanation"]["technical_notes"]

    assert body["model_meta"]["model_type"] == "xgb"
    assert body["model_meta"]["feature_version"] == "v2"
    assert body["model_meta"]["threshold"] == 0.75
    assert body["model_meta"]["threshold_source"] == "metadata"
    assert body["model_meta"]["recommended_threshold"] == 0.8
    assert body["model_meta"]["recommended_threshold_source"] == "artifact"
    assert body["model_meta"]["metrics"]["roc_auc"] == 0.999
    assert body["model_meta"]["metrics"]["average_precision"] == 0.998


def test_score_urls_returns_results_list_with_explanations(monkeypatch):
    _set_test_auth(monkeypatch)
    _mock_model_meta(monkeypatch, model_type="logreg")

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: {
            "url": url,
            "label": 0,
            "prob_malicious": 0.11,
            "heuristic": {
                "score": 0.10,
                "reasons": [],
            },
            "final_label": "benign",
            "risk": "low",
            "reasons": ["No major indicators found"],
            "explanation": {
                "summary": "This URL currently appears low risk, although no automated check is perfect.",
                "why_flagged": "The machine-learning model found relatively few malicious patterns.",
                "user_action": "Proceed carefully and verify the destination independently.",
                "technical_notes": ["No major indicators found"],
                "risk": "low",
                "final_label": "benign",
            },
        },
    )

    response = client.post(
        "/score-urls",
        headers={"X-API-KEY": "test-key"},
        json={"urls": ["https://example.com", "https://example.org"]},
    )

    assert response.status_code == 200
    body = response.json()

    assert "results" in body
    assert len(body["results"]) == 2
    assert body["results"][0]["schema_version"] == "1.2"
    assert body["results"][0]["model_meta"]["model_type"] == "logreg"
    assert body["results"][0]["model_meta"]["recommended_threshold"] == 0.8
    assert body["results"][0]["model_meta"]["recommended_threshold_source"] == "artifact"
    assert body["results"][0]["explanation"]["final_label"] == "benign"
    assert body["results"][1]["url"] == "https://example.org"


def test_explain_score_returns_explanation_response(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: {
            "url": url,
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
        },
    )

    response = client.post(
        "/explain-score",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://www.google.com/"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["final_label"] == "benign"
    assert body["risk"] == "low"
    assert "summary" in body
    assert "why_flagged" in body
    assert "user_action" in body
    assert len(body["technical_notes"]) == 2


def test_score_url_validation_error_for_missing_url(monkeypatch):
    _set_test_auth(monkeypatch)

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={},
    )

    assert response.status_code == 422


def test_score_urls_validation_error_for_missing_urls(monkeypatch):
    _set_test_auth(monkeypatch)

    response = client.post(
        "/score-urls",
        headers={"X-API-KEY": "test-key"},
        json={},
    )

    assert response.status_code == 422


def test_explain_score_validation_error_for_missing_url(monkeypatch):
    _set_test_auth(monkeypatch)

    response = client.post(
        "/explain-score",
        headers={"X-API-KEY": "test-key"},
        json={},
    )

    assert response.status_code == 422


def test_model_info_returns_metadata_response(monkeypatch):
    _set_test_auth(monkeypatch)
    _mock_model_meta(monkeypatch, model_type="xgb")

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "1.1"
    assert body["model_meta"]["model_type"] == "xgb"
    assert body["model_meta"]["feature_version"] == "v2"
    assert body["model_meta"]["recommended_threshold"] == 0.8
    assert body["model_meta"]["recommended_threshold_source"] == "artifact"
    assert body["model_meta"]["metrics"]["roc_auc"] == 0.999
    assert body["model_meta"]["top_features"] == [
        {"feature": "has_ip", "importance": 0.31},
        {"feature": "url_length", "importance": 0.22},
    ]


def test_score_url_sets_rate_limit_headers(monkeypatch):
    _set_test_auth(monkeypatch)
    _mock_model_meta(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: {
            "url": url,
            "label": 0,
            "prob_malicious": 0.05,
            "heuristic": {"score": 0.0, "reasons": []},
            "final_label": "benign",
            "risk": "low",
            "reasons": [],
            "explanation": {
                "summary": "Looks low risk.",
                "why_flagged": "",
                "user_action": "Proceed carefully.",
                "technical_notes": [],
                "risk": "low",
                "final_label": "benign",
            },
        },
    )

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == str(api_module.RATE_LIMIT_REQUESTS)
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers


def test_model_info_uses_safe_defaults_for_partial_metadata(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "model_type": "xgb",
            "threshold": 0.75,
        },
    )

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["model_meta"]["model_type"] == "xgb"
    assert body["model_meta"]["threshold"] == 0.75
    assert body["model_meta"]["threshold_source"] == "metadata"
    assert body["model_meta"]["recommended_threshold"] is None
    assert body["model_meta"]["recommended_threshold_source"] is None
    assert body["model_meta"]["dataset_source"] == {}
    assert body["model_meta"]["metrics"] == {
        "roc_auc": None,
        "average_precision": None,
    }
    assert body["model_meta"]["class_labels"] == {
        "benign": None,
        "malicious": None,
    }
    assert body["model_meta"]["class_counts"] == {
        "train_0": None,
        "train_1": None,
        "test_0": None,
        "test_1": None,
    }
    assert body["model_meta"]["training_params"] == {}


def test_score_url_returns_structured_runtime_error(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: (_ for _ in ()).throw(RuntimeError("model load failed")),
    )

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal scoring error",
        "error_type": "runtime_error",
    }


def test_explain_score_returns_structured_runtime_error(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: (_ for _ in ()).throw(RuntimeError("feature extraction failed")),
    )

    response = client.post(
        "/explain-score",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal scoring error",
        "error_type": "runtime_error",
    }


def test_score_url_response_contains_expected_top_level_keys(monkeypatch):
    _set_test_auth(monkeypatch)
    _mock_model_meta(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: {
            "url": url,
            "label": 1,
            "prob_malicious": 0.83,
            "heuristic": {"score": 1.2, "reasons": ["login keyword"]},
            "final_label": "suspicious",
            "risk": "medium",
            "reasons": ["Flagged by ML and heuristics"],
            "explanation": {
                "summary": "Suspicious traits detected.",
                "why_flagged": "Elevated model probability.",
                "user_action": "Verify independently.",
                "technical_notes": ["Flagged by ML and heuristics"],
                "risk": "medium",
                "final_label": "suspicious",
            },
        },
    )

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://example.com/login"},
    )

    assert response.status_code == 200
    body = response.json()

    assert set(body.keys()) == {
        "schema_version",
        "url",
        "label",
        "prob_malicious",
        "threshold",
        "heuristic",
        "final_label",
        "risk",
        "reasons",
        "explanation",
        "model_meta",
    }


def test_score_url_includes_top_features_in_model_meta(monkeypatch):
    _set_test_auth(monkeypatch)
    _mock_model_meta(monkeypatch, model_type="xgb")

    monkeypatch.setattr(
        api_module,
        "enrich_score",
        lambda url: {
            "url": url,
            "label": 1,
            "prob_malicious": 0.88,
            "heuristic": {
                "score": 0.8,
                "reasons": ["Suspicious keyword"],
            },
            "final_label": "malicious",
            "risk": "high",
            "reasons": ["High ML score"],
            "explanation": {
                "summary": "This URL looks likely malicious.",
                "why_flagged": "The model assigned a high malicious probability.",
                "user_action": "Do not open the link.",
                "technical_notes": ["High ML score"],
                "risk": "high",
                "final_label": "malicious",
            },
        },
    )

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://phishy.example/login"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_meta"]["top_features"] == [
        {"feature": "has_ip", "importance": 0.31},
        {"feature": "url_length", "importance": 0.22},
    ]


def test_model_info_defaults_top_features_to_empty_list(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "model_type": "xgb",
            "threshold": 0.75,
        },
    )

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_meta"]["top_features"] == []


def test_model_info_filters_invalid_top_feature_entries(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "model_type": "xgb",
            "threshold": 0.75,
            "top_features": [
                {"feature": "url_length", "importance": 0.42},
                {"feature": "missing_importance"},
                {"importance": 0.5},
                "bad-entry",
                {"feature": "has_ip", "importance": "0.21"},
            ],
        },
    )

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_meta"]["top_features"] == [
        {"feature": "url_length", "importance": 0.42},
        {"feature": "has_ip", "importance": 0.21},
    ]


def test_model_info_returns_threshold_source_from_metadata(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "model_type": "xgb",
            "threshold": 0.6,
            "threshold_source": "env",
            "metrics": {},
        },
    )

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_meta"]["threshold"] == 0.6
    assert body["model_meta"]["threshold_source"] == "env"


def test_model_info_uses_effective_threshold_metadata(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "model_type": "xgb",
            "threshold": 0.6,
            "threshold_source": "env",
            "feature_version": "v2",
            "metrics": {},
            "top_features": [],
        },
    )

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_meta"]["threshold"] == 0.6
    assert body["model_meta"]["threshold_source"] == "env"


def test_model_info_returns_recommended_threshold_fields(monkeypatch):
    _set_test_auth(monkeypatch)

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "model_type": "xgb",
            "threshold": 0.75,
            "threshold_source": "metadata",
            "recommended_threshold": 0.82,
            "recommended_threshold_source": "artifact",
            "metrics": {},
            "top_features": [],
        },
    )

    response = client.get(
        "/model-info",
        headers={"X-API-KEY": "test-key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_meta"]["recommended_threshold"] == 0.82
    assert body["model_meta"]["recommended_threshold_source"] == "artifact"