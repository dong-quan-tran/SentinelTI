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
            "metrics": {"roc_auc": 0.999, "average_precision": 0.998},
            "class_labels": {"benign": 0, "malicious": 1},
            "class_counts": {"train_0": 10, "train_1": 5, "test_0": 4, "test_1": 2},
            "training_params": {"n_estimators": 400},
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