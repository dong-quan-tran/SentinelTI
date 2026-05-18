from __future__ import annotations

from fastapi.testclient import TestClient

import sentinelti.api as api_module


client = TestClient(api_module.app)


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


def test_score_url_returns_typed_response(monkeypatch):
    monkeypatch.setattr(api_module, "API_KEY", "test-key")
    api_module._rate_limit_store.clear()

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
        },
    )

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "artifact_version": "1.0",
            "model_type": "xgb",
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

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={"url": "https://phishy.example/login"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["schema_version"] == "1.1"
    assert body["url"] == "https://phishy.example/login"
    assert body["label"] == 1
    assert body["prob_malicious"] == 0.91
    assert body["threshold"] == 0.75
    assert body["final_label"] == "malicious"
    assert body["risk"] == "high"

    assert body["heuristic"]["score"] == 0.82
    assert "Suspicious login keyword" in body["heuristic"]["reasons"]

    assert body["model_meta"]["model_type"] == "xgb"
    assert body["model_meta"]["feature_version"] == "v2"
    assert body["model_meta"]["threshold"] == 0.75
    assert body["model_meta"]["metrics"]["roc_auc"] == 0.999
    assert body["model_meta"]["metrics"]["average_precision"] == 0.998


def test_score_urls_returns_results_list(monkeypatch):
    monkeypatch.setattr(api_module, "API_KEY", "test-key")
    api_module._rate_limit_store.clear()

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
        },
    )

    monkeypatch.setattr(
        api_module,
        "get_loaded_model_metadata",
        lambda: {
            "artifact_version": "1.0",
            "model_type": "logreg",
            "trained_at": "2026-05-18T04:00:00Z",
            "dataset_name": "kaggle",
            "dataset_source": {"use_real_data": True},
            "feature_version": "v2",
            "threshold": 0.75,
            "metrics": {"roc_auc": 0.98, "average_precision": 0.97},
            "class_labels": {"benign": 0, "malicious": 1},
            "class_counts": {"train_0": 100, "train_1": 50, "test_0": 40, "test_1": 20},
            "training_params": {"max_iter": 2000},
            "artifact_path": "sentinelti/models/url_classifier_logreg.joblib",
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
    assert body["results"][0]["schema_version"] == "1.1"
    assert body["results"][0]["model_meta"]["model_type"] == "logreg"
    assert body["results"][1]["url"] == "https://example.org"


def test_score_url_validation_error_for_missing_url(monkeypatch):
    monkeypatch.setattr(api_module, "API_KEY", "test-key")
    api_module._rate_limit_store.clear()

    response = client.post(
        "/score-url",
        headers={"X-API-KEY": "test-key"},
        json={},
    )

    assert response.status_code == 422


def test_score_urls_validation_error_for_missing_urls(monkeypatch):
    monkeypatch.setattr(api_module, "API_KEY", "test-key")
    api_module._rate_limit_store.clear()

    response = client.post(
        "/score-urls",
        headers={"X-API-KEY": "test-key"},
        json={},
    )

    assert response.status_code == 422