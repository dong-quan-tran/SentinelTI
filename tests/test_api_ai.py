from __future__ import annotations

from fastapi.testclient import TestClient

from sentinelti.api import app as fastapi_app
import sentinelti.api.dependencies as deps_module
import sentinelti.api.routes as routes_module
import sentinelti.services.ai_explanations as ai_explanations_module
from sentinelti.services.ai_explanations import (
    AIExplanationError,
    AIModelNotAvailableError,
)
from sentinelti.services.ai_score_service import AIEndpointDisabledError


def _make_client(monkeypatch, *, api_key: str = "test-key") -> TestClient:
    monkeypatch.setattr(deps_module, "API_KEY", api_key)
    deps_module._rate_limit_store.clear()
    return TestClient(fastapi_app)


def _auth_headers(api_key: str = "test-key") -> dict[str, str]:
    return {"X-API-KEY": api_key}


def test_ai_models_requires_api_key(monkeypatch):
    client = _make_client(monkeypatch)

    response = client.get("/ai-models")

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_explain_score_requires_api_key(monkeypatch):
    client = _make_client(monkeypatch)

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_models_returns_provider_and_models_for_ollama(monkeypatch):
    client = _make_client(monkeypatch)

    monkeypatch.setattr(ai_explanations_module, "get_ai_provider_name", lambda: "ollama")
    monkeypatch.setattr(ai_explanations_module, "get_ollama_model", lambda: "llama3.1:8b")
    monkeypatch.setattr(
        ai_explanations_module,
        "list_ollama_models",
        lambda: ["llama3.1:8b", "mistral:7b"],
    )

    response = client.get(
        "/ai-models",
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "provider": "ollama",
        "default_model": "llama3.1:8b",
        "models": ["llama3.1:8b", "mistral:7b"],
    }


def test_ai_models_returns_empty_models_for_non_ollama_provider(monkeypatch):
    client = _make_client(monkeypatch)

    monkeypatch.setattr(ai_explanations_module, "get_ai_provider_name", lambda: "openai")

    response = client.get(
        "/ai-models",
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "provider": "openai",
        "default_model": None,
        "models": [],
    }


def test_ai_models_runtime_error_returns_structured_error(monkeypatch):
    client = _make_client(monkeypatch)

    def boom():
        raise RuntimeError("provider lookup failed")

    monkeypatch.setattr(ai_explanations_module, "get_ai_provider_name", boom)

    response = client.get(
        "/ai-models",
        headers=_auth_headers(),
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal scoring error",
        "error_type": "runtime_error",
    }


def test_ai_explain_score_returns_combined_response(monkeypatch):
    client = _make_client(monkeypatch)

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        lambda url, ai_model=None: {
            "url": url,
            "label": 1,
            "prob_malicious": 0.91,
            "threshold": 0.75,
            "heuristic": {
                "score": 0.82,
                "reasons": ["Suspicious login keyword", "Nested redirect parameter"],
            },
            "final_label": "malicious",
            "risk": "high",
            "reasons": ["Model score above threshold", "Multiple phishing indicators"],
            "deterministic_explanation": {
                "summary": "This URL looks likely malicious and should be treated as unsafe.",
                "why_flagged": "The deterministic model assigned a very high malicious probability.",
                "user_action": "Do not open the link or enter credentials.",
                "technical_notes": [
                    "Model score above threshold",
                    "Multiple phishing indicators",
                ],
                "risk": "high",
                "final_label": "malicious",
            },
            "ai": {
                "summary": (
                    "This link shows several warning signs that are commonly associated "
                    "with phishing or other unsafe destinations."
                ),
                "guidance": "Do not open the link or enter credentials.",
            },
            "model_meta": {
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
                "class_counts": {
                    "train_0": 10,
                    "train_1": 5,
                    "test_0": 4,
                    "test_1": 2,
                },
                "training_params": {"n_estimators": 400},
                "top_features": [
                    {"feature": "has_ip", "importance": 0.31},
                    {"feature": "url_length", "importance": 0.22},
                ],
                "training_notes": [],
                "model_summary": {
                    "model_type": "xgb",
                    "dataset_name": "kaggle",
                    "trained_at": "2026-05-18T03:55:05Z",
                    "top_features": [
                        {"feature": "has_ip", "importance": 0.31},
                        {"feature": "url_length", "importance": 0.22},
                    ],
                },
            },
        },
    )

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={
            "url": "https://phishy.example/login",
            "ai_model": "llama3.1:8b",
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert "deterministic_explanation" in body
    assert "ai" in body

    assert body["deterministic_explanation"]["summary"] == (
        "This URL looks likely malicious and should be treated as unsafe."
    )
    assert body["deterministic_explanation"]["why_flagged"] == (
        "The deterministic model assigned a very high malicious probability."
    )
    assert body["deterministic_explanation"]["user_action"] == (
        "Do not open the link or enter credentials."
    )
    assert body["deterministic_explanation"]["risk"] == "high"
    assert body["deterministic_explanation"]["final_label"] == "malicious"
    assert body["deterministic_explanation"]["technical_notes"] == [
        "Model score above threshold",
        "Multiple phishing indicators",
    ]

    assert body["ai"]["summary"].startswith("This link shows several warning signs")
    assert body["ai"]["guidance"] == "Do not open the link or enter credentials."

def test_ai_explain_score_supports_missing_ai_model_override(monkeypatch):
    client = _make_client(monkeypatch)

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        lambda url, ai_model=None: {
            "url": url,
            "label": 0,
            "prob_malicious": 0.11,
            "threshold": 0.75,
            "heuristic": {
                "score": 0.10,
                "reasons": [],
            },
            "final_label": "benign",
            "risk": "low",
            "reasons": ["No major indicators found"],
            "deterministic_explanation": {
                "summary": "This URL currently appears low risk.",
                "why_flagged": "Few malicious patterns were detected.",
                "user_action": "Proceed carefully.",
                "technical_notes": ["No major indicators found"],
                "risk": "low",
                "final_label": "benign",
            },
            "ai": {
                "summary": "This link appears relatively low risk based on the current checks.",
                "guidance": "Proceed carefully and verify the destination independently.",
            },
            "model_meta": {
                "artifact_version": "1.0",
                "model_type": "logreg",
                "trained_at": None,
                "dataset_name": None,
                "dataset_source": {},
                "feature_version": None,
                "threshold": 0.75,
                "threshold_source": "metadata",
                "recommended_threshold": None,
                "recommended_threshold_source": None,
                "metrics": {"roc_auc": None, "average_precision": None},
                "class_labels": {"benign": None, "malicious": None},
                "class_counts": {
                    "train_0": None,
                    "train_1": None,
                    "test_0": None,
                    "test_1": None,
                },
                "training_params": {},
                "top_features": [],
                "training_notes": [],
                "model_summary": {
                    "model_type": "logreg",
                    "dataset_name": None,
                    "trained_at": None,
                    "top_features": [],
                },
            },
        },
    )

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    body = response.json()

    assert "deterministic_explanation" in body
    assert "ai" in body

    assert body["deterministic_explanation"]["summary"] == "This URL currently appears low risk."
    assert body["deterministic_explanation"]["why_flagged"] == "Few malicious patterns were detected."
    assert body["deterministic_explanation"]["user_action"] == "Proceed carefully."
    assert body["deterministic_explanation"]["risk"] == "low"
    assert body["deterministic_explanation"]["final_label"] == "benign"
    assert body["deterministic_explanation"]["technical_notes"] == ["No major indicators found"]

    assert body["ai"]["summary"] == "This link appears relatively low risk based on the current checks."
    assert body["ai"]["guidance"] == "Proceed carefully and verify the destination independently."


def test_ai_explain_score_validation_error_for_missing_url(monkeypatch):
    client = _make_client(monkeypatch)

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={},
    )

    assert response.status_code == 422
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], list)
    assert body["detail"][0]["type"]


def test_ai_explain_score_returns_503_when_ai_disabled(monkeypatch):
    client = _make_client(monkeypatch)

    def disabled(_url, ai_model=None):
        raise AIEndpointDisabledError("AI-assisted explanations are disabled")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", disabled)

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={"url": "https://example.com"},
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "AI-assisted explanations are disabled",
        "error_type": "ai_disabled",
    }


def test_ai_explain_score_returns_422_for_unavailable_model(monkeypatch):
    client = _make_client(monkeypatch)

    def unavailable(_url, ai_model=None):
        raise AIModelNotAvailableError("Requested AI model is not available")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", unavailable)

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={
            "url": "https://example.com",
            "ai_model": "missing-model",
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Requested AI model is not available",
        "error_type": "ai_model_unavailable",
    }


def test_ai_explain_score_returns_500_for_ai_explanation_error(monkeypatch):
    client = _make_client(monkeypatch)

    def broken(_url, ai_model=None):
        raise AIExplanationError("AI generation failed")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", broken)

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={"url": "https://example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "AI generation failed",
        "error_type": "ai_explanation_error",
    }


def test_ai_explain_score_returns_500_for_runtime_error(monkeypatch):
    client = _make_client(monkeypatch)

    def boom(_url, ai_model=None):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", boom)

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={"url": "https://example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal scoring error",
        "error_type": "runtime_error",
    }


def test_ai_explain_score_sets_rate_limit_headers(monkeypatch):
    client = _make_client(monkeypatch)

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        lambda url, ai_model=None: {
            "url": url,
            "label": 0,
            "prob_malicious": 0.11,
            "threshold": 0.75,
            "heuristic": {
                "score": 0.10,
                "reasons": [],
            },
            "final_label": "benign",
            "risk": "low",
            "reasons": ["No major indicators found"],
            "deterministic_explanation": {
                "summary": "This URL currently appears low risk.",
                "why_flagged": "Few malicious patterns were detected.",
                "user_action": "Proceed carefully.",
                "technical_notes": ["No major indicators found"],
                "risk": "low",
                "final_label": "benign",
            },
            "ai": {
                "summary": "This link appears relatively low risk based on the current checks.",
                "guidance": "Proceed carefully and verify the destination independently.",
            },
            "model_meta": {
                "artifact_version": "1.0",
                "model_type": "logreg",
                "trained_at": None,
                "dataset_name": None,
                "dataset_source": {},
                "feature_version": None,
                "threshold": 0.75,
                "threshold_source": "metadata",
                "recommended_threshold": None,
                "recommended_threshold_source": None,
                "metrics": {"roc_auc": None, "average_precision": None},
                "class_labels": {"benign": None, "malicious": None},
                "class_counts": {
                    "train_0": None,
                    "train_1": None,
                    "test_0": None,
                    "test_1": None,
                },
                "training_params": {},
                "top_features": [],
                "training_notes": [],
                "model_summary": {
                    "model_type": "logreg",
                    "dataset_name": None,
                    "trained_at": None,
                    "top_features": [],
                },
            },
        },
    )

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == str(deps_module.RATE_LIMIT_REQUESTS)
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers


def test_ai_models_rate_limit_exceeded_returns_429(monkeypatch):
    client = _make_client(monkeypatch)

    deps_module._rate_limit_store["testclient"] = [
        9999999999.0 for _ in range(deps_module.RATE_LIMIT_REQUESTS)
    ]

    response = client.get(
        "/ai-models",
        headers=_auth_headers(),
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "Rate limit exceeded. Try again later."


def test_ai_explain_score_rate_limit_exceeded_returns_429(monkeypatch):
    client = _make_client(monkeypatch)

    deps_module._rate_limit_store["testclient"] = [
        9999999999.0 for _ in range(deps_module.RATE_LIMIT_REQUESTS)
    ]

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={"url": "https://example.com"},
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "Rate limit exceeded. Try again later."