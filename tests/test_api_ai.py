from __future__ import annotations

import sentinelti.api.dependencies as deps_module
import sentinelti.api.routes as routes_module
import sentinelti.services.ai_explanations as ai_explanations_module
from sentinelti.services.ai_explanations import (
    AIExplanationError,
    AIModelNotAvailableError,
)
from sentinelti.services.ai_score_service import AIEndpointDisabledError


def _success_ai_response(
    *,
    summary: str = "This URL currently appears low risk.",
    why_flagged: str = "Few malicious patterns were detected.",
    user_action: str = "Proceed carefully.",
    technical_notes: list[str] | None = None,
    risk: str = "low",
    final_label: str = "benign",
    ai_summary: str = "This link appears relatively low risk based on the current checks.",
    ai_guidance: str = "Proceed carefully and verify the destination independently.",
) -> dict:
    return {
        "deterministic_explanation": {
            "summary": summary,
            "why_flagged": why_flagged,
            "user_action": user_action,
            "technical_notes": technical_notes or ["No major indicators found"],
            "risk": risk,
            "final_label": final_label,
        },
        "ai": {
            "summary": ai_summary,
            "guidance": ai_guidance,
        },
    }


def test_ai_models_requires_api_key(client):
    response = client.get("/ai-models")

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_explain_score_requires_api_key(client):
    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_models_returns_provider_and_models_for_ollama(client, auth_headers, monkeypatch):
    monkeypatch.setattr(ai_explanations_module, "get_ai_provider_name", lambda: "ollama")
    monkeypatch.setattr(ai_explanations_module, "get_ollama_model", lambda: "llama3.1:8b")
    monkeypatch.setattr(
        ai_explanations_module,
        "list_ollama_models",
        lambda: ["llama3.1:8b", "mistral:7b"],
    )

    response = client.get(
        "/ai-models",
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "provider": "ollama",
        "default_model": "llama3.1:8b",
        "models": ["llama3.1:8b", "mistral:7b"],
    }


def test_ai_models_returns_empty_models_for_non_ollama_provider(client, auth_headers, monkeypatch):
    monkeypatch.setattr(ai_explanations_module, "get_ai_provider_name", lambda: "openai")

    response = client.get(
        "/ai-models",
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "provider": "openai",
        "default_model": None,
        "models": [],
    }


def test_ai_models_runtime_error_returns_structured_error(client, auth_headers, monkeypatch):
    def boom():
        raise RuntimeError("provider lookup failed")

    monkeypatch.setattr(ai_explanations_module, "get_ai_provider_name", boom)

    response = client.get(
        "/ai-models",
        headers=auth_headers,
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal scoring error",
        "error_type": "runtime_error",
    }


def test_ai_explain_score_returns_combined_response(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        lambda url, ai_model=None: _success_ai_response(
            summary="This URL looks likely malicious and should be treated as unsafe.",
            why_flagged="The deterministic model assigned a very high malicious probability.",
            user_action="Do not open the link or enter credentials.",
            technical_notes=[
                "Model score above threshold",
                "Multiple phishing indicators",
            ],
            risk="high",
            final_label="malicious",
            ai_summary=(
                "This link shows several warning signs that are commonly associated "
                "with phishing or other unsafe destinations."
            ),
            ai_guidance="Do not open the link or enter credentials.",
        ),
    )

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={
            "url": "https://phishy.example/login",
            "ai_model": "llama3.1:8b",
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body == {
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
    }


def test_ai_explain_score_supports_missing_ai_model_override(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        lambda url, ai_model=None: _success_ai_response(),
    )

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body == {
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
    }


def test_ai_explain_score_validation_error_for_missing_url(client, auth_headers):
    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={},
    )

    assert response.status_code == 422
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], list)
    assert body["detail"][0]["type"]


def test_ai_explain_score_returns_503_when_ai_disabled(client, auth_headers, monkeypatch):
    def disabled(_url, ai_model=None):
        raise AIEndpointDisabledError("AI-assisted explanations are disabled")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", disabled)

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={"url": "https://example.com"},
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "AI-assisted explanations are disabled",
        "error_type": "ai_disabled",
    }


def test_ai_explain_score_returns_422_for_unavailable_model(client, auth_headers, monkeypatch):
    def unavailable(_url, ai_model=None):
        raise AIModelNotAvailableError("Requested AI model is not available")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", unavailable)

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
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


def test_ai_explain_score_returns_500_for_ai_explanation_error(client, auth_headers, monkeypatch):
    def broken(_url, ai_model=None):
        raise AIExplanationError("AI generation failed")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", broken)

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={"url": "https://example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "AI generation failed",
        "error_type": "ai_explanation_error",
    }


def test_ai_explain_score_returns_500_for_runtime_error(client, auth_headers, monkeypatch):
    def boom(_url, ai_model=None):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(routes_module, "build_ai_explanation_response", boom)

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={"url": "https://example.com"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal scoring error",
        "error_type": "runtime_error",
    }


def test_ai_explain_score_sets_rate_limit_headers(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        lambda url, ai_model=None: _success_ai_response(),
    )

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == str(deps_module.RATE_LIMIT_REQUESTS)
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers


def test_ai_models_rate_limit_exceeded_returns_429(client, auth_headers):
    deps_module._rate_limit_store["testclient"] = [
        9999999999.0 for _ in range(deps_module.RATE_LIMIT_REQUESTS)
    ]

    response = client.get(
        "/ai-models",
        headers=auth_headers,
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "Rate limit exceeded. Try again later."


def test_ai_explain_score_rate_limit_exceeded_returns_429(client, auth_headers):
    deps_module._rate_limit_store["testclient"] = [
        9999999999.0 for _ in range(deps_module.RATE_LIMIT_REQUESTS)
    ]

    response = client.post(
        "/ai-explain-score",
        headers=auth_headers,
        json={"url": "https://example.com"},
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "Rate limit exceeded. Try again later."