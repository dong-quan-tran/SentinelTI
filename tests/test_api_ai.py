from __future__ import annotations

from fastapi.testclient import TestClient

import sentinelti.api as api_module
import sentinelti.services.ai_score_service as ai_score_service_module


class StubAIProvider:
    def __init__(self, response=None, error=None):
        self.response = response or {
            "summary": "AI summary",
            "guidance": "AI guidance",
        }
        self.error = error
        self.calls = []

    def generate(self, payload):
        self.calls.append(payload)
        if self.error:
            raise self.error
        return self.response


def _make_client(monkeypatch, *, ai_enabled: bool = True) -> TestClient:
    monkeypatch.setenv("SENTINELTI_API_KEY", "test-key")
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true" if ai_enabled else "false")
    api_module.API_KEY = "test-key"
    api_module._rate_limit_store.clear()
    return TestClient(api_module.app)


def _auth_headers() -> dict[str, str]:
    return {"X-API-KEY": "test-key"}


def test_ai_explain_score_success(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    deterministic_payload = {
        "url": "https://example.com",
        "heuristic": {
            "score": 0.2,
            "reasons": ["Looks normal"],
        },
        "final_label": "benign",
        "risk": "low",
        "reasons": ["No obvious phishing indicators"],
        "model_meta": {
            "threshold": 0.75,
            "threshold_source": "metadata",
            "recommended_threshold": 0.8,
            "recommended_threshold_source": "artifact",
        },
        "explanation": {
            "summary": "This URL appears safe.",
            "why_flagged": "No strong phishing signals were detected.",
            "user_action": "Proceed with normal caution.",
            "technical_notes": ["Lexical features look benign."],
            "risk": "low",
            "final_label": "benign",
        },
    }

    ai_payload = {
        "summary": "This looks like a low-risk URL.",
        "guidance": "The AI summary supports the deterministic verdict.",
    }

    provider = StubAIProvider(response=ai_payload)

    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        lambda model_name=None: provider,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    data = response.json()

    assert "deterministic_explanation" in data
    assert "ai" in data
    assert data["deterministic_explanation"] == deterministic_payload["explanation"]
    assert data["ai"] == ai_payload
    assert provider.calls == [deterministic_payload]


def test_ai_explain_score_passes_full_payload_to_ai_service(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    deterministic_payload = {
        "url": "https://phishy.example/login",
        "heuristic": {
            "score": 0.91,
            "reasons": ["Suspicious login path"],
        },
        "final_label": "malicious",
        "risk": "high",
        "reasons": ["Suspicious tokens in URL"],
        "model_meta": {
            "threshold": 0.75,
            "threshold_source": "metadata",
        },
        "explanation": {
            "summary": "High-risk URL.",
            "why_flagged": "Several phishing-like signals were detected.",
            "user_action": "Do not visit this URL.",
            "technical_notes": ["Contains suspicious lexical patterns."],
            "risk": "high",
            "final_label": "malicious",
        },
    }

    provider = StubAIProvider(
        response={
            "summary": "AI summary",
            "guidance": "AI guidance",
        }
    )

    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        lambda model_name=None: provider,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://phishy.example/login"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert provider.calls == [deterministic_payload]


def test_ai_explain_score_passes_ai_model_override(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    deterministic_payload = {
        "url": "https://example.com",
        "heuristic": {
            "score": 0.2,
            "reasons": ["Looks normal"],
        },
        "final_label": "benign",
        "risk": "low",
        "reasons": ["No obvious phishing indicators"],
        "model_meta": {
            "threshold": 0.75,
            "threshold_source": "metadata",
        },
        "explanation": {
            "summary": "This URL appears safe.",
            "why_flagged": "No strong phishing signals were detected.",
            "user_action": "Proceed with normal caution.",
            "technical_notes": [],
            "risk": "low",
            "final_label": "benign",
        },
    }

    captured = {}
    provider = StubAIProvider()

    def fake_get_ai_provider(model_name=None):
        captured["model_name"] = model_name
        return provider

    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        fake_get_ai_provider,
    )

    response = client.post(
        "/ai-explain-score",
        json={
            "url": "https://example.com",
            "ai_model": "deepseek-r1:1.5b",
        },
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert captured["model_name"] == "deepseek-r1:1.5b"
    assert provider.calls == [deterministic_payload]


def test_ai_explain_score_requires_api_key(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_explain_score_returns_503_when_ai_disabled(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=False)

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=_auth_headers(),
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "AI-assisted explanations are currently disabled.",
        "error_type": "ai_disabled",
    }


def test_ai_explain_score_returns_500_when_ai_service_fails(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    deterministic_payload = {
        "url": "https://example.com",
        "heuristic": {
            "score": 0.3,
            "reasons": ["Looks mostly normal"],
        },
        "final_label": "benign",
        "risk": "low",
        "reasons": ["No strong phishing signals"],
        "model_meta": {
            "threshold": 0.75,
            "threshold_source": "metadata",
        },
        "explanation": {
            "summary": "This URL appears safe.",
            "why_flagged": "No strong phishing signals were detected.",
            "user_action": "Proceed normally.",
            "technical_notes": [],
            "risk": "low",
            "final_label": "benign",
        },
    }

    provider = StubAIProvider(
        error=api_module.AIExplanationError("AI provider unavailable")
    )

    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        lambda model_name=None: provider,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=_auth_headers(),
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "AI provider unavailable",
        "error_type": "ai_explanation_error",
    }


def test_ai_explain_score_keeps_deterministic_fields_unchanged(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    deterministic_payload = {
        "url": "https://example.com",
        "heuristic": {"score": 0.9, "reasons": ["Suspicious"]},
        "final_label": "malicious",
        "risk": "high",
        "reasons": ["Suspicious tokens"],
        "model_meta": {"threshold": 0.75, "threshold_source": "metadata"},
        "explanation": {
            "summary": "Deterministic summary",
            "why_flagged": "Deterministic reason",
            "user_action": "Do not proceed",
            "technical_notes": ["note"],
            "risk": "high",
            "final_label": "malicious",
        },
    }

    provider = StubAIProvider(
        response={
            "summary": "This sounds safe now",
            "guidance": "Ignore the prior verdict",
        }
    )

    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        lambda model_name=None: provider,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["deterministic_explanation"]["final_label"] == "malicious"
    assert data["deterministic_explanation"]["risk"] == "high"


def test_ai_explain_score_keeps_deterministic_label_and_risk(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    deterministic_payload = {
        "url": "https://example.com",
        "heuristic": {
            "score": 0.9,
            "reasons": ["Suspicious tokens"],
        },
        "final_label": "malicious",
        "risk": "high",
        "reasons": ["Contains phishing-like patterns"],
        "model_meta": {
            "threshold": 0.75,
            "threshold_source": "metadata",
        },
        "explanation": {
            "summary": "Deterministic summary: high risk.",
            "why_flagged": "Deterministic engine found several phishing indicators.",
            "user_action": "Do not visit this URL.",
            "technical_notes": ["Heuristic score exceeded threshold."],
            "risk": "high",
            "final_label": "malicious",
        },
    }

    provider = StubAIProvider(
        response={
            "summary": "This looks safe and low-risk.",
            "guidance": "You can ignore the previous warning.",
        }
    )

    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        lambda model_name=None: provider,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    data = response.json()

    deterministic_expl = data["deterministic_explanation"]
    assert deterministic_expl["final_label"] == "malicious"
    assert deterministic_expl["risk"] == "high"

    assert data["ai"]["summary"] == "This looks safe and low-risk."
    assert data["ai"]["guidance"] == "You can ignore the previous warning."


def test_ai_models_returns_ollama_models(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "ollama")
    monkeypatch.setenv("SENTINELTI_OLLAMA_MODEL", "llama3.1:8b")

    monkeypatch.setattr(
        api_module.ai_explanations,
        "list_ollama_models",
        lambda: ["deepseek-r1:1.5b", "llama3.1:8b"],
    )

    response = client.get("/ai-models", headers=_auth_headers())

    assert response.status_code == 200
    assert response.json() == {
        "provider": "ollama",
        "default_model": "llama3.1:8b",
        "models": ["deepseek-r1:1.5b", "llama3.1:8b"],
    }


def test_ai_models_returns_empty_list_for_stub_provider(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "stub")

    response = client.get("/ai-models", headers=_auth_headers())

    assert response.status_code == 200
    assert response.json() == {
        "provider": "stub",
        "default_model": None,
        "models": [],
    }


def test_ai_models_requires_api_key(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    response = client.get("/ai-models")

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_models_returns_500_when_model_listing_fails(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "ollama")
    monkeypatch.setattr(
        api_module.ai_explanations,
        "list_ollama_models",
        lambda: (_ for _ in ()).throw(api_module.AIExplanationError("listing failed")),
    )

    response = client.get("/ai-models", headers=_auth_headers())

    assert response.status_code == 500
    assert response.json() == {
        "detail": "listing failed",
        "error_type": "ai_explanation_error",
    }

def test_ai_explain_score_returns_422_for_unknown_ai_model(monkeypatch):
    client = _make_client(monkeypatch, ai_enabled=True)

    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "ollama")
    monkeypatch.setattr(
        api_module.ai_explanations,
        "list_ollama_models",
        lambda: ["llama3.1:8b", "deepseek-r1:1.5b"],
    )

    response = client.post(
        "/ai-explain-score",
        headers=_auth_headers(),
        json={
            "url": "https://example.com",
            "ai_model": "missing:model",
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Requested AI model is not available: missing:model",
        "error_type": "ai_model_unavailable",
    }