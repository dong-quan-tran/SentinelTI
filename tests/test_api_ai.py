from __future__ import annotations

from fastapi.testclient import TestClient

import sentinelti.api as api_module


def _make_client(monkeypatch) -> TestClient:
    monkeypatch.setenv("SENTINELTI_API_KEY", "test-key")
    api_module.API_KEY = "test-key"
    return TestClient(api_module.app)


def _auth_headers() -> dict[str, str]:
    return {"X-API-KEY": "test-key"}


def test_ai_explain_score_success(monkeypatch):
    client = _make_client(monkeypatch)

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

    monkeypatch.setattr(api_module, "enrich_score", lambda url: deterministic_payload)
    monkeypatch.setattr(api_module, "ai_rewrite_explanation", lambda payload: ai_payload)

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


def test_ai_explain_score_passes_full_payload_to_ai_service(monkeypatch):
    client = _make_client(monkeypatch)

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

    captured = {}

    def fake_ai_rewrite(payload):
        captured["payload"] = payload
        return {
            "summary": "AI summary",
            "guidance": "AI guidance",
        }

    monkeypatch.setattr(api_module, "enrich_score", lambda url: deterministic_payload)
    monkeypatch.setattr(api_module, "ai_rewrite_explanation", fake_ai_rewrite)

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://phishy.example/login"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert captured["payload"] == deterministic_payload


def test_ai_explain_score_requires_api_key(monkeypatch):
    client = _make_client(monkeypatch)

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_ai_explain_score_returns_500_when_ai_service_fails(monkeypatch):
    client = _make_client(monkeypatch)

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

    monkeypatch.setattr(api_module, "enrich_score", lambda url: deterministic_payload)

    def fail_ai(payload):
        raise api_module.AIExplanationError("AI provider unavailable")

    monkeypatch.setattr(api_module, "ai_rewrite_explanation", fail_ai)

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=_auth_headers(),
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "AI provider unavailable"}