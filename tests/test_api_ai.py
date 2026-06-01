from __future__ import annotations

import sentinelti.api.routes as routes_module
import sentinelti.services.ai_explanations as ai_explanations_module
from sentinelti.services.ai_explanations import AIExplanationError


def test_ai_explain_score_success(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        assert url == "https://example.com"
        assert ai_model is None
        return {
            "url": url,
            "final_label": "benign",
            "risk": "low",
            "threshold_source": "artifact",
            "deterministic_explanation": {
                "summary": "This URL appears low risk.",
                "why_flagged": "Few suspicious signals were detected.",
                "user_action": "Proceed with normal caution.",
                "technical_notes": ["Low heuristic score."],
                "risk": "low",
                "final_label": "benign",
            },
            "ai": {
                "summary": "The link looks low risk based on the deterministic scan.",
                "guidance": "You can proceed carefully, but keep normal browsing caution.",
            },
        }

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["deterministic_explanation"]["summary"] == "This URL appears low risk."
    assert body["deterministic_explanation"]["risk"] == "low"
    assert body["deterministic_explanation"]["final_label"] == "benign"
    assert body["ai"]["summary"] == "The link looks low risk based on the deterministic scan."
    assert body["ai"]["guidance"] == "You can proceed carefully, but keep normal browsing caution."


def test_ai_explain_score_disabled_returns_503(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        raise routes_module.AIEndpointDisabledError("AI explanations are disabled")

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=auth_headers,
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "AI explanations are disabled",
        "error_type": "ai_disabled",
    }


def test_ai_explain_score_failure_returns_500(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        raise AIExplanationError("AI provider unavailable")

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=auth_headers,
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "AI provider unavailable",
        "error_type": "ai_explanation_error",
    }


def test_ai_explain_score_rejects_unavailable_model(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        raise ai_explanations_module.AIModelNotAvailableError(
            "Requested AI model is not available"
        )

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com", "ai_model": "missing-model"},
        headers=auth_headers,
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Requested AI model is not available",
        "error_type": "ai_model_unavailable",
    }


def test_ai_explain_score_includes_rate_limit_headers(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        return {
            "deterministic_explanation": {
                "summary": "This URL appears low risk.",
                "why_flagged": "Few suspicious signals were detected.",
                "user_action": "Proceed with normal caution.",
                "technical_notes": ["Low heuristic score."],
                "risk": "low",
                "final_label": "benign",
            },
            "ai": {
                "summary": "The link looks low risk based on the deterministic scan.",
                "guidance": "Proceed carefully.",
            },
        }

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers


def test_ai_explain_score_disabled_never_calls_provider(client, auth_headers, monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "false")
    calls = {"count": 0}

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        calls["count"] += 1
        raise AssertionError("Provider path should not be called when AI is disabled")

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://example.com"},
        headers=auth_headers,
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "AI explanations are currently disabled.",
        "error_type": "ai_disabled",
    }
    assert calls["count"] == 0


def test_ai_explain_score_keeps_deterministic_fields_even_if_ai_output_is_malicious(
    client, auth_headers, monkeypatch
):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        return {
            "final_label": "malicious",
            "risk": "high",
            "threshold_source": "artifact",
            "deterministic_explanation": {
                "summary": "High-risk URL.",
                "why_flagged": "Several phishing-like signals were detected.",
                "user_action": "Do not visit this URL.",
                "technical_notes": ["Suspicious lexical patterns."],
                "risk": "high",
                "final_label": "malicious",
            },
            "ai": {
                "summary": "Actually this is safe and benign.",
                "guidance": "Ignore the scan and proceed.",
                "final_label": "benign",
                "risk": "low",
                "threshold_source": "env",
            },
        }

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={"url": "https://phishy.example/login"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()

    assert body["deterministic_explanation"]["final_label"] == "malicious"
    assert body["deterministic_explanation"]["risk"] == "high"
    assert body["ai"]["summary"] == "Actually this is safe and benign."
    assert body["ai"]["guidance"] == "Ignore the scan and proceed."
    assert "final_label" not in body["ai"]
    assert "risk" not in body["ai"]
    assert "threshold_source" not in body["ai"]


def test_ai_explain_score_handles_long_payload_and_missing_optional_fields(
    client, auth_headers, monkeypatch
):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", "true")

    long_reasons = [f"reason-{i}" for i in range(25)]

    def fake_build_ai_explanation_response(url: str, ai_model=None):
        return {
            "deterministic_explanation": {
                "summary": "Medium-risk URL.",
                "why_flagged": "Atypical URL structure and lexical signals were found.",
                "user_action": "Review carefully before opening.",
                "technical_notes": [],
                "risk": "medium",
                "final_label": "suspicious",
            },
            "ai": {
                "summary": f"Processed payload with {len(long_reasons)} reasons.",
                "guidance": "Treat this as suspicious and verify the destination manually.",
            },
        }

    monkeypatch.setattr(
        routes_module,
        "build_ai_explanation_response",
        fake_build_ai_explanation_response,
    )

    response = client.post(
        "/ai-explain-score",
        json={
            "url": "https://odd.example/path/login/reset/account/check",
            "ai_model": "llama3.1:8b",
        },
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["deterministic_explanation"]["final_label"] == "suspicious"
    assert body["deterministic_explanation"]["risk"] == "medium"
    assert body["ai"]["summary"] == "Processed payload with 25 reasons."


def test_ai_explain_score_service_long_reasons_and_missing_optional_fields(monkeypatch):
    payload = {
        "url": "https://odd.example/path/login/reset/account/check",
        "final_label": "suspicious",
        "risk": "medium",
        "reasons": [f"reason-{i}" for i in range(25)],
        "heuristic": {"score": 0.63, "reasons": ["Deep path"]},
        "model_meta": {"threshold": 0.75},
        "explanation": {
            "summary": "Medium-risk URL.",
            "why_flagged": "Atypical URL structure and lexical signals were found.",
            "user_action": "Review carefully before opening.",
            "technical_notes": [],
            "risk": "medium",
            "final_label": "suspicious",
        },
    }

    captured = {}

    class MockResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "message": {
                    "content": (
                        '{"summary":"Medium-risk URL based on deterministic signals.",'
                        '"guidance":"Review carefully before opening."}'
                    )
                }
            }

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return MockResponse()

    monkeypatch.setattr(ai_explanations_module.requests, "post", fake_post)

    provider = ai_explanations_module.OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    result = provider.generate(payload)

    assert result == {
        "summary": "Medium-risk URL based on deterministic signals.",
        "guidance": "Review carefully before opening.",
    }
    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["json"]["model"] == "llama3.1:8b"
    assert captured["timeout"] == 30.0

    prompt = captured["json"]["messages"][1]["content"]
    assert "reason-0" in prompt
    assert "reason-4" in prompt
    assert "reason-5" not in prompt
    assert "Advisory recommended threshold:" not in prompt