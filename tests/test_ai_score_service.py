from __future__ import annotations

import pytest

import sentinelti.services.ai_score_service as ai_score_service_module
from sentinelti.services.ai_explanations import AIExplanationError


@pytest.fixture
def deterministic_payload():
    return {
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
            "technical_notes": ["Lexical features look benign."],
            "risk": "low",
            "final_label": "benign",
        },
    }


class StubProvider:
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


def test_build_ai_explanation_response_success(monkeypatch, deterministic_payload):
    provider = StubProvider(
        response={
            "summary": "This looks like a low-risk URL.",
            "guidance": "The AI summary supports the deterministic verdict.",
        }
    )

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
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

    result = ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert result == {
        "deterministic_explanation": deterministic_payload["explanation"],
        "ai": {
            "summary": "This looks like a low-risk URL.",
            "guidance": "The AI summary supports the deterministic verdict.",
        },
    }
    assert provider.calls == [deterministic_payload]


def test_build_ai_explanation_response_raises_when_ai_disabled(monkeypatch):
    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: False)

    with pytest.raises(ai_score_service_module.AIEndpointDisabledError) as exc_info:
        ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert str(exc_info.value) == "AI-assisted explanations are currently disabled."


def test_build_ai_explanation_response_passes_full_deterministic_payload_to_provider(
    monkeypatch, deterministic_payload
):
    provider = StubProvider()

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
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

    result = ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert provider.calls == [deterministic_payload]
    assert result["deterministic_explanation"] == deterministic_payload["explanation"]


def test_build_ai_explanation_response_propagates_ai_explanation_error(
    monkeypatch, deterministic_payload
):
    provider = StubProvider(error=AIExplanationError("AI provider unavailable"))

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
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

    with pytest.raises(AIExplanationError, match="AI provider unavailable"):
        ai_score_service_module.build_ai_explanation_response("https://example.com")


def test_build_ai_explanation_response_keeps_deterministic_explanation_unchanged(
    monkeypatch,
):
    deterministic_payload = {
        "url": "https://example.com",
        "heuristic": {
            "score": 0.9,
            "reasons": ["Suspicious"],
        },
        "final_label": "malicious",
        "risk": "high",
        "reasons": ["Suspicious tokens"],
        "model_meta": {
            "threshold": 0.75,
            "threshold_source": "metadata",
        },
        "explanation": {
            "summary": "Deterministic summary",
            "why_flagged": "Deterministic reason",
            "user_action": "Do not proceed",
            "technical_notes": ["note"],
            "risk": "high",
            "final_label": "malicious",
        },
    }

    provider = StubProvider(
        response={
            "summary": "This sounds safe now",
            "guidance": "Ignore the prior verdict",
        }
    )

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
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

    result = ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert result["deterministic_explanation"]["final_label"] == "malicious"
    assert result["deterministic_explanation"]["risk"] == "high"
    assert result["ai"]["summary"] == "This sounds safe now"
    assert result["ai"]["guidance"] == "Ignore the prior verdict"


def test_build_ai_explanation_response_uses_requested_url_for_scoring(
    monkeypatch, deterministic_payload
):
    provider = StubProvider()
    captured = {}

    def fake_enrich_score(url):
        captured["url"] = url
        return deterministic_payload

    def fake_get_ai_provider(model_name=None):
        captured["model_name"] = model_name
        return provider

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
    monkeypatch.setattr(ai_score_service_module.scoring, "enrich_score", fake_enrich_score)
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "get_ai_provider",
        fake_get_ai_provider,
    )

    ai_score_service_module.build_ai_explanation_response("https://requested.example/path")

    assert captured["url"] == "https://requested.example/path"
    assert captured["model_name"] is None


def test_build_ai_explanation_response_passes_ai_model_override(
    monkeypatch, deterministic_payload
):
    provider = StubProvider()
    captured = {}

    def fake_get_ai_provider(model_name=None):
        captured["model_name"] = model_name
        return provider

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
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

    result = ai_score_service_module.build_ai_explanation_response(
        "https://example.com",
        ai_model="deepseek-r1:1.5b",
    )

    assert captured["model_name"] == "deepseek-r1:1.5b"
    assert result["deterministic_explanation"] == deterministic_payload["explanation"]
    assert provider.calls == [deterministic_payload]