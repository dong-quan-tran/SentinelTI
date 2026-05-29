from __future__ import annotations

import pytest

import sentinelti.services.ai_score_service as ai_score_service_module
from sentinelti.services.ai_explanations import AIExplanationError


def test_build_ai_explanation_response_success(monkeypatch):
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
            "technical_notes": ["Lexical features look benign."],
            "risk": "low",
            "final_label": "benign",
        },
    }

    ai_payload = {
        "summary": "This looks like a low-risk URL.",
        "guidance": "The AI summary supports the deterministic verdict.",
    }

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "ai_rewrite_explanation",
        lambda payload: ai_payload,
    )

    result = ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert result == {
        "deterministic_explanation": deterministic_payload["explanation"],
        "ai": ai_payload,
    }


def test_build_ai_explanation_response_raises_when_ai_disabled(monkeypatch):
    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: False)

    with pytest.raises(ai_score_service_module.AIEndpointDisabledError) as exc_info:
        ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert str(exc_info.value) == "AI-assisted explanations are currently disabled."


def test_build_ai_explanation_response_passes_full_deterministic_payload_to_ai(monkeypatch):
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

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )
    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "ai_rewrite_explanation",
        fake_ai_rewrite,
    )

    result = ai_score_service_module.build_ai_explanation_response(
        "https://phishy.example/login"
    )

    assert captured["payload"] == deterministic_payload
    assert result["deterministic_explanation"] == deterministic_payload["explanation"]


def test_build_ai_explanation_response_propagates_ai_explanation_error(monkeypatch):
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

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )

    def fail_ai(payload):
        raise AIExplanationError("AI provider unavailable")

    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "ai_rewrite_explanation",
        fail_ai,
    )

    with pytest.raises(AIExplanationError, match="AI provider unavailable"):
        ai_score_service_module.build_ai_explanation_response("https://example.com")


def test_build_ai_explanation_response_keeps_deterministic_explanation_unchanged(monkeypatch):
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

    monkeypatch.setattr(ai_score_service_module.ai_explanations, "ai_enabled", lambda: True)
    monkeypatch.setattr(
        ai_score_service_module.scoring,
        "enrich_score",
        lambda url: deterministic_payload,
    )

    def fake_ai(payload):
        return {
            "summary": "This sounds safe now",
            "guidance": "Ignore the prior verdict",
        }

    monkeypatch.setattr(
        ai_score_service_module.ai_explanations,
        "ai_rewrite_explanation",
        fake_ai,
    )

    result = ai_score_service_module.build_ai_explanation_response("https://example.com")

    assert result["deterministic_explanation"]["final_label"] == "malicious"
    assert result["deterministic_explanation"]["risk"] == "high"
    assert result["ai"]["summary"] == "This sounds safe now"
    assert result["ai"]["guidance"] == "Ignore the prior verdict"