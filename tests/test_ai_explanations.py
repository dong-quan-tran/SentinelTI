from __future__ import annotations

import copy

import pytest

from sentinelti.services.ai_explanations import (
    AIExplanationError,
    ai_enabled,
    ai_rewrite_explanation,
    build_ai_explanation_prompt,
)


@pytest.fixture
def score_payload():
    return {
        "url": "https://phishy.example/login",
        "final_label": "malicious",
        "risk": "high",
        "reasons": [
            "Contains suspicious login keywords",
            "Uses a high-risk TLD",
            "Path is unusually deep",
            "Hostname pattern looks deceptive",
            "Contains mixed brand-like tokens",
            "Uses URL structure common in phishing pages",
        ],
        "heuristic": {"score": 0.91, "reasons": ["Suspicious login path"]},
        "model_meta": {
            "threshold": 0.75,
            "recommended_threshold": 0.80,
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


def test_ai_enabled_false_by_default(monkeypatch):
    monkeypatch.delenv("SENTINELTI_AI_ENABLED", raising=False)
    assert ai_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_ai_enabled_true_values(monkeypatch, value):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", value)
    assert ai_enabled() is True


def test_build_ai_explanation_prompt_includes_core_fields(score_payload):
    prompt = build_ai_explanation_prompt(score_payload)

    assert "URL: https://phishy.example/login" in prompt
    assert "Deterministic verdict: malicious (risk: high)" in prompt
    assert "Heuristic score: 0.91" in prompt
    assert "Advisory recommended threshold: 0.8" in prompt


def test_build_ai_explanation_prompt_limits_reasons_to_top_five(score_payload):
    prompt = build_ai_explanation_prompt(score_payload)

    assert "Contains suspicious login keywords" in prompt
    assert "Uses URL structure common in phishing pages" not in prompt


def test_ai_rewrite_explanation_returns_summary_and_guidance(score_payload):
    result = ai_rewrite_explanation(score_payload)

    assert set(result.keys()) == {"summary", "guidance"}
    assert "classified as malicious" in result["summary"]
    assert "deterministic model" in result["guidance"]


def test_ai_rewrite_explanation_raises_on_empty_payload():
    with pytest.raises(AIExplanationError, match="empty payload"):
        ai_rewrite_explanation({})


def test_ai_rewrite_explanation_raises_on_missing_required_fields(score_payload):
    bad_payload = dict(score_payload)
    bad_payload.pop("final_label")

    with pytest.raises(AIExplanationError, match="missing required fields"):
        ai_rewrite_explanation(bad_payload)


def test_ai_rewrite_explanation_raises_when_reasons_is_not_a_list(score_payload):
    bad_payload = dict(score_payload)
    bad_payload["reasons"] = "not-a-list"

    with pytest.raises(AIExplanationError, match="reasons must be a list"):
        ai_rewrite_explanation(bad_payload)


def test_ai_rewrite_explanation_does_not_modify_input_payload(score_payload):
    original = copy.deepcopy(score_payload)

    ai_rewrite_explanation(score_payload)

    assert score_payload == original
    assert score_payload["final_label"] == original["final_label"]
    assert score_payload["risk"] == original["risk"]