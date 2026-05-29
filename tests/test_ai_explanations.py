from __future__ import annotations

import copy

import pytest

from sentinelti.services.ai_explanations import (
    AIExplanationError,
    StubAIExplanationProvider,
    ai_enabled,
    build_ai_explanation_prompt,
    get_ai_provider,
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


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off", ""])
def test_ai_enabled_false_values(monkeypatch, value):
    monkeypatch.setenv("SENTINELTI_AI_ENABLED", value)
    assert ai_enabled() is False


def test_build_ai_explanation_prompt_includes_core_fields(score_payload):
    prompt = build_ai_explanation_prompt(score_payload)

    assert "URL: https://phishy.example/login" in prompt
    assert "Deterministic verdict: malicious" in prompt
    assert "Risk: high" in prompt
    assert "Heuristic score: 0.91" in prompt
    assert "Deterministic summary: High-risk URL." in prompt
    assert "Why flagged: Several phishing-like signals were detected." in prompt
    assert "User action: Do not visit this URL." in prompt
    assert "Advisory recommended threshold: 0.8" in prompt


def test_build_ai_explanation_prompt_limits_reasons_to_top_five(score_payload):
    prompt = build_ai_explanation_prompt(score_payload)

    assert "Contains suspicious login keywords" in prompt
    assert "Uses URL structure common in phishing pages" not in prompt


def test_build_ai_explanation_prompt_without_recommended_threshold(score_payload):
    payload = copy.deepcopy(score_payload)
    payload["model_meta"] = {"threshold": 0.75}

    prompt = build_ai_explanation_prompt(payload)

    assert "Advisory recommended threshold:" not in prompt


def test_stub_provider_returns_summary_and_guidance(score_payload):
    provider = StubAIExplanationProvider()

    result = provider.generate(score_payload)

    assert set(result.keys()) == {"summary", "guidance"}
    assert "deterministically classified as malicious" in result["summary"]
    assert "risk" in result["summary"]
    assert "deterministic verdict, threshold, and risk remain unchanged" in result["guidance"]


def test_stub_provider_uses_fallback_user_action_when_missing(score_payload):
    payload = copy.deepcopy(score_payload)
    payload["explanation"]["user_action"] = ""

    provider = StubAIExplanationProvider()
    result = provider.generate(payload)

    assert "Review the deterministic explanation before taking action." in result["guidance"]


def test_stub_provider_raises_on_empty_payload():
    provider = StubAIExplanationProvider()

    with pytest.raises(AIExplanationError, match="empty payload"):
        provider.generate({})


def test_stub_provider_raises_on_missing_required_fields(score_payload):
    bad_payload = dict(score_payload)
    bad_payload.pop("final_label")

    provider = StubAIExplanationProvider()

    with pytest.raises(AIExplanationError, match="missing required fields"):
        provider.generate(bad_payload)


def test_stub_provider_raises_when_reasons_is_not_a_list(score_payload):
    bad_payload = dict(score_payload)
    bad_payload["reasons"] = "not-a-list"

    provider = StubAIExplanationProvider()

    with pytest.raises(AIExplanationError, match="reasons must be a list"):
        provider.generate(bad_payload)


def test_stub_provider_raises_when_explanation_is_not_an_object(score_payload):
    bad_payload = dict(score_payload)
    bad_payload["explanation"] = "not-an-object"

    provider = StubAIExplanationProvider()

    with pytest.raises(AIExplanationError, match="explanation must be an object"):
        provider.generate(bad_payload)


def test_stub_provider_does_not_modify_input_payload(score_payload):
    original = copy.deepcopy(score_payload)

    provider = StubAIExplanationProvider()
    provider.generate(score_payload)

    assert score_payload == original
    assert score_payload["final_label"] == original["final_label"]
    assert score_payload["risk"] == original["risk"]


def test_get_ai_provider_returns_stub_by_default(monkeypatch):
    monkeypatch.delenv("SENTINELTI_AI_PROVIDER", raising=False)

    provider = get_ai_provider()

    assert isinstance(provider, StubAIExplanationProvider)


def test_get_ai_provider_returns_stub_when_configured(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "stub")

    provider = get_ai_provider()

    assert isinstance(provider, StubAIExplanationProvider)


def test_get_ai_provider_raises_on_unsupported_provider(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "openai")

    with pytest.raises(AIExplanationError, match="Unsupported AI provider: openai"):
        get_ai_provider()