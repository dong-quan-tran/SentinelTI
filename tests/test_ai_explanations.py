from __future__ import annotations

import copy
import json

import pytest
import requests

import sentinelti.services.ai_explanations as ai_explanations_module
from sentinelti.services.ai_explanations import (
    AIExplanationError,
    OllamaAIExplanationProvider,
    StubAIExplanationProvider,
    ai_enabled,
    build_ai_explanation_prompt,
    get_ai_provider,
    get_ai_provider_name,
    get_ollama_endpoint,
    get_ollama_model,
    validate_ai_provider_config,
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


class MockResponse:
    def __init__(self, json_data=None, status_error=None, json_error=None):
        self._json_data = json_data
        self._status_error = status_error
        self._json_error = json_error

    def raise_for_status(self):
        if self._status_error:
            raise self._status_error

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._json_data


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
    assert "Return valid JSON with exactly two string fields: summary and guidance." in prompt


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


def test_get_ai_provider_name_defaults_to_stub(monkeypatch):
    monkeypatch.delenv("SENTINELTI_AI_PROVIDER", raising=False)

    assert get_ai_provider_name() == "stub"


def test_get_ai_provider_name_normalizes_case_and_spacing(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "  OLLAMA  ")

    assert get_ai_provider_name() == "ollama"


def test_get_ollama_endpoint_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("SENTINELTI_OLLAMA_ENDPOINT", raising=False)

    assert get_ollama_endpoint() == "http://localhost:11434"


def test_get_ollama_model_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("SENTINELTI_OLLAMA_MODEL", raising=False)

    assert get_ollama_model() == "llama3.1:8b"


def test_validate_ai_provider_config_allows_stub(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "stub")

    validate_ai_provider_config()


def test_validate_ai_provider_config_allows_ollama(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "ollama")
    monkeypatch.setenv("SENTINELTI_OLLAMA_ENDPOINT", "http://localhost:11434")
    monkeypatch.setenv("SENTINELTI_OLLAMA_MODEL", "llama3.1:8b")

    validate_ai_provider_config()


def test_validate_ai_provider_config_rejects_unsupported_provider(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "openai")

    with pytest.raises(AIExplanationError, match="Unsupported AI provider: openai"):
        validate_ai_provider_config()


def test_get_ai_provider_returns_ollama_provider(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "ollama")
    monkeypatch.setenv("SENTINELTI_OLLAMA_ENDPOINT", "http://localhost:11434")
    monkeypatch.setenv("SENTINELTI_OLLAMA_MODEL", "llama3.1:8b")

    provider = get_ai_provider()

    assert isinstance(provider, OllamaAIExplanationProvider)
    assert provider.endpoint == "http://localhost:11434"
    assert provider.model_name == "llama3.1:8b"


def test_get_ai_provider_uses_model_override(monkeypatch):
    monkeypatch.setenv("SENTINELTI_AI_PROVIDER", "ollama")
    monkeypatch.setenv("SENTINELTI_OLLAMA_ENDPOINT", "http://localhost:11434")
    monkeypatch.setenv("SENTINELTI_OLLAMA_MODEL", "llama3.1:8b")

    provider = get_ai_provider(model_name="deepseek-r1:1.5b")

    assert isinstance(provider, OllamaAIExplanationProvider)
    assert provider.model_name == "deepseek-r1:1.5b"


def test_ollama_provider_returns_summary_and_guidance(monkeypatch, score_payload):
    captured = {}
    json_module = json

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return MockResponse(
            json_data={
                "message": {
                    "content": json_module.dumps(
                        {
                            "summary": "This URL appears high-risk based on deterministic signals.",
                            "guidance": "Avoid visiting the URL and rely on the deterministic verdict.",
                        }
                    )
                }
            }
        )

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    result = provider.generate(score_payload)

    assert result == {
        "summary": "This URL appears high-risk based on deterministic signals.",
        "guidance": "Avoid visiting the URL and rely on the deterministic verdict.",
    }
    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["json"]["model"] == "llama3.1:8b"
    assert captured["json"]["stream"] is False
    assert captured["timeout"] == 30.0
    assert captured["json"]["messages"][1]["role"] == "user"


def test_ollama_provider_raises_on_request_failure(monkeypatch, score_payload):
    def fake_post(url, json=None, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    with pytest.raises(AIExplanationError, match="Ollama request failed"):
        provider.generate(score_payload)


def test_ollama_provider_raises_on_invalid_response_json(monkeypatch, score_payload):
    def fake_post(url, json=None, timeout=None):
        return MockResponse(json_error=ValueError("bad json"))

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    with pytest.raises(AIExplanationError, match="Ollama returned invalid JSON"):
        provider.generate(score_payload)


def test_ollama_provider_raises_when_message_content_missing(monkeypatch, score_payload):
    def fake_post(url, json=None, timeout=None):
        return MockResponse(json_data={"message": {}})

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    with pytest.raises(
        AIExplanationError,
        match="Ollama response did not contain message content",
    ):
        provider.generate(score_payload)


def test_ollama_provider_raises_when_message_content_is_not_valid_json(
    monkeypatch, score_payload
):
    def fake_post(url, json=None, timeout=None):
        return MockResponse(
            json_data={
                "message": {
                    "content": "not-json"
                }
            }
        )

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    with pytest.raises(
        AIExplanationError,
        match="Ollama response content was not valid JSON",
    ):
        provider.generate(score_payload)


def test_ollama_provider_raises_when_summary_missing(monkeypatch, score_payload):
    json_module = json

    def fake_post(url, json=None, timeout=None):
        return MockResponse(
            json_data={
                "message": {
                    "content": json_module.dumps(
                        {
                            "guidance": "Do not trust the URL.",
                        }
                    )
                }
            }
        )

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    with pytest.raises(AIExplanationError, match="missing a valid summary"):
        provider.generate(score_payload)


def test_ollama_provider_raises_when_guidance_missing(monkeypatch, score_payload):
    json_module = json

    def fake_post(url, json=None, timeout=None):
        return MockResponse(
            json_data={
                "message": {
                    "content": json_module.dumps(
                        {
                            "summary": "This URL looks suspicious.",
                        }
                    )
                }
            }
        )

    monkeypatch.setattr(
        "sentinelti.services.ai_explanations.requests.post",
        fake_post,
    )

    provider = OllamaAIExplanationProvider(
        endpoint="http://localhost:11434",
        model_name="llama3.1:8b",
    )

    with pytest.raises(AIExplanationError, match="missing valid guidance"):
        provider.generate(score_payload)


def test_list_ollama_models_returns_sorted_unique_names(monkeypatch):
    class _MockResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "models": [
                    {"name": "llama3.1:8b"},
                    {"name": "deepseek-r1:1.5b"},
                    {"name": "llama3.1:8b"},
                ]
            }

    monkeypatch.setattr(
        ai_explanations_module.requests,
        "get",
        lambda url, timeout=None: _MockResponse(),
    )

    result = ai_explanations_module.list_ollama_models()

    assert result == ["deepseek-r1:1.5b", "llama3.1:8b"]


def test_list_ollama_models_raises_on_request_failure(monkeypatch):
    def fake_get(url, timeout=None):
        raise ai_explanations_module.requests.RequestException("connection refused")

    monkeypatch.setattr(ai_explanations_module.requests, "get", fake_get)

    with pytest.raises(AIExplanationError, match="Ollama model listing failed"):
        ai_explanations_module.list_ollama_models()


def test_list_ollama_models_raises_on_invalid_json(monkeypatch):
    class _MockResponse:
        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("bad json")

    monkeypatch.setattr(
        ai_explanations_module.requests,
        "get",
        lambda url, timeout=None: _MockResponse(),
    )

    with pytest.raises(AIExplanationError, match="invalid JSON"):
        ai_explanations_module.list_ollama_models()


def test_list_ollama_models_raises_when_models_missing(monkeypatch):
    class _MockResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"not_models": []}

    monkeypatch.setattr(
        ai_explanations_module.requests,
        "get",
        lambda url, timeout=None: _MockResponse(),
    )

    with pytest.raises(AIExplanationError, match="missing models"):
        ai_explanations_module.list_ollama_models()