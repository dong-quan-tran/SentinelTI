from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Protocol

import requests


REQUIRED_SCORE_FIELDS = {"url", "final_label", "risk", "explanation"}


def ai_enabled() -> bool:
    raw = os.getenv("SENTINELTI_AI_ENABLED", "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def get_ai_provider_name() -> str:
    return os.getenv("SENTINELTI_AI_PROVIDER", "stub").strip().lower()


def get_ollama_endpoint() -> str:
    return os.getenv("SENTINELTI_OLLAMA_ENDPOINT", "http://localhost:11434").strip()


def get_ollama_model() -> str:
    return os.getenv("SENTINELTI_OLLAMA_MODEL", "llama3.1:8b").strip()


class AIExplanationError(RuntimeError):
    """Raised when an AI explanation cannot be generated safely."""


class AIExplanationProvider(Protocol):
    def generate(self, score_payload: Dict[str, Any]) -> Dict[str, str]:
        """Return an AI-friendly rewrite containing summary and guidance."""


def _validate_score_payload(score_payload: Dict[str, Any]) -> None:
    if not score_payload:
        raise AIExplanationError("Cannot build AI explanation from empty payload")

    missing = [field for field in REQUIRED_SCORE_FIELDS if field not in score_payload]
    if missing:
        raise AIExplanationError(
            f"Malformed score payload; missing required fields: {', '.join(sorted(missing))}"
        )

    if not isinstance(score_payload.get("reasons", []), list):
        raise AIExplanationError("Malformed score payload; reasons must be a list")

    explanation = score_payload.get("explanation")
    if not isinstance(explanation, dict):
        raise AIExplanationError("Malformed score payload; explanation must be an object")


def build_ai_explanation_prompt(score_payload: Dict[str, Any]) -> str:
    _validate_score_payload(score_payload)

    url = score_payload["url"]
    final_label = score_payload["final_label"]
    risk = score_payload["risk"]
    reasons = score_payload.get("reasons") or []
    heuristic = score_payload.get("heuristic") or {}
    model_meta = score_payload.get("model_meta") or {}
    explanation = score_payload.get("explanation") or {}

    parts: list[str] = [
        "You are rewriting a deterministic URL safety explanation.",
        "Do not change the verdict, score meaning, threshold meaning, or risk level.",
        "Do not claim the URL is safe if the deterministic verdict says malicious or suspicious.",
        "Return valid JSON with exactly two string fields: summary and guidance.",
        "Keep both fields concise and user-facing.",
        "",
        f"URL: {url}",
        f"Deterministic verdict: {final_label}",
        f"Risk: {risk}",
        f"Heuristic score: {heuristic.get('score')}",
        f"Deterministic summary: {explanation.get('summary', '')}",
        f"Why flagged: {explanation.get('why_flagged', '')}",
        f"User action: {explanation.get('user_action', '')}",
        "Top reasons:",
    ]

    for reason in reasons[:5]:
        parts.append(f"- {reason}")

    recommended_threshold = model_meta.get("recommended_threshold")
    if recommended_threshold is not None:
        parts.append(f"Advisory recommended threshold: {recommended_threshold}")

    return "\n".join(str(part) for part in parts if part is not None)


def _validate_ai_response_payload(payload: Dict[str, Any]) -> Dict[str, str]:
    summary = payload.get("summary")
    guidance = payload.get("guidance")

    if not isinstance(summary, str) or not summary.strip():
        raise AIExplanationError("AI response is missing a valid summary")
    if not isinstance(guidance, str) or not guidance.strip():
        raise AIExplanationError("AI response is missing valid guidance")

    return {
        "summary": summary.strip(),
        "guidance": guidance.strip(),
    }


def list_ollama_models() -> list[str]:
    endpoint = get_ollama_endpoint()

    try:
        response = requests.get(
            f"{endpoint.rstrip('/')}/api/tags",
            timeout=10.0,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise AIExplanationError(f"Ollama model listing failed: {exc}") from exc

    try:
        body = response.json()
    except ValueError as exc:
        raise AIExplanationError("Ollama model listing returned invalid JSON") from exc

    models = body.get("models")
    if not isinstance(models, list):
        raise AIExplanationError("Ollama model listing response is missing models")

    names: list[str] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        name = model.get("name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())

    return sorted(set(names))


@dataclass
class StubAIExplanationProvider:
    def generate(self, score_payload: Dict[str, Any]) -> Dict[str, str]:
        _validate_score_payload(score_payload)

        prompt = build_ai_explanation_prompt(score_payload)
        if not prompt.strip():
            raise AIExplanationError("Cannot build AI explanation from empty payload")

        final_label = score_payload["final_label"]
        risk = score_payload["risk"]
        explanation = score_payload.get("explanation") or {}
        user_action = explanation.get("user_action") or (
            "Review the deterministic explanation before taking action."
        )

        summary = (
            f"This URL was deterministically classified as {final_label} "
            f"with {risk} risk. This AI summary is only a simplified rewrite."
        )

        guidance = (
            f"{user_action} The deterministic verdict, threshold, and risk remain unchanged."
        )

        return {"summary": summary, "guidance": guidance}


@dataclass
class OllamaAIExplanationProvider:
    endpoint: str
    model_name: str
    timeout_seconds: float = 30.0

    def generate(self, score_payload: Dict[str, Any]) -> Dict[str, str]:
        _validate_score_payload(score_payload)
        prompt = build_ai_explanation_prompt(score_payload)

        try:
            response = requests.post(
                f"{self.endpoint.rstrip('/')}/api/chat",
                json={
                    "model": self.model_name,
                    "stream": False,
                    "format": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                            "guidance": {"type": "string"},
                        },
                        "required": ["summary", "guidance"],
                    },
                    "options": {
                        "temperature": 0,
                    },
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a safety explanation assistant. "
                                "You rewrite deterministic phishing verdicts without changing them."
                            ),
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ],
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise AIExplanationError(f"Ollama request failed: {exc}") from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise AIExplanationError("Ollama returned invalid JSON") from exc

        message = body.get("message") or {}
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise AIExplanationError("Ollama response did not contain message content")

        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise AIExplanationError("Ollama response content was not valid JSON") from exc

        return _validate_ai_response_payload(parsed)


def validate_ai_provider_config() -> None:
    provider_name = get_ai_provider_name()

    if provider_name == "stub":
        return

    if provider_name == "ollama":
        endpoint = get_ollama_endpoint()
        model_name = get_ollama_model()

        if not endpoint:
            raise AIExplanationError(
                "SENTINELTI_OLLAMA_ENDPOINT must not be empty when SENTINELTI_AI_PROVIDER=ollama"
            )
        if not model_name:
            raise AIExplanationError(
                "SENTINELTI_OLLAMA_MODEL must not be empty when SENTINELTI_AI_PROVIDER=ollama"
            )
        return

    raise AIExplanationError(f"Unsupported AI provider: {provider_name}")


def get_ai_provider(model_name: str | None = None) -> AIExplanationProvider:
    provider_name = os.getenv("SENTINELTI_AI_PROVIDER", "stub").strip().lower()

    if provider_name == "stub":
        return StubAIExplanationProvider()

    if provider_name == "ollama":
        endpoint = os.getenv("SENTINELTI_OLLAMA_ENDPOINT", "http://localhost:11434")
        resolved_model = model_name or os.getenv("SENTINELTI_OLLAMA_MODEL", "llama3.1:8b")
        return OllamaAIExplanationProvider(
            endpoint=endpoint,
            model_name=resolved_model,
        )

    raise AIExplanationError(f"Unsupported AI provider: {provider_name}")