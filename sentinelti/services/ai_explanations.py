from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Protocol


REQUIRED_SCORE_FIELDS = {"url", "final_label", "risk", "explanation"}


def ai_enabled() -> bool:
    raw = os.getenv("SENTINELTI_AI_ENABLED", "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


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
        "Keep the explanation concise and user-facing.",
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


def get_ai_provider() -> AIExplanationProvider:
    provider_name = os.getenv("SENTINELTI_AI_PROVIDER", "stub").strip().lower()

    if provider_name == "stub":
        return StubAIExplanationProvider()

    raise AIExplanationError(f"Unsupported AI provider: {provider_name}")