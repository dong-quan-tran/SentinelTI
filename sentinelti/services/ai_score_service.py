from __future__ import annotations

from typing import Any, Dict

from sentinelti import scoring
from sentinelti.services import ai_explanations


class AIEndpointDisabledError(RuntimeError):
    """Raised when AI-assisted explanations are disabled."""


def _validate_requested_ai_model(ai_model: str | None) -> None:
    if not ai_model:
        return

    provider_name = ai_explanations.get_ai_provider_name()

    if provider_name != "ollama":
        return

    available_models = ai_explanations.list_ollama_models()
    if ai_model not in available_models:
        raise ai_explanations.AIModelNotAvailableError(
            f"Requested AI model is not available: {ai_model}"
        )


def build_ai_explanation_response(
    url: str,
    ai_model: str | None = None,
) -> Dict[str, Any]:
    if not ai_explanations.ai_enabled():
        raise AIEndpointDisabledError("AI-assisted explanations are currently disabled.")

    _validate_requested_ai_model(ai_model)

    deterministic = scoring.enrich_score(url)
    provider = ai_explanations.get_ai_provider(model_name=ai_model)
    ai_payload = provider.generate(deterministic)

    return {
        "deterministic_explanation": deterministic["explanation"],
        "ai": ai_payload,
    }