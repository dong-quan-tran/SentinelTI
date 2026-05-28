from __future__ import annotations

from typing import Any, Dict

from sentinelti.scoring import enrich_score
from sentinelti.services.ai_explanations import (
    AIExplanationError,
    ai_enabled,
    ai_rewrite_explanation,
)


class AIEndpointDisabledError(RuntimeError):
    """Raised when AI-assisted explanations are disabled."""


def build_ai_explanation_response(url: str) -> Dict[str, Any]:
    if not ai_enabled():
        raise AIEndpointDisabledError("AI-assisted explanations are currently disabled.")

    deterministic = enrich_score(url)
    ai_payload = ai_rewrite_explanation(deterministic)

    return {
        "deterministic_explanation": deterministic["explanation"],
        "ai": ai_payload,
    }