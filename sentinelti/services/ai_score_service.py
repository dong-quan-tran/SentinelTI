from __future__ import annotations

from typing import Any, Dict

from sentinelti import scoring
from sentinelti.services import ai_explanations


class AIEndpointDisabledError(RuntimeError):
    """Raised when AI-assisted explanations are disabled."""


def build_ai_explanation_response(url: str) -> Dict[str, Any]:
    if not ai_explanations.ai_enabled():
        raise AIEndpointDisabledError("AI-assisted explanations are currently disabled.")

    deterministic = scoring.enrich_score(url)
    ai_payload = ai_explanations.ai_rewrite_explanation(deterministic)

    return {
        "deterministic_explanation": deterministic["explanation"],
        "ai": ai_payload,
    }