from __future__ import annotations

from typing import Any, Dict
import os


REQUIRED_SCORE_FIELDS = {"url", "final_label", "risk", "explanation"}


def ai_enabled() -> bool:
    raw = os.getenv("SENTINELTI_AI_ENABLED", "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


class AIExplanationError(RuntimeError):
    """Raised when an AI explanation cannot be generated safely."""


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


def build_ai_explanation_prompt(score_payload: Dict[str, Any]) -> str:
    _validate_score_payload(score_payload)

    url = score_payload["url"]
    final_label = score_payload["final_label"]
    risk = score_payload["risk"]
    reasons = score_payload.get("reasons") or []
    heuristic = score_payload.get("heuristic") or {}
    model_meta = score_payload.get("model_meta") or {}

    parts: list[str] = [
        f"URL: {url}",
        f"Deterministic verdict: {final_label} (risk: {risk})",
        f"Heuristic score: {heuristic.get('score')}",
        "Top reasons:",
    ]

    for r in reasons[:5]:
        parts.append(f"- {r}")

    recommended_threshold = model_meta.get("recommended_threshold")
    if recommended_threshold is not None:
        parts.append(f"Advisory recommended threshold: {recommended_threshold}")

    return "\n".join(str(p) for p in parts if p is not None)


def ai_rewrite_explanation(score_payload: Dict[str, Any]) -> Dict[str, str]:
    _validate_score_payload(score_payload)
    prompt = build_ai_explanation_prompt(score_payload)

    if not prompt.strip():
        raise AIExplanationError("Cannot build AI explanation from empty payload")

    final_label = score_payload["final_label"]
    risk = score_payload["risk"]

    summary = (
        f"This URL has been classified as {final_label} with {risk} risk "
        f"based on deterministic scoring results."
    )

    guidance = (
        "Use this AI summary as a helper only. The underlying score and label "
        "still come from the deterministic model."
    )

    return {"summary": summary, "guidance": guidance}