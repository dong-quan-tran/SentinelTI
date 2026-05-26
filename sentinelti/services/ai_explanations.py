from __future__ import annotations

from typing import Any, Dict


class AIExplanationError(RuntimeError):
    """Raised when an AI explanation cannot be generated safely."""


def build_ai_explanation_prompt(score_payload: Dict[str, Any]) -> str:
    """
    Prepare a compact prompt string from deterministic scoring data.

    score_payload is expected to look like the dict returned by enrich_score().
    """
    url = score_payload.get("url", "")
    final_label = score_payload.get("final_label", "benign")
    risk = score_payload.get("risk", "low")
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
        parts.append(
            f"Advisory recommended threshold: {recommended_threshold}"
        )

    return "\n".join(str(p) for p in parts if p is not None)


def ai_rewrite_explanation(score_payload: Dict[str, Any]) -> Dict[str, str]:
    """
    Stubbed AI call: rewrite deterministic explanation into clearer text.

    This keeps contracts and error handling in place before wiring a real provider.
    """
    prompt = build_ai_explanation_prompt(score_payload)

    if not prompt.strip():
        raise AIExplanationError("Cannot build AI explanation from empty payload")

    final_label = score_payload.get("final_label", "benign")
    risk = score_payload.get("risk", "low")

    summary = (
        f"This URL has been classified as {final_label} with {risk} risk "
        f"based on deterministic scoring results."
    )

    guidance = (
        "Use this AI summary as a helper only. The underlying score and label "
        "still come from the deterministic model."
    )

    return {
        "summary": summary,
        "guidance": guidance,
    }