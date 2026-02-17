"""
Scoring and enrichment logic for SentinelTi.

This module combines the ML URL classifier output with heuristic
signals to produce a final label, risk level, and explanations
suitable for CLI and API consumers.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

from urllib.parse import urlparse

from .heuristics import analyze_url
from .ml.service import score_url as ml_score_url  # adjust path if needed


TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "microsoftonline.com",
    "netflix.com",
    "paypal.com",
    "amazon.com",
    # Add more as we see fit
}

def enrich_score(url: str) -> Dict[str, Any]:
    """
    Run the ML model and heuristics on a URL and return an enriched result.

    Returns a dict with at least:
      - url
      - label (ML label)
      - prob_malicious (float)
      - heuristic (nested dict)
      - final_label: 'benign' | 'suspicious' | 'malicious'
      - risk: 'low' | 'medium' | 'high'
      - reasons: list[str]
    """
    ml_result = ml_score_url(url)  # existing function: {url, label, prob_malicious}
    heur = analyze_url(url)

    p = float(ml_result["prob_malicious"])
    h = float(heur.score)

    # Strong ML + strong heuristics => malicious / high
    if (p >= 0.90 and h >= 1.5) or h >= 3.5:
        final_label = "malicious"
        risk = "high"

    # Clear benign: very low ML, no heuristic signals
    elif p <= 0.05 and h == 0.0:
        final_label = "benign"
        risk = "low"

    # Mostly benign but some mild heuristic noise
    elif p <= 0.10 and h < 1.5:
        final_label = "benign"
        risk = "low"

    # Medium risk: either ML is moderately high or heuristics indicate phishing structure
    elif p >= 0.60 or h >= 1.5:
        final_label = "suspicious"
        risk = "medium"

    # Default: suspicious if we have any heuristic score, otherwise low-risk benign
    else:
        if h > 0.0:
            final_label = "suspicious"
            risk = "medium"
        else:
            final_label = "benign"
            risk = "low"

    # Trusted domain override: keep well-known legitimate domains benign
    # unless the model is extremely confident they are malicious.
    parsed = urlparse(url)
    host = parsed.hostname or ""

    # Use the base domain (last two labels) as a simple heuristic.
    parts = host.split(".")
    base_host = ".".join(parts[-2:]) if len(parts) >= 2 else host
    
    if base_host in TRUSTED_DOMAINS and p < 0.90:
        # Only override if heuristics are not extremely scary
        if h < 2.0:
            final_label = "benign"
            risk = "low"


        # Build human-readable reasons
    reasons: list[str] = []

    # 1) Always include model confidence
    label = int(ml_result["label"])
    if label == 1:
        reasons.append(
            f"Model predicts malicious with probability {p:.2f}."
        )
    else:
        reasons.append(
            f"Model predicts benign with probability {1 - p:.2f} "
            f"(malicious probability {p:.2f})."
        )

    # 2) Add heuristic reasons, if any
    heuristic_reasons = list(heur.reasons)
    if heuristic_reasons:
        reasons.append(
            "Heuristic analysis flagged the following indicators: "
            + "; ".join(heuristic_reasons)
        )

    # 3) Fallback messages based on final_label
    if not heuristic_reasons and final_label == "benign":
        reasons.append(
            "No strong malicious indicators detected by model or heuristics."
        )
    elif not heuristic_reasons and final_label != "benign":
        reasons.append(
            "Flagged primarily by the ML classifier score."
        )

    return {
        **ml_result,
        "heuristic": asdict(heur),
        "final_label": final_label,
        "risk": risk,
        "reasons": reasons,
    }

