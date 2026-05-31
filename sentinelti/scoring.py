"""
Scoring and enrichment logic for SentinelTi.

This module combines the ML URL classifier output with heuristic
signals to produce a final label, risk level, and explanations
suitable for CLI and API consumers.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

import ipaddress
from urllib.parse import urlparse

from .heuristics import analyze_url
from .resolution import resolve_hostname_to_ip
from .ml.service import score_url as ml_score_url
from .reputation import lookup_ip_reputation


TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "microsoftonline.com",
    "netflix.com",
    "paypal.com",
    "amazon.com",
}

KNOWN_SUSPICIOUS_IPS = {
    "203.0.113.66",
    "198.51.100.200",
}


def _classify_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if obj.is_loopback:
        return "loopback"
    if obj.is_private:
        return "private"
    if obj.is_reserved:
        return "reserved"
    return "public"


def build_explanation(result: Dict[str, Any]) -> Dict[str, Any]:
    final_label = result.get("final_label", "suspicious")
    risk = result.get("risk", "medium")
    prob_malicious = float(result.get("prob_malicious", 0.0))
    reasons = list(result.get("reasons", []))
    heuristic = result.get("heuristic", {}) or {}
    features = heuristic.get("features", {}) or {}
    infrastructure = result.get("infrastructure", {}) or {}

    if final_label == "malicious":
        summary = (
            "This URL looks likely malicious and should be treated as unsafe."
        )
    elif final_label == "suspicious":
        summary = (
            "This URL shows suspicious traits and should be handled carefully."
        )
    else:
        summary = (
            "This URL currently appears low risk, although no automated check is perfect."
        )

    why_parts: list[str] = []

    if prob_malicious >= 0.90:
        why_parts.append(
            "The machine-learning model assigned a very high malicious probability."
        )
    elif prob_malicious >= 0.60:
        why_parts.append(
            "The machine-learning model assigned an elevated malicious probability."
        )
    elif prob_malicious <= 0.10:
        why_parts.append(
            "The machine-learning model found relatively few malicious patterns."
        )

    if features.get("has_homoglyph_brand_pattern") or features.get("has_m_rn_homoglyph"):
        why_parts.append(
            "The hostname appears to use look-alike characters often seen in phishing domains."
        )

    if features.get("is_ip_host"):
        why_parts.append(
            "The URL uses a direct IP address instead of a normal domain name, which is often suspicious."
        )

    if features.get("has_at_symbol"):
        why_parts.append(
            "The URL contains an @ symbol, a trick sometimes used to hide the real destination."
        )

    if features.get("has_login_keyword") or features.get("has_verify_keyword"):
        why_parts.append(
            "The URL uses account-related wording such as login or verify, which is common in credential phishing."
        )

    infra_flag = infrastructure.get("infra_flag")
    if infra_flag == "suspicious_infra":
        why_parts.append(
            "Its infrastructure signals also look suspicious based on IP resolution or local reputation checks."
        )
    elif infra_flag == "internal":
        why_parts.append(
            "The hostname appears to point to internal-style infrastructure rather than a normal public site."
        )

    if not why_parts and reasons:
        why_parts.append(reasons[0])

    if final_label == "malicious":
        user_action = (
            "Do not open the link, do not enter credentials, and do not download anything from it."
        )
    elif final_label == "suspicious":
        user_action = (
            "Avoid signing in or downloading files until you verify the sender and destination independently."
        )
    else:
        user_action = (
            "Proceed carefully and still verify the domain manually before sharing sensitive information."
        )

    technical_notes: list[str] = []
    if reasons:
        technical_notes.extend(reasons[:3])

    return {
        "summary": summary,
        "why_flagged": " ".join(why_parts),
        "user_action": user_action,
        "technical_notes": technical_notes,
        "risk": risk,
        "final_label": final_label,
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
    ml_result = ml_score_url(url)
    heur = analyze_url(url)

    p = float(ml_result["prob_malicious"])
    h = float(heur.score)

    if (p >= 0.90 and h >= 1.5) or h >= 3.5:
        final_label = "malicious"
        risk = "high"
    elif p <= 0.05 and h == 0.0:
        final_label = "benign"
        risk = "low"
    elif p <= 0.10 and h < 1.5:
        final_label = "benign"
        risk = "low"
    elif p >= 0.60 or h >= 1.5:
        final_label = "suspicious"
        risk = "medium"
    else:
        if h > 0.0:
            final_label = "suspicious"
            risk = "medium"
        else:
            final_label = "benign"
            risk = "low"

    parsed = urlparse(url)
    host = parsed.hostname or ""

    parts = host.split(".")
    base_host = ".".join(parts[-2:]) if len(parts) >= 2 else host

    if base_host in TRUSTED_DOMAINS and p < 0.90:
        if h < 2.0:
            final_label = "benign"
            risk = "low"

    resolved_ip: str | None = None
    try:
        resolved_ip = resolve_hostname_to_ip(host)
    except Exception:
        resolved_ip = None

    reasons: list[str] = []

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

    heuristic_reasons = list(heur.reasons)
    if heuristic_reasons:
        reasons.append(
            "Heuristic analysis flagged the following indicators: "
            + "; ".join(heuristic_reasons)
        )

    if not heuristic_reasons and final_label == "benign":
        reasons.append(
            "No strong malicious indicators detected by model or heuristics."
        )
    elif not heuristic_reasons and final_label != "benign":
        reasons.append(
            "Flagged primarily by the ML classifier score."
        )

    ip_class = _classify_ip(resolved_ip)

    infra_note: str | None = None
    if host and not host.replace(".", "").isdigit():
        if ip_class in {"private", "loopback"}:
            infra_note = (
                "Infrastructure anomaly: external-looking hostname resolves to an internal "
                "or loopback IP address; this can indicate DNS rebinding, tunneling, or "
                "exposed internal services."
            )
            h += 0.25

    if infra_note:
        reasons.append(infra_note)

    rep_result = (
        lookup_ip_reputation(
            resolved_ip,
            suspicious_ips=KNOWN_SUSPICIOUS_IPS,
            external_provider=None,
        )
        if resolved_ip
        else None
    )
    reputation: str | None = rep_result.reputation if rep_result else "unknown"

    if reputation == "suspicious":
        h += 0.25
        reasons.append(
            "Infrastructure: resolved IP appears in a locally maintained suspicious IP list."
        )

    heuristic_dict = asdict(heur)
    infra_flag = "normal"

    has_homoglyph = heuristic_dict.get("features", {}).get("has_m_rn_homoglyph")
    if has_homoglyph:
        reasons.append(
            "URL hostname includes a known homoglyph brand pattern "
            "(e.g., rn vs m or vv vs w), often used in phishing domains."
        )

    is_internal = heuristic_dict.get("features", {}).get("is_internal")
    if is_internal:
        infra_flag = "internal"

    if reputation == "suspicious" or (
        ip_class in {"private", "loopback"} and not is_internal
    ):
        infra_flag = "suspicious_infra"

    infra = {
        "ip": resolved_ip,
        "ip_class": ip_class,
        "is_internal": is_internal,
        "tld": heuristic_dict.get("features", {}).get("tld"),
        "asn": None,
        "provider": None,
        "reputation": reputation,
        "infra_flag": infra_flag,
        "reputation_source": rep_result.source if rep_result else None,
    }

    enriched = {
        **ml_result,
        "heuristic": heuristic_dict,
        "final_label": final_label,
        "risk": risk,
        "reasons": reasons,
        "infrastructure": infra,
    }
    enriched["explanation"] = build_explanation(enriched)
    return enriched