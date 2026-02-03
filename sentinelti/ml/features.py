from __future__ import annotations

from typing import Dict
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "confirm",
    "password",
    "bank",
]


def extract_features(url: str) -> Dict[str, float]:
    """
    Extract simple lexical features from a URL.
    """

    parsed = urlparse(url)

    full = url or ""
    domain = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Basic lengths
    url_len = len(full)
    domain_len = len(domain)
    path_len = len(path)
    query_len = len(query)

    # Character-level counts
    digits_count = sum(c.isdigit() for c in full)
    alpha_count = sum(c.isalpha() for c in full)
    special_chars = "-_.@?=&%"

    special_count = sum(c in special_chars for c in full)

    # Ratios (avoid division by zero)
    digit_ratio = digits_count / url_len if url_len > 0 else 0.0
    alpha_ratio = alpha_count / url_len if url_len > 0 else 0.0

    # Structural features
    has_ip = _looks_like_ip(domain)
    dot_count = domain.count(".")
    hyphen_count = domain.count("-")
    at_count = full.count("@")
    path_segments = path.strip("/").split("/") if path.strip("/") else []
    num_path_segments = len(path_segments)
    num_query_params = query.count("&") + (1 if query else 0)

    # Suspicious keywords
    lowered = full.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered)

    # TLD (simple extraction: last label)
    tld = domain.split(".")[-1] if "." in domain else ""

    features: Dict[str, float] = {
        "url_len": float(url_len),
        "domain_len": float(domain_len),
        "path_len": float(path_len),
        "query_len": float(query_len),
        "digits_count": float(digits_count),
        "alpha_count": float(alpha_count),
        "special_count": float(special_count),
        "digit_ratio": float(digit_ratio),
        "alpha_ratio": float(alpha_ratio),
        "has_ip": float(has_ip),
        "dot_count": float(dot_count),
        "hyphen_count": float(hyphen_count),
        "at_count": float(at_count),
        "num_path_segments": float(num_path_segments),
        "num_query_params": float(num_query_params),
        "keyword_hits": float(keyword_hits),
        "tld": 0.0,  # placeholder numeric value; handled separately
    }

    # Carry raw TLD separately
    features["_tld_raw"] = tld

    return features


def _looks_like_ip(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
