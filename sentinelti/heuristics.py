
from __future__ import annotations
"""
Heuristic URL analysis for SentinelTi.

This module inspects a URL for phishing and malware indicators
(e.g. raw IP hosts, suspicious tokens, uncommon TLDs) and returns
a numeric risk score plus human-readable reasons to enrich the
ML classifier output.
"""

"""
Current limitations of heuristic-based URL analysis (v1)

These heuristics are intentionally simple and conservative. They are useful
for enriching the ML model output but are NOT a full phishing/malware
detection engine. Known limitations include:

1. Typosquatting and IDN lookalikes
   - Domains like examp1e.com, paypa1-secure.com, micr0soft-account.com or
     IDN/punycode forms (e.g. xn--pple-43d.com) are only weakly detected
     via generic tokens (e.g. "login") and not via true brand-similarity
     logic. Many such domains may still score as benign.

2. Open-redirect patterns and embedded evil URLs
   - URLs that contain another URL in query parameters or fragments
     (e.g. redirect=http://evil.com, url=http%3A%2F%2Fevil.com, or
     #https://evil.com) are not explicitly analyzed. These may appear as
     benign if other heuristics do not fire.

3. Malware download and payload indicators
   - File downloads (e.g. *.exe, payload.exe, update.exe, setup.exe) and
     paths suggesting drive-by or dropper behavior are not given strong
     special treatment. Such URLs can remain low-score or benign unless
     the ML model flags them.

4. Internal / local infrastructure
   - IP-based URLs (e.g. 127.0.0.1, 192.168.x.x, 10.x.x.x) are treated
     similarly to external IPs. This can over-flag internal dashboards or
     admin panels as suspicious when they use raw IPs.

5. Deep paths and complex SSO flows
   - Deeply nested paths contribute to the score only when combined with
     suspicious tokens, but complex yet legitimate SSO or application
     URLs can still be flagged as suspicious in some cases.

6. Brand impersonation scope
   - Brand impersonation logic focuses on obvious brand tokens
     (paypal, apple, google, microsoft, netflix, etc.) outside a small
     whitelist of trusted domains. It does not yet consider more subtle
     forms of impersonation or full certificate/WHOIS/host reputation.

These heuristics should be viewed as a lightweight signal layer. Any
strong security decision should consider the ML model output, additional
context (e.g. threat intel, reputation), and future rules that address
the above gaps.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from urllib.parse import urlparse

import tldextract


SUSPICIOUS_TOKENS = {
    "login", "log-in", "signin", "sign-in",
    "verify", "verification", "update", "secure",
    "account", "bank", "paypal", "appleid", "office365",
    "microsoft", "netflix", "payment", "invoice",
}

UNUSUAL_TLDS = {
    "xyz", "top", "club", "click", "link",
    "online", "work", "pw", "guru", "kim",
}

TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "microsoftonline.com",
    "netflix.com",
    "paypal.com",
    "amazon.com",
}

BRAND_TOKENS = {
    "paypal",
    "appleid",
    "apple",
    "google",
    "office365",
    "microsoft",
    "netflix",
    "dropbox",
    "facebook",
    "faceb0ok",
    "bankofamerica",
    "amazon",
}

PHISHING_KEYWORDS = {
    "login", "signin", "sign-in",
    "verify", "verification",
    "secure", "security",
    "account", "password",
    "update", "confirm",
}

RAW_IP_SCORE = 2.0
AT_AUTHORITY_SCORE = 1.5
SUSPICIOUS_TOKEN_SCORE = 0.75
UNUSUAL_TLD_SCORE = 1.0
LONG_DOMAIN_SCORE = 0.5
DEEP_PATH_SCORE = 0.5

BRAND_IMPERSONATION_SCORE = 2.0

@dataclass
class HeuristicResult:
    score: float
    reasons: List[str] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)

def _normalize_leetspeak(s: str) -> str:
    """
    Very simple leetspeak normalizer to help catch brand lookalike domains.
    This is intentionally conservative to avoid too many false positives.
    """
    table = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a",
    })
    return s.translate(table)

def analyze_url(url: str) -> HeuristicResult:
    """
    Analyze a URL and return heuristic score + reasons.
    This does NOT call the ML model.
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    score = 0.0
    reasons: List[str] = []
    features: Dict[str, Any] = {}

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Punycode / IDN lookalike detection
    lower_host = (host or "").lower()
    if "xn--" in lower_host:
        score += 1.5
        reasons.append(
            "Hostname contains Punycode (xn--), which is often used for IDN lookalike domains."
        )


    # Raw IP host (very rough check)
    if host.replace(".", "").isdigit():
        score += RAW_IP_SCORE
        reasons.append("URL uses a raw IP address as host (common in malicious infrastructure).")

    # '@' in authority part
    if "@" in parsed.netloc:
        score += AT_AUTHORITY_SCORE
        reasons.append("URL contains '@' in the authority part (possible obfuscation).")

    # Suspicious tokens in path/query
    lower_path_query = (path + "?" + query).lower()
    matched_tokens = sorted({t for t in SUSPICIOUS_TOKENS if t in lower_path_query})
    if matched_tokens:
        token_score = SUSPICIOUS_TOKEN_SCORE * len(matched_tokens)
        score += token_score
        reasons.append(
            f"Contains suspicious tokens often seen in phishing URLs: {', '.join(matched_tokens)}."
        )

    # Unusual TLD
    tld = (ext.suffix or "").lower()
    features["tld"] = tld
    if tld in UNUSUAL_TLDS:
        score += UNUSUAL_TLD_SCORE
        reasons.append(f"Uses an uncommon TLD: .{tld}.")

    # Long domain (subdomain + domain)
    domain_length = len(ext.domain or "") + len(ext.subdomain or "")
    features["domain_length"] = domain_length
    if domain_length >= 20:
        score += LONG_DOMAIN_SCORE
        reasons.append("Domain part is unusually long, which can indicate obfuscation.")

        # New: brand impersonation heuristic
    host_labels = (host or "").split(".")
    base_domain = ".".join(host_labels[-2:]) if len(host_labels) >= 2 else host
    lower_host = (host or "").lower()
    lower_path = path.lower()
    lower_query = query.lower()

    normalized_host = _normalize_leetspeak(lower_host)

    present_brands = {b for b in BRAND_TOKENS if b in normalized_host}
    phishing_hits = {k for k in PHISHING_KEYWORDS if k in lower_host or k in lower_path or k in lower_query}

    # Only apply impersonation bump if NOT a trusted brand domain
    if present_brands and phishing_hits and base_domain not in TRUSTED_DOMAINS:
        score += BRAND_IMPERSONATION_SCORE
        reasons.append(
            "Hostname contains brand-like tokens "
            f"({', '.join(sorted(present_brands))}) combined with phishing keywords "
            f"({', '.join(sorted(phishing_hits))}); likely brand impersonation."
        )


    # Deep path
    depth = len([p for p in path.split("/") if p])
    features["path_depth"] = depth
    if depth >= 4:
        score += DEEP_PATH_SCORE
        reasons.append("URL path is deeply nested, often used to hide payloads or phishing pages.")

    features["raw_score"] = score

    return HeuristicResult(score=score, reasons=reasons, features=features)
