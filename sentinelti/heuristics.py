
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

4. Only literal IP hosts are checked so far, not domain names to IP resolution or more advanced infrastructure analysis (e.g. hosting provider, age, etc.)

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

from urllib.parse import parse_qsl, unquote
from dataclasses import dataclass, field
from typing import List, Dict, Any
from urllib.parse import urlparse

import os
import tldextract
import ipaddress


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

GIVEAWAY_TOKENS = {
    "free-gift-card",
    "gift-card",
    "giftcard",
    "giveaway",
    "crypto-giveaway",
    "free-gift",
    "freegift",
    "lottery",
    "prize",
    "jackpot",
    "airdrop",
    "remote-help",
    "remote-help-session",
}


SSO_HOST_HINTS = {
    "sso.",
    "login.microsoftonline.com",
    "accounts.google.com",
}

SSO_PATH_HINTS = {
    "/saml2/",
    "/saml/",
    "/oauth2/",
    "/oauth/",
    "/idp/",
    "/authorize",
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

    lower_host = (host or "").lower()
    lower_path = path.lower()
    lower_query = query.lower()

    is_sso_like = False

    host_l = lower_host
    path_l = lower_path

    cred_keys = {"user", "username", "login"}
    pass_keys = {"password", "pass", "pwd"}

    is_docs_or_blog = lower_host.startswith("docs.") or lower_host.startswith("blog.")

    # Check for presence of credential-like parameters in the query string
    seen_cred_key = False
    seen_pass_key = False

    for key, value in parse_qsl(query, keep_blank_values=True):
        k = (key or "").lower()
        if k in cred_keys:
            seen_cred_key = True
        if k in pass_keys:
            seen_pass_key = True

    if seen_cred_key and seen_pass_key:
        score += 1.5
        reasons.append(
            "URL query contains both username- and password-style parameters, "
            "which is typical of insecure or phishing login forms."
        )

    if any(hint in host_l for hint in SSO_HOST_HINTS) or any(hint in path_l for hint in SSO_PATH_HINTS):
        is_sso_like = True


    #fragment handling for nested URL detection (e.g. http://example.com/#http://evil.com)
    fragment = parsed.fragment or ""

    if "http://" in fragment.lower() or "https://" in fragment.lower():
        score += 1.0
        reasons.append(
            "URL fragment contains a nested URL, which can be used to hide redirects or tracking."
        )


    # Punycode / IDN lookalike detection
    if "xn--" in lower_host:
        score += 1.5
        reasons.append(
            "Hostname contains Punycode (xn--), which is often used for IDN lookalike domains."
        )

    # Open-redirect / embedded URL detection in query parameters
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if ip_obj.is_private or ip_obj.is_loopback:
            score += 1.0
            reasons.append(
                "URL host resolves to a private or local IP address "
                "(e.g., internal or loopback), which may indicate internal exposure or SSRF risk."
            )
        else:
            score += RAW_IP_SCORE
            reasons.append("URL uses a raw IP address as host (common in malicious infrastructure).")
    else:
        if lower_host in {"localhost", "local"}:
            score += 1.0
            reasons.append(
                "Hostname appears to reference a local or internal service (localhost/local)."
            )
    is_internal = False

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if ip_obj.is_private or ip_obj.is_loopback:
            is_internal = True
            score += 1.0
            reasons.append(
                "URL host resolves to a private or local IP address "
                "(e.g., internal or loopback), which may indicate internal exposure or SSRF risk."
            )
        else:
            # Public (including 192.0.2.x, 198.51.100.x, 203.0.113.x)
            score += RAW_IP_SCORE
            reasons.append(
                "URL uses a raw IP address as host (common in malicious infrastructure)."
            )
    else:
        if lower_host in {"localhost", "local"}:
            is_internal = True
            score += 1.0
            reasons.append(
                "Hostname appears to reference a local or internal service (localhost/local)."
            )

    features["is_internal"] = is_internal

        

    # Common redirect-style parameter names to check
    redirect_param_names = {
        "redirect", "redir", "url", "next", "dest", "destination",
        "return", "returnurl", "target", "goto",
    }

    def _contains_http_url(s: str) -> bool:
        s_l = s.lower()
        return "http://" in s_l or "https://" in s_l

    redirect_param_nested = False

    # First pass: redirect-style params only
    for key, value in parse_qsl(query, keep_blank_values=True):
        key_l = (key or "").lower()
        if key_l not in redirect_param_names:
            continue

        candidate = value or ""

        # Up to 2 rounds of decoding to catch url=http%3A%2F%2Fevil.com and double-encoded variants
        for _ in range(2):
            if _contains_http_url(candidate):
                redirect_param_nested = True
                break
            candidate = unquote(candidate)

        if redirect_param_nested:
            break

    # Second pass: any param value (weaker signal)
    any_param_nested = redirect_param_nested
    nested_param_key = None

    if not any_param_nested:
        for key, value in parse_qsl(query, keep_blank_values=True):
            candidate = value or ""
            key_l = (key or "").lower()

            for _ in range(2):
                if _contains_http_url(candidate):
                    any_param_nested = True
                    nested_param_key = key_l
                    break
                candidate = unquote(candidate)

            if any_param_nested:
                break

    if redirect_param_nested:
        score += 1.5
        reasons.append(
            "Query parameters contain a nested URL in a redirect-style parameter, "
            "which can be abused to hide redirects to malicious sites."
        )
    elif any_param_nested:
        score += 1.25  # was 1.0
        if nested_param_key in {"callback", "share", "tracker", "u"}:
            score += 0.25
            reasons.append(
                "Nested URL appears in a callback/share/tracker-style parameter, "
                "which is often used to pull remote scripts or tracking beacons."
            )
        else:
            reasons.append(
                "Query parameters contain a nested URL, which can be abused to hide redirects to malicious sites."
            )


    # '@' in authority part
    if "@" in parsed.netloc:
        score += AT_AUTHORITY_SCORE
        reasons.append("URL contains '@' in the authority part (possible obfuscation).")

    # Suspicious tokens in path/query
    lower_path_query = (path + "?" + query).lower()
    full_url_surface = (host + path + "?" + query).lower()

    matched_tokens = sorted({t for t in SUSPICIOUS_TOKENS if t in lower_path_query})
    if matched_tokens:
        token_score = SUSPICIOUS_TOKEN_SCORE * len(matched_tokens)
        if is_sso_like:
            token_score *= 0.5  # halve the impact for SSO-like endpoints
        score += token_score
        reasons.append(
            f"Contains suspicious tokens often seen in phishing URLs: {', '.join(matched_tokens)}."
        )

    # Giveaway/lottery-style tokens
    giveaway_hits = sorted({t for t in GIVEAWAY_TOKENS if t in full_url_surface})
    if giveaway_hits:
        score += 2.0
        reasons.append(
            "URL contains giveaway/lottery-style tokens often used in scam and phishing campaigns: "
            f"{', '.join(giveaway_hits)}."
        )


    # Executable / malware-style download detection
    filename = os.path.basename(path.lower())
    EXECUTABLE_EXTS = (".exe", ".scr", ".bat", ".cmd", ".ps1")

    # Optionally compute base_domain once here, since we’ll need it later anyway
    host_labels = (host or "").split(".")
    base_domain = ".".join(host_labels[-2:]) if len(host_labels) >= 2 else host

    if filename and any(filename.endswith(ext) for ext in EXECUTABLE_EXTS):
        # Be slightly conservative: don't penalize obviously trusted domains as hard
        if base_domain in TRUSTED_DOMAINS:
            score += 0.5
            reasons.append(
                "URL points to an executable or script download on a trusted domain; "
                "may still be risky depending on context."
            )
        else:
            score += 1.5
            reasons.append(
                "URL path appears to point to an executable or script download, "
                "which is common in malware delivery."
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

    # Extra: brand-like host plus login/security anywhere (even without explicit phishing_hits)
    if present_brands and base_domain not in TRUSTED_DOMAINS:
        host_tokens = lower_host.replace(".", "-").split("-")
        path_tokens = [p for p in lower_path.split("/") if p]

        has_login_like = any(t in {"login", "signin", "sign-in"} for t in host_tokens + path_tokens)
        has_security_like = any(t in {"secure", "security", "security-check"} for t in host_tokens + path_tokens)

        if has_login_like or has_security_like:
            score += 0.75  # or 1.0, but only one of these blocks, not two
            reasons.append(
                "Brand-like tokens appear with login/security terms on a non-trusted domain; "
                "this pattern is common in phishing and impersonation attacks."
            )




    # Deep path
    depth = len([p for p in path.split("/") if p])
    features["path_depth"] = depth
    if depth >= 5:
        if is_sso_like or is_docs_or_blog:
            # maybe no bump or a tiny one
            score += 0.0
        else:
            score += DEEP_PATH_SCORE
            reasons.append("URL path is deeply nested, often used to hide payloads or phishing pages.")

    features["raw_score"] = score

    return HeuristicResult(score=score, reasons=reasons, features=features)
