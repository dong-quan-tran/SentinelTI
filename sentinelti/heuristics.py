
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

IP and infrastructure scope
Literal IP hosts and resolved IPs are classified as loopback, private, reserved, or public and lightly influence scoring.
The scoring layer performs best-effort DNS resolution for hostnames and exposes infrastructure metadata (IP, class, internal flag, TLD, local IP reputation, and a summarized infra flag) in the enriched output.
Mild infra-based heuristics are applied when an external-looking hostname resolves to an internal or loopback IP, or when the resolved IP appears in a small, locally maintained suspicious‑IP list.
External infrastructure and reputation services (e.g., hosting provider, domain age, commercial IP/domain reputation feeds) are still not integrated; current infra signals rely only on local logic and static lists, behind a pluggable lookup_ip_reputation hook.

5. Deep paths and complex SSO flows
   - Deep paths and nested URLs contribute to the score, with lighter treatment for SSO/OAuth-style endpoints.
     However, complex but legitimate SSO or application URLs can still be flagged as suspicious in some cases.

6. Brand impersonation and typo scope
   - Brand impersonation logic focuses on obvious brand tokens
     (paypal, apple, google, microsoft, netflix, dropbox, facebook, amazon, etc.)
     outside a small whitelist of trusted domains. It does not yet cover more subtle impersonation patterns
     or use certificate/WHOIS/host reputation.
   - Additional heuristics exist for some typo/IDN domains and for generic example-like typo domains with login paths,
     but homograph coverage is not exhaustive.

     New heuristics (recent additions)
   - Login on very long or unusual domains/TLDs (especially when combined with uncommon TLDs or deep subdomains).
   - Conservative typo-domain + login detection for example-like domains (e.g. examp1e.com/login).
   - Softer scoring for nested URLs on clearly SSO/OAuth-like endpoints to avoid over-flagging legitimate flows.
   - Targeted handling for Microsoft-typo recovery domains (e.g. micr0soft-account.com/recover).
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

PORTAL_HOST_HINTS = {"portal", "intranet", "dashboard", "myaccount", "accounts", "workspace"}
COMMON_SAFE_TLDS = {"com", "org", "net", "edu", "gov"}

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
     "teams",
    "onedrive",
    "github",
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

COMMON_GENERIC_WORDS = {"example"}


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

def _simple_token(s: str) -> str:
    """Strip to letters only, for simple typo checks."""
    return "".join(ch for ch in s if ch.isalpha())


def _one_char_digit_swap(a: str, b: str) -> bool:
    """
    Return True if a and b are same length and differ in exactly one position
    where one side is a digit and the other is a letter.
    """
    if len(a) != len(b):
        return False

    diffs = [(x, y) for x, y in zip(a, b) if x != y]
    if len(diffs) != 1:
        return False

    x, y = diffs[0]
    return (x.isdigit() and y.isalpha()) or (y.isdigit() and x.isalpha())


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

    path_depth = max(0, path.count("/") - 1)

    features["path_depth"] = path_depth

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

    is_internal = False
    ip_obj = None

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        # Loopback: 127.0.0.0/8
        if ip_obj.is_loopback:
            is_internal = True
            score += RAW_IP_SCORE
            reasons.append(
                "URL host is a loopback IP (127.0.0.0/8), typically used for local-only services."
            )
        # Private RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        elif ip_obj.is_private:
            is_internal = True
            score += RAW_IP_SCORE
            reasons.append(
                "URL host is a private RFC1918 IP address, which may indicate internal service exposure."
            )
        # Reserved / documentation ranges (includes RFC 5737 example nets)
        elif ip_obj.is_reserved:
            score += RAW_IP_SCORE
            reasons.append(
                "URL uses a raw IP address from a reserved or documentation-only range, "
                "which is uncommon in normal browsing."
            )
        else:
            # Public raw IP
            score += RAW_IP_SCORE
            reasons.append(
                "URL uses a raw public IP address as host, which is common in malicious infrastructure."
            )
    else:
        if lower_host in {"localhost", "local"}:
            is_internal = True
            score += RAW_IP_SCORE
            reasons.append(
                "Hostname appears to reference a local or internal service (localhost/local)."
            )

    features["is_internal"] = is_internal

    # Extra: bare public IP combined with login path
    is_public_ip = ip_obj is not None and not (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    )
    if is_public_ip:
        path_segments = [p for p in (lower_path or "").split("/") if p]
        has_login_hint = any(seg in {"login", "signin", "sign-in"} for seg in path_segments)
        if has_login_hint:
            score += 0.5
            reasons.append(
                "Login path is hosted directly on a bare public IP address, "
                "which is a common pattern in low-reputation phishing infrastructure."
            )


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

    SPECIAL_NESTED_PARAMS = {"callback", "share", "tracker", "u", "link"}

    is_sso_like = any(hint in lower_host for hint in SSO_HOST_HINTS) or any(
        hint in lower_path for hint in SSO_PATH_HINTS
    )

    if redirect_param_nested:
        # Soften for clearly SSO-like flows
        if is_sso_like:
            score += 0.25
            reasons.append(
                "Nested redirect URL present in an SSO/OAuth-style endpoint; "
                "may be normal but can be abused if misconfigured."
            )
        else:
            score += 1.5
            reasons.append(
                "Query parameters contain a nested URL in a redirect-style parameter, "
                "which can be abused to hide redirects to malicious sites."
            )
    elif any_param_nested:
        if is_sso_like:
            # Optional: either no score, or very small score
            score += 0.1
            reasons.append(
                "Nested URL present in SSO-like query parameters; typically benign but worth light scrutiny."
            )
        else:
            score += 1.5
            if nested_param_key in SPECIAL_NESTED_PARAMS:
                score += 0.5
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

    # '@' in path near login/security
    if "@" in lower_path:
        host_tokens = (lower_host or "").replace(".", "-").split("-")
        path_tokens = [p for p in (lower_path or "").split("/") if p]
        all_tokens = host_tokens + path_tokens

        has_login_like = any(t in {"login", "signin", "sign-in"} for t in all_tokens)
        has_security_like = any(t in {"secure", "security", "security-check"} for t in all_tokens)
        has_account_like = any(t in {"account", "accounts"} for t in all_tokens)

        # Soften for clearly SSO-like flows
        is_sso_like = any(h in (lower_host or "") for h in SSO_HOST_HINTS) or any(
            h in (lower_path or "") for h in SSO_PATH_HINTS
        )

        if (has_login_like or has_security_like or has_account_like) and not is_sso_like:
            score += 0.75
            reasons.append(
                "URL path contains '@' near login or security-related terms, "
                "which can be used to obfuscate or mimic email-based phishing flows."
            )

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

    #login + weird/very long domain/TLD
    host_labels = (lower_host or "").split(".")
    tld = host_labels[-1] if host_labels else ""
    path_segments = [p for p in (lower_path or "").split("/") if p]
    has_login_hint = any(seg in {"login", "signin", "sign-in"} for seg in path_segments)

    host_tokens = (lower_host or "").replace(".", "-").split("-")
    has_login_in_host = any(tok == "login" for tok in host_tokens)

    has_login_like = has_login_hint or has_login_in_host

    is_sso_like = any(h in (lower_host or "") for h in SSO_HOST_HINTS) or any(
        h in (lower_path or "") for h in SSO_PATH_HINTS
    )

    hostname_long = len(lower_host or "") > 45
    label_depth_high = len(host_labels) >= 5
    tld_weird = tld in UNUSUAL_TLDS or len(tld) > 8

    if has_login_like and not is_sso_like and (hostname_long or label_depth_high or tld_weird):
        score += 1.5
        reasons.append(
            "Login path appears on a very long or unusual domain/TLD, "
            "which is a common pattern in credential phishing infrastructure."
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

    # Extra: executable download hosted directly on a bare public IP
    is_public_ip = ip_obj is not None and not (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    )
    if is_public_ip and filename and any(filename.endswith(ext) for ext in EXECUTABLE_EXTS):
        score += 0.5
        reasons.append(
            "Executable or script download is hosted directly on a bare public IP address, "
            "which is a common pattern in transient malware infrastructure."
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
    host_flat = normalized_host.replace(".", "").replace("-", "")

    present_brands = {b for b in BRAND_TOKENS if b in host_flat}
    phishing_hits = {k for k in PHISHING_KEYWORDS if k in lower_host or k in lower_path or k in lower_query}

    # Identify the part of the host before the base domain
    host_labels = (lower_host or "").split(".")
    base_labels = (base_domain or "").split(".")
    prefix_labels = host_labels[:-len(base_labels)] if len(host_labels) > len(base_labels) else []
    prefix_host = ".".join(prefix_labels)

    # Only apply impersonation bump if NOT a trusted brand domain
    if present_brands and phishing_hits and base_domain not in TRUSTED_DOMAINS:
        # Identify the part of the host before the base domain
        host_labels = (lower_host or "").split(".")
        base_labels = (base_domain or "").split(".") if base_domain else []
        if base_labels and len(host_labels) > len(base_labels):
            prefix_labels = host_labels[:-len(base_labels)]
        else:
            prefix_labels = []

        prefix_host = ".".join(prefix_labels)

        # Only treat as strong impersonation if the brand appears in the prefix
        if any(b in prefix_host for b in present_brands):
            score += BRAND_IMPERSONATION_SCORE
            reasons.append(
                "Subdomain contains brand-like tokens "
                f"({', '.join(sorted(present_brands))}) combined with phishing keywords "
                f"({', '.join(sorted(phishing_hits))}); likely brand impersonation."
            )

    # Mild rule: brand-like tokens anywhere in host plus login in host or path, on non-trusted domain
    if present_brands and base_domain not in TRUSTED_DOMAINS and base_domain != "github.com":
        path_segments = [p for p in (lower_path or "").split("/") if p]
        has_login_in_path = any(seg in {"login", "signin", "sign-in"} for seg in path_segments)

        host_tokens = (lower_host or "").replace(".", "-").split("-")
        has_login_in_host = any(tok in {"login", "signin", "sign-in"} for tok in host_tokens)

        has_login_like = has_login_in_path or has_login_in_host

        normalized_host = _normalize_leetspeak(lower_host or "")
        has_brand_anywhere = any(b in normalized_host for b in present_brands)

        if has_login_like and has_brand_anywhere:
            score += 1.5  # smaller than BRAND_IMPERSONATION_SCORE
            reasons.append(
                "Hostname appears brand-like and is combined with a login indicator on a non-trusted domain; "
                "this pattern is common in phishing and impersonation attacks."
            )


    # Extra: brand-like host plus login/security anywhere (even without explicit phishing_hits)
    host_tokens = lower_host.replace(".", "-").split("-")
    path_tokens = [p for p in lower_path.split("/") if p]
    all_tokens = host_tokens + path_tokens

    if present_brands and base_domain not in TRUSTED_DOMAINS:
        has_login_like = any(t in {"login", "signin", "sign-in"} for t in all_tokens)
        has_security_like = any(t in {"secure", "security", "security-check"} for t in all_tokens)
        has_recovery_like = any(t in {"recover", "recovery", "reset"} for t in all_tokens)

        if has_login_like or has_security_like or has_recovery_like:
            score += 1.0
            reasons.append(
                "Brand-like tokens appear with login/security/recovery terms on a non-trusted domain; "
                "this pattern is common in phishing and impersonation attacks."
            )

    # Conservative typo-domain + login heuristic (e.g., examp1e.com/login)
    base_labels = (base_domain or "").split(".")
    sld = base_labels[0] if base_labels else ""

    path_segments = [p for p in (lower_path or "").split("/") if p]
    has_login_hint = any(seg in {"login", "signin", "sign-in"} for seg in path_segments)

    looks_like_generic_typo = False
    if len(sld) == 7:  # exact length of "example"
        looks_like_generic_typo = _one_char_digit_swap(sld, "example")


    if looks_like_generic_typo and has_login_hint and base_domain not in TRUSTED_DOMAINS:
        score += 1.25
        reasons.append(
            "Domain name appears to be a near-typo of a generic example site "
            "combined with a login path; possible phishing typo-domain."
        )


    # Conservative special case: microsoft-typo domains with recovery paths
    looks_like_microsoft_typo = any(
        t.startswith("micr0soft") or t.startswith("micros0ft") or t == "micr0soft"
        for t in host_tokens
    )

    has_recovery_like = any(t in {"recover", "recovery", "reset"} for t in all_tokens)

    if looks_like_microsoft_typo and has_recovery_like and base_domain not in TRUSTED_DOMAINS:
        score += 1.0
        reasons.append(
            "Domain resembles a Microsoft account recovery page on a non-trusted domain; "
            "this pattern is common in account takeover phishing."
        )

    # Targeted special case: Office 365 / Microsoft login-style hosts
    if base_domain not in TRUSTED_DOMAINS:
        host_tokens = (lower_host or "").replace(".", "-").split("-")

        has_login_token = any(tok in {"login", "signin", "sign-in"} for tok in host_tokens)
        has_office365_token = any(
            tok in {"office365", "microsoftonline", "o365"} for tok in host_tokens
        )

        if has_login_token and has_office365_token:
            score += 1.5
            reasons.append(
                "Hostname combines login and Office 365/Microsoft tokens on a non-trusted domain; "
                "this pattern is common in Microsoft 365 credential phishing pages."
            )



    # Targeted special case: login-github-style hosts
    if base_domain not in TRUSTED_DOMAINS:
        host_tokens = (lower_host or "").replace(".", "-").split("-")
        has_login_token = any(tok in {"login", "signin", "sign-in"} for tok in host_tokens)
        has_github_token = any(tok == "github" for tok in host_tokens)

        if has_login_token and has_github_token:
            score += 1.0
            reasons.append(
                "Hostname combines login and GitHub tokens on a non-trusted domain; "
                "this pattern is common in GitHub credential phishing pages."
            )

    is_github_oauth = (
        base_domain == "github.com"
        and (lower_path or "").startswith("/login/oauth")
    )

    # Mild portal-like heuristic to reduce over-flagging obviously internal/portal sites
    host_tokens = (lower_host or "").replace(".", "-").split("-")
    is_portal_like = any(tok in PORTAL_HOST_HINTS for tok in host_tokens)

    # Re-use tld and domain_length we already computed
    tld = features.get("tld", "")
    domain_length = features.get("domain_length", 0)

    # Only consider softening if not already clearly malicious
    no_brand_impersonation = not present_brands
    no_giveaway_tokens = not giveaway_hits
    no_punycode = "xn--" not in lower_host

    looks_infra_normal = (tld in COMMON_SAFE_TLDS or tld == "") and domain_length < 30

    if is_portal_like and looks_infra_normal and no_brand_impersonation and no_giveaway_tokens and no_punycode:
        # Slightly reduce generic heuristic noise, but never go below zero
        if score > 0.0:
            reduction = min(0.5, score)
            score -= reduction
            reasons.append(
                "Hostname appears to be a normal portal/dashboard on a common TLD; "
                "slightly reducing heuristic risk to avoid over-flagging."
            )

    if is_github_oauth:
        score -= 0.5
        reasons.append(
            "Recognized as a standard GitHub OAuth authorization endpoint; reduced risk."
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

    # Mild signal for unusually deep paths on non-trusted, non-SSO domains
    is_trusted = base_domain in TRUSTED_DOMAINS  # or however you already do this

    if path_depth >= 6 and not is_trusted and not is_sso_like:
        score += 0.5
        reasons.append(
            "URL has an unusually deep path structure for a non-trusted domain, "
            "which can indicate complex phishing or tracking flows."
        )


    # Deduplicate reasons while preserving order
    seen = set()
    deduped_reasons: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped_reasons.append(r)

    features["raw_score"] = score

    return HeuristicResult(score=score, reasons=deduped_reasons, features=features)
