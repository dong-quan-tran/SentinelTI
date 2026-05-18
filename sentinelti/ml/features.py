from __future__ import annotations

from typing import Dict
from urllib.parse import urlparse, parse_qsl, unquote
import math
import ipaddress


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "confirm",
    "password",
    "bank",
    "signin",
    "sign-in",
    "security",
    "reset",
    "recovery",
    "invoice",
    "payment",
    "wallet",
    "gift",
    "prize",
    "crypto",
    "office365",
    "microsoft",
    "paypal",
    "google",
    "apple",
    "netflix",
    "amazon",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".js", ".jar", ".zip", ".rar"
}

REDIRECT_PARAM_NAMES = {
    "redirect", "redir", "url", "next", "dest", "destination",
    "return", "returnurl", "target", "goto",
}

UNUSUAL_PORTS = {81, 82, 3000, 3333, 4443, 4444, 5555, 8000, 8080, 8081, 8443, 9000}


def extract_features(url: str) -> Dict[str, float]:
    parsed = urlparse(url)

    full = url or ""
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or ""
    domain = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    lower_full = full.lower()
    lower_host = host.lower()
    lower_path = path.lower()
    lower_query = query.lower()

    url_len = len(full)
    domain_len = len(domain)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)
    fragment_len = len(fragment)

    digits_count = sum(c.isdigit() for c in full)
    alpha_count = sum(c.isalpha() for c in full)
    slash_count = full.count("/")
    dot_count_full = full.count(".")
    dot_count_host = host.count(".")
    hyphen_count_host = host.count("-")
    underscore_count = full.count("_")
    percent_count = full.count("%")
    equals_count = full.count("=")
    amp_count = full.count("&")
    question_count = full.count("?")
    at_count = full.count("@")

    special_chars = "-_.@?=&%:/#"
    special_count = sum(c in special_chars for c in full)

    digit_ratio = digits_count / url_len if url_len > 0 else 0.0
    alpha_ratio = alpha_count / url_len if url_len > 0 else 0.0
    special_ratio = special_count / url_len if url_len > 0 else 0.0

    has_ip = _looks_like_ip(host)
    is_http = float(scheme == "http")
    is_https = float(scheme == "https")

    # Safe port handling: some malformed URLs may have non-numeric ports
    raw_port = None
    try:
        raw_port = parsed.port
    except ValueError:
        raw_port = None

    has_port = float(raw_port is not None)
    port_value = float(raw_port or 0)
    uncommon_port = float((raw_port or 0) in UNUSUAL_PORTS)

    host_labels = [p for p in host.split(".") if p]
    subdomain_depth = float(max(len(host_labels) - 2, 0))
    max_host_label_len = float(max((len(p) for p in host_labels), default=0))
    avg_host_label_len = (
        float(sum(len(p) for p in host_labels) / len(host_labels))
        if host_labels else 0.0
    )

    path_segments = [p for p in path.strip("/").split("/") if p]
    num_path_segments = float(len(path_segments))
    max_path_segment_len = float(max((len(p) for p in path_segments), default=0))

    query_params = list(parse_qsl(query, keep_blank_values=True))
    num_query_params = float(len(query_params))

    keyword_hits = float(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_full))
    keyword_density = keyword_hits / max(url_len, 1)

    tld = host.split(".")[-1] if "." in host else ""

    has_punycode = float("xn--" in lower_host)
    has_fragment = float(bool(fragment))
    has_nested_url_in_query = float(_query_has_nested_url(query))
    has_nested_url_in_fragment = float(("http://" in fragment.lower()) or ("https://" in fragment.lower()))
    redirect_param_count = float(sum(1 for k, _ in query_params if (k or "").lower() in REDIRECT_PARAM_NAMES))

    login_in_host = float(any(tok in lower_host for tok in ["login", "signin", "sign-in"]))
    login_in_path = float(any(tok in lower_path for tok in ["login", "signin", "sign-in"]))
    brand_in_host = float(any(tok in lower_host for tok in ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "github"]))
    brand_in_path = float(any(tok in lower_path for tok in ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "github"]))

    suspicious_extension = float(_has_suspicious_extension(lower_path))
    repeated_char_ratio = float(_repeated_char_ratio(lower_full))
    url_entropy = float(_shannon_entropy(lower_full))

    is_internal_host = float(_is_internal_host(host))
    https_token_in_host = float("https" in lower_host)
    double_slash_in_path = float("//" in path)
    tilde_count = float(full.count("~"))
    plus_count = float(full.count("+"))
    semicolon_count = float(full.count(";"))

    features: Dict[str, float] = {
        "url_len": float(url_len),
        "domain_len": float(domain_len),
        "host_len": float(host_len),
        "path_len": float(path_len),
        "query_len": float(query_len),
        "fragment_len": float(fragment_len),
        "digits_count": float(digits_count),
        "alpha_count": float(alpha_count),
        "special_count": float(special_count),
        "slash_count": float(slash_count),
        "dot_count_full": float(dot_count_full),
        "dot_count_host": float(dot_count_host),
        "hyphen_count_host": float(hyphen_count_host),
        "underscore_count": float(underscore_count),
        "percent_count": float(percent_count),
        "equals_count": float(equals_count),
        "amp_count": float(amp_count),
        "question_count": float(question_count),
        "at_count": float(at_count),
        "digit_ratio": float(digit_ratio),
        "alpha_ratio": float(alpha_ratio),
        "special_ratio": float(special_ratio),
        "has_ip": float(has_ip),
        "is_http": is_http,
        "is_https": is_https,
        "has_port": has_port,
        "port_value": port_value,
        "uncommon_port": uncommon_port,
        "subdomain_depth": subdomain_depth,
        "max_host_label_len": max_host_label_len,
        "avg_host_label_len": avg_host_label_len,
        "num_path_segments": num_path_segments,
        "max_path_segment_len": max_path_segment_len,
        "num_query_params": num_query_params,
        "keyword_hits": float(keyword_hits),
        "keyword_density": float(keyword_density),
        "has_punycode": has_punycode,
        "has_fragment": has_fragment,
        "has_nested_url_in_query": has_nested_url_in_query,
        "has_nested_url_in_fragment": has_nested_url_in_fragment,
        "redirect_param_count": redirect_param_count,
        "login_in_host": login_in_host,
        "login_in_path": login_in_path,
        "brand_in_host": brand_in_host,
        "brand_in_path": brand_in_path,
        "suspicious_extension": suspicious_extension,
        "repeated_char_ratio": repeated_char_ratio,
        "url_entropy": url_entropy,
        "is_internal_host": is_internal_host,
        "https_token_in_host": https_token_in_host,
        "double_slash_in_path": double_slash_in_path,
        "tilde_count": tilde_count,
        "plus_count": plus_count,
        "semicolon_count": semicolon_count,
        "tld": 0.0,
    }

    features["_tld_raw"] = tld
    return features


def _looks_like_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _is_internal_host(host: str) -> bool:
    if not host:
        return False
    if host.lower() in {"localhost", "local"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _has_suspicious_extension(path: str) -> bool:
    return any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


def _query_has_nested_url(query: str) -> bool:
    for _, value in parse_qsl(query, keep_blank_values=True):
        candidate = value or ""
        for _ in range(2):
            lower = candidate.lower()
            if "http://" in lower or "https://" in lower:
                return True
            candidate = unquote(candidate)
    return False


def _repeated_char_ratio(s: str) -> float:
    if not s:
        return 0.0
    repeated = 0
    prev = None
    for ch in s:
        if ch == prev:
            repeated += 1
        prev = ch
    return repeated / len(s)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy