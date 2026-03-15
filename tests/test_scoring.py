import socket
from typing import Iterable, Optional

import pytest

from sentinelti import resolution, scoring
from sentinelti.scoring import enrich_score
from sentinelti.heuristics import analyze_url

from sentinelti.scoring import enrich_score
from sentinelti.reputation import IPReputationResult, ExternalIPReputationProvider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reasons_text(result: dict) -> str:
    return " ".join(result.get("reasons", []))


def _has_reason(snippet: str, reasons: Iterable[str]) -> bool:
    return any(snippet in r for r in reasons)


# ---------------------------------------------------------------------------
# Enriched scoring shape / infra metadata
# ---------------------------------------------------------------------------

def test_enrich_score_has_expected_keys() -> None:
    result = enrich_score("http://example.com")

    for key in ["url", "label", "prob_malicious", "final_label", "risk", "reasons", "heuristic"]:
        assert key in result

    assert isinstance(result["reasons"], list)
    assert isinstance(result["heuristic"], dict)


def test_enrich_score_includes_infrastructure_metadata() -> None:
    result = enrich_score("http://example.com")
    infra = result["infrastructure"]

    for key in [
        "ip",
        "ip_class",
        "is_internal",
        "tld",
        "asn",
        "provider",
        "reputation",
        "infra_flag",
    ]:
        assert key in infra

    if infra["ip_class"] is not None:
        assert infra["ip_class"] in {"loopback", "private", "reserved", "public"}

    assert infra["reputation"] in {"unknown", "suspicious"}
    assert infra["infra_flag"] in {"normal", "internal", "suspicious_infra"}


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/login",
        "http://192.168.0.1/login",
        "http://93.184.216.34/login",
    ],
)
def test_infrastructure_metadata_present_for_domains_and_ips(url: str) -> None:
    result = enrich_score(url)
    infra = result["infrastructure"]

    for key in ["ip", "ip_class", "is_internal", "tld", "asn", "provider", "reputation"]:
        assert key in infra


# ---------------------------------------------------------------------------
# Infra heuristics / infra_flag
# ---------------------------------------------------------------------------

def test_external_hostname_resolving_to_private_ip_adds_infra_note(monkeypatch) -> None:
    def fake_resolve(host: str) -> str:
        assert host == "example.com"
        return "10.0.0.42"

    monkeypatch.setattr(scoring, "resolve_hostname_to_ip", fake_resolve)

    result = scoring.enrich_score("http://example.com/login")
    reasons_text = _reasons_text(result)
    assert "external-looking hostname resolves to an internal or loopback IP address" in reasons_text


def test_local_suspicious_ip_sets_reputation_and_reason(monkeypatch) -> None:
    def fake_resolve(host: str) -> str:
        assert host == "example.com"
        return "203.0.113.66"  # in KNOWN_SUSPICIOUS_IPS

    monkeypatch.setattr(scoring, "resolve_hostname_to_ip", fake_resolve)

    result = scoring.enrich_score("http://example.com/login")
    infra = result["infrastructure"]

    assert infra["ip"] == "203.0.113.66"
    assert infra["reputation"] == "suspicious"

    reasons_text = _reasons_text(result)
    assert "resolved IP appears in a locally maintained suspicious IP list" in reasons_text


def test_external_hostname_resolving_to_private_ip_sets_suspicious_infra(monkeypatch) -> None:
    def fake_resolve(host: str) -> str:
        assert host == "example.com"
        return "192.168.1.10"  # private IP

    monkeypatch.setattr(scoring, "resolve_hostname_to_ip", fake_resolve)

    result = scoring.enrich_score("http://example.com/login")
    infra = result["infrastructure"]

    assert infra["ip"] == "192.168.1.10"
    assert infra["ip_class"] == "private"
    assert infra["infra_flag"] == "suspicious_infra"


def test_literal_internal_ip_host_sets_internal_flag() -> None:
    result = scoring.enrich_score("http://192.168.1.20/admin")
    infra = result["infrastructure"]

    assert infra["ip"] in {"192.168.1.20", None}
    assert infra["ip_class"] in {"private", None}
    assert infra["is_internal"] is True
    assert infra["infra_flag"] in {"internal", "suspicious_infra"}


# ---------------------------------------------------------------------------
# Heuristic feature tests (path depth, URL length, brand/typo)
# ---------------------------------------------------------------------------

def test_path_depth_feature_is_populated() -> None:
    h = analyze_url("http://example.com/a/b/c")
    assert "path_depth" in h.features
    assert h.features["path_depth"] == 3


def test_deep_path_on_non_trusted_domain_increases_score() -> None:
    h = analyze_url("http://evil.test/a/b/c/d/e/f/g")
    assert h.features["path_depth"] >= 6
    assert h.score > 0.0
    assert _has_reason("unusually deep path", h.reasons)


def test_deep_path_on_sso_like_endpoint_is_treated_softly() -> None:
    h = analyze_url(
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize/a/b/c/d/e/f"
    )
    assert h.features["path_depth"] >= 6
    assert not _has_reason("unusually deep path", h.reasons)


def test_url_length_feature_is_populated() -> None:
    h = analyze_url("http://example.com/a")
    assert "url_length" in h.features
    assert h.features["url_length"] > 0


def test_brand_token_in_path_not_domain_increases_score() -> None:
    h = analyze_url("http://randomsite.com/paypal-login")
    assert h.score > 0.0
    assert _has_reason("Brand token 'paypal'", h.reasons)


def test_brand_token_in_trusted_domain_does_not_trigger_path_brand_reason() -> None:
    h = analyze_url("https://paypal.com/signin")
    assert not _has_reason("Brand token 'paypal'", h.reasons)


def test_example_like_domain_without_login_path_is_weaker() -> None:
    h = analyze_url("http://examp1e.com/")
    assert not _has_reason("example/typo domain", h.reasons)


def test_enrich_score_includes_homoglyph_reason() -> None:
    result = enrich_score("https://rnicrosoft.com/login")
    joined = " ".join(result["reasons"]).lower()
    assert "homoglyph" in joined or "rn vs m" in joined


def test_enrich_score_uses_local_ip_reputation() -> None:
    url = "http://203.0.113.66/login"

    result = enrich_score(url)

    infra = result["infrastructure"]
    assert infra["ip"] == "203.0.113.66"
    # 203.0.113.66 is in KNOWN_SUSPICIOUS_IPS, so reputation should be suspicious
    assert infra["reputation"] == "suspicious"
    assert infra["reputation_source"] == "local-list"
