import socket
from sentinelti.scoring import enrich_score
from sentinelti import resolution
from sentinelti import scoring
import pytest


def test_enrich_score_has_expected_keys():
    result = enrich_score("http://example.com")

    for key in ["url", "label", "prob_malicious", "final_label", "risk", "reasons", "heuristic"]:
        assert key in result

    assert isinstance(result["reasons"], list)
    assert isinstance(result["heuristic"], dict)


def test_enrich_score_includes_infrastructure_metadata() -> None:
    result = enrich_score("http://example.com")

    assert "infrastructure" in result
    infra = result["infrastructure"]

    for key in ["ip", "ip_class", "is_internal", "tld", "asn", "provider", "reputation"]:
        assert key in infra

    # ip_class may be None or one of the known categories
    if infra["ip_class"] is not None:
        assert infra["ip_class"] in {"loopback", "private", "reserved", "public"}

    # reputation should be either unknown or suspicious at this stage
    assert infra["reputation"] in {"unknown", "suspicious"}


def test_external_hostname_resolving_to_private_ip_adds_infra_note(monkeypatch):
    def fake_resolve(host: str) -> str:
        assert host == "example.com"
        return "10.0.0.42"

    monkeypatch.setattr(scoring, "resolve_hostname_to_ip", fake_resolve)

    result = scoring.enrich_score("http://example.com/login")
    reasons_text = " ".join(result["reasons"])
    assert "Hostname resolves to an internal or loopback IP address" in reasons_text

def test_local_suspicious_ip_sets_reputation_and_reason(monkeypatch):
    def fake_resolve(host: str) -> str:
        assert host == "example.com"
        # Use one of the KNOWN_SUSPICIOUS_IPS from scoring.py
        return "203.0.113.66"

    monkeypatch.setattr(scoring, "resolve_hostname_to_ip", fake_resolve)

    result = scoring.enrich_score("http://example.com/login")
    infra = result["infrastructure"]

    assert infra["ip"] == "203.0.113.66"
    assert infra["reputation"] == "suspicious"

    reasons_text = " ".join(result["reasons"])
    assert "locally maintained list of suspicious infrastructure" in reasons_text

@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/login",
        "http://192.168.0.1/login",
    ],
)
def test_infrastructure_metadata_present_for_domains_and_ips(url: str) -> None:
    result = enrich_score(url)
    infra = result["infrastructure"]

    for key in ["ip", "ip_class", "is_internal", "tld", "asn", "provider", "reputation"]:
        assert key in infra
