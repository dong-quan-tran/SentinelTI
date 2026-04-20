import socket
from typing import Iterable, Optional

import pytest

from sentinelti import resolution, scoring
from sentinelti.scoring import enrich_score
from sentinelti.heuristics import analyze_url
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


def test_enrich_score_has_expected_keys(fake_ml_score) -> None:
    fake_ml_score(prob=0.08, label=0)

    result = enrich_score("http://example.com")

    assert "url" in result
    assert "label" in result
    assert "prob_malicious" in result


def test_enrich_score_includes_infrastructure_metadata(monkeypatch) -> None:
    def fake_ml_score_url(url: str) -> dict:
        return {
            "url": url,
            "label": 0,
            "prob_malicious": 0.05,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

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
def test_infrastructure_metadata_present_for_domains_and_ips(url: str, monkeypatch) -> None:
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.10,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    infra = result["infrastructure"]

    for key in ["ip", "ip_class", "is_internal", "tld", "asn", "provider", "reputation"]:
        assert key in infra