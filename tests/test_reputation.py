import pytest

from typing import Optional

from sentinelti.reputation import (
    IPReputationResult,
    lookup_ip_reputation,
)


def test_lookup_ip_reputation_unknown_by_default() -> None:
    result = lookup_ip_reputation("203.0.113.10", suspicious_ips=[])
    assert result.reputation == "unknown"


def test_lookup_ip_reputation_marks_local_suspicious() -> None:
    result = lookup_ip_reputation("203.0.113.42", suspicious_ips={"203.0.113.42"})
    assert result.reputation == "suspicious"
    assert result.source == "local-list"

class DummyExternalProvider:
    def __init__(self, mapping: dict[str, IPReputationResult]) -> None:
        self.mapping = mapping

    def lookup(self, ip: str) -> Optional[IPReputationResult]:
        return self.mapping.get(ip)


def test_external_provider_can_override_local_list() -> None:
    ext_result = IPReputationResult(reputation="trusted", source="external-feed")
    provider = DummyExternalProvider({"203.0.113.10": ext_result})

    result = lookup_ip_reputation("203.0.113.10", suspicious_ips={"203.0.113.10"}, external_provider=provider)
    assert result.reputation == "trusted"
    assert result.source == "external-feed"

def test_lookup_ip_reputation_uses_external_provider_when_available() -> None:
    external_result = IPReputationResult(reputation="trusted", source="external-feed")
    provider = DummyExternalProvider({"203.0.113.10": external_result})

    result = lookup_ip_reputation(
        "203.0.113.10",
        suspicious_ips={"203.0.113.10"},
        external_provider=provider,
    )

    assert result.reputation == "trusted"
    assert result.source == "external-feed"