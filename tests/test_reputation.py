from sentinelti.reputation import lookup_ip_reputation


def test_lookup_ip_reputation_unknown_by_default() -> None:
    result = lookup_ip_reputation("203.0.113.10", suspicious_ips=[])
    assert result.reputation == "unknown"


def test_lookup_ip_reputation_marks_local_suspicious() -> None:
    result = lookup_ip_reputation("203.0.113.42", suspicious_ips={"203.0.113.42"})
    assert result.reputation == "suspicious"
    assert result.source == "local-list"
