from sentinelti.reputation import lookup_ip_reputation


def test_ip_reputation_lookup_defaults_to_unknown() -> None:
    res = lookup_ip_reputation("203.0.113.66")
    assert res.reputation == "unknown"
