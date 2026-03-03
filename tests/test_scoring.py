from sentinelti.scoring import enrich_score


def test_enrich_score_includes_infrastructure_metadata() -> None:
    result = enrich_score("http://example.com")

    assert "infrastructure" in result

    infra = result["infrastructure"]
    for key in ["ip", "ip_class", "is_internal", "tld", "asn", "reputation"]:
        assert key in infra

    # For now, only is_internal/tld are meaningful; others are placeholders
    assert infra["ip"] is None
    assert infra["ip_class"] is None


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
    for key in ["ip", "ip_class", "is_internal", "tld", "asn", "reputation"]:
        assert key in infra

    # We cannot guarantee DNS in tests, but ip should be present as a key.
    # ip_class remains None for now (not wired yet).
    assert infra["ip_class"] is None