# tests/test_cli_infra_output.py

from sentinelti import cli


def test_score_url_prints_infra_summary(monkeypatch, capsys) -> None:
    # Mock enrich_score so we control infrastructure fields
    from sentinelti import scoring

    def fake_enrich(url: str) -> dict:
        return {
            "url": url,
            "label": 1,
            "prob_malicious": 0.9,
            "final_label": "suspicious",
            "risk": "medium",
            "reasons": [],
            "infrastructure": {
                "ip": "203.0.113.66",
                "ip_class": "public",
                "is_internal": False,
                "tld": "com",
                "asn": None,
                "provider": None,
                "reputation": "suspicious",
                "infra_flag": "suspicious_infra",
                "reputation_source": "local-list",
            },
        }

    monkeypatch.setattr(cli, "enrich_score", fake_enrich)

    # Call the CLI with explicit argv (so we avoid sys.argv)
    monkeypatch.setattr("sys.argv", ["sentinelti", "score-url", "http://example.com/test"])
    cli.main()

    out, err = capsys.readouterr()
    assert "Infrastructure: suspicious" in out
    assert "IP reputation: suspicious" in out
