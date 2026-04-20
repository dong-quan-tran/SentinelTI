import pytest

from sentinelti import scoring
from sentinelti import cli


@pytest.fixture
def fake_ml_score(monkeypatch):
    """
    Patch sentinelti.scoring.ml_score_url with configurable fake output.

    Usage:
        def test_something(fake_ml_score):
            fake_ml_score(prob=0.20, label=0)
            result = enrich_score("http://example.com")
    """
    def _apply(prob: float = 0.10, label: int = 0):
        def fake_ml_score_url(url: str) -> dict:
            return {
                "url": url,
                "label": label,
                "prob_malicious": prob,
            }

        monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)
        return fake_ml_score_url

    return _apply


@pytest.fixture
def fake_cli_enrich_score(monkeypatch):
    """
    Patch sentinelti.cli.enrich_score with configurable fake output.

    Usage:
        def test_cli(fake_cli_enrich_score):
            fake_cli_enrich_score()
            ...
    """
    def _apply(
        *,
        label: int = 0,
        prob_malicious: float = 0.10,
        final_label: str = "benign",
        risk: str = "low",
        reasons: list[str] | None = None,
        heuristic: dict | None = None,
        infrastructure: dict | None = None,
    ):
        def fake_enrich_score(url: str) -> dict:
            return {
                "url": url,
                "label": label,
                "prob_malicious": prob_malicious,
                "final_label": final_label,
                "risk": risk,
                "reasons": reasons or [],
                "heuristic": heuristic or {},
                "infrastructure": infrastructure or {},
            }

        monkeypatch.setattr(cli, "enrich_score", fake_enrich_score)
        return fake_enrich_score

    return _apply