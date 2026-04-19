from pathlib import Path
import sys

from sentinelti import cli


def test_score_file_runs(tmp_path: Path, monkeypatch, capsys) -> None:
    # create a temporary urls.txt
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text(
        "http://example.com\nhttp://192.168.0.1/login\n",
        encoding="utf-8",
    )

    # Fake enrich_score so the CLI does not hit the real ML model
    def fake_enrich_score(url: str) -> dict:
        return {
            "url": url,
            "label": 0,
            "prob_malicious": 0.1,
            "final_label": "benign",
            "risk": "low",
            "reasons": [],
            "heuristic": {},
            "infrastructure": {},
        }

    monkeypatch.setattr(cli, "enrich_score", fake_enrich_score)

    # Simulate CLI argv: sentinelti score-file <file> --output-format json
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sentinelti",
            "score-file",
            str(urls_file),
            "--output-format",
            "json",
        ],
    )

    cli.main()

    out, err = capsys.readouterr()
    assert "[" in out
    assert "http://example.com" in out
    assert "http://192.168.0.1/login" in out