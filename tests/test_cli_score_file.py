from pathlib import Path
import sys

from sentinelti import cli

import pytest

def test_score_file_runs(tmp_path: Path, monkeypatch, capsys, fake_cli_enrich_score) -> None:
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text(
        "http://example.com\nhttp://192.168.0.1/login\n",
        encoding="utf-8",
    )

    fake_cli_enrich_score()

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


def test_cli_reports_missing_model_artifacts_gracefully(monkeypatch, capsys, tmp_path: Path) -> None:
    # Create an input file to satisfy CLI validation
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("http://example.com\n", encoding="utf-8")

    # Make enrich_score raise the same FileNotFoundError as the model loader
    def fake_enrich_score(url: str):
        raise FileNotFoundError("No trained URL model artifacts found")

    monkeypatch.setattr(cli, "enrich_score", fake_enrich_score)

    # Simulate CLI argv
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

    with pytest.raises(SystemExit) as excinfo:
        cli.main()

    assert excinfo.value.code == 1
    out, err = capsys.readouterr()
    err_lower = err.lower()
    assert "no trained url model artifacts found" in err_lower
    assert "train the model first or add the expected model files" in err_lower