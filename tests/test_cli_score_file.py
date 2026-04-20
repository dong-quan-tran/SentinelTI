from pathlib import Path
import sys

from sentinelti import cli


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