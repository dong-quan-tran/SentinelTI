import csv

import pytest

from sentinelti.ml.audit_supplemental import audit, read_csv
from sentinelti.ml.supplemental_data import FIELDS


def write_csv(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def record(url, label="benign"):
    return {
        "url": url,
        "label": label,
        "source": "synthetic-fixture",
        "source_reference": "fixture:001",
        "collected_at": "2026-10-08T12:00:00Z",
        "reviewed_at": "2026-10-08T13:00:00Z",
        "reviewer": "test-reviewer",
        "review_evidence": "Synthetic fixture, not a real label judgment.",
    }


def run_audit(tmp_path, records, original=(), manifest=()):
    supplemental = write_csv(tmp_path / "supplemental.csv", FIELDS, records)
    base = write_csv(tmp_path / "original.csv", ("url", "label"), original)
    split = write_csv(tmp_path / "split.csv", ("group", "partition"), manifest)
    return audit(supplemental, base, split)


def test_empty_template_does_not_authorize_training(tmp_path):
    result = run_audit(tmp_path, [])
    assert result["status"] == "empty"
    assert result["supplemental_rows"] == 0
    assert result["training_authorized"] is False


def test_normalized_conflict_blocks_audit(tmp_path):
    result = run_audit(
        tmp_path,
        [
            record("https://fixture-site.com"),
            record("https://fixture-site.com/", "malicious"),
        ],
    )
    assert result["status"] == "blocked"
    assert result["findings"]["normalized_label_conflicts"] == 1


def test_normalized_duplicate_requires_review(tmp_path):
    result = run_audit(
        tmp_path,
        [
            record("https://fixture-site.com"),
            record("https://fixture-site.com/"),
        ],
    )
    assert result["status"] == "review_required"
    assert result["findings"]["normalized_duplicates"] == 1


def test_original_label_conflict_blocks_audit(tmp_path):
    result = run_audit(
        tmp_path,
        [record("https://fixture-site.com")],
        [{"url": "https://fixture-site.com/", "label": "malicious"}],
    )
    assert result["status"] == "blocked"
    assert result["findings"]["original_label_conflict_rows"] == 1


def test_original_same_label_overlap_requires_review(tmp_path):
    result = run_audit(
        tmp_path,
        [record("https://fixture-site.com")],
        [{"url": "https://fixture-site.com/", "label": "benign"}],
    )
    assert result["status"] == "review_required"
    assert result["findings"]["original_url_overlap_rows"] == 1


def test_existing_holdout_domain_requires_review(tmp_path):
    result = run_audit(
        tmp_path,
        [record("https://login.fixture-site.com/path")],
        manifest=[{"group": "fixture-site.com", "partition": "test"}],
    )
    assert result["status"] == "review_required"
    assert result["manifest_domain_overlap_rows"]["test"] == 1
    assert result["coverage_rows"] == {"benign:https_subdomain": 1}


def test_unseen_domain_passes_checks_but_not_training_authorization(tmp_path):
    result = run_audit(tmp_path, [record("http://fixture-site.com")])
    assert result["status"] == "checks_passed"
    assert result["training_authorized"] is False
    assert result["manifest_domain_overlap_rows"]["unseen"] == 1
    assert result["coverage_rows"] == {"benign:http_apex": 1}


def test_diagnostic_domain_requires_review(tmp_path):
    result = run_audit(tmp_path, [record("https://example.com")])
    assert result["status"] == "review_required"
    assert result["findings"]["diagnostic_domain_rows"] == 1


def test_conflicting_manifest_partitions_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="Duplicate group"):
        run_audit(
            tmp_path,
            [],
            manifest=[
                {"group": "fixture-site.com", "partition": "train"},
                {"group": "fixture-site.com", "partition": "test"},
            ],
        )


def test_duplicate_csv_headers_are_rejected(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("url,url,label\na,b,benign\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate CSV headers"):
        read_csv(path, ("url", "label"))
