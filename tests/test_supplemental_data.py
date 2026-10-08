import pytest

from sentinelti.ml.supplemental_data import (
    FIELDS,
    validate_record,
    validate_records,
)


@pytest.fixture
def record():
    return {
        "url": "http://example.com",
        "label": "benign",
        "source": "synthetic-test-fixture",
        "source_reference": "fixture:001",
        "collected_at": "2026-10-08T12:00:00Z",
        "reviewed_at": "2026-10-08T13:00:00Z",
        "reviewer": "test-reviewer",
        "review_evidence": "Synthetic fixture; not a real benign judgment.",
    }


def test_valid_record_preserves_original_url(record):
    result = validate_record(record)
    assert result == record
    assert result is not record
    assert result["url"] == "http://example.com"


@pytest.mark.parametrize("label", ["benign", "malicious"])
def test_supported_labels(record, label):
    record["label"] = label
    assert validate_record(record)["label"] == label


@pytest.mark.parametrize("field", FIELDS)
def test_missing_field_is_rejected(record, field):
    del record[field]
    with pytest.raises(ValueError, match="Schema mismatch"):
        validate_record(record)


@pytest.mark.parametrize("value", ["", " ", None])
def test_empty_review_evidence_is_rejected(record, value):
    record["review_evidence"] = value
    with pytest.raises(ValueError, match="review_evidence"):
        validate_record(record)


def test_extra_field_is_rejected(record):
    record["inferred_label"] = "benign"
    with pytest.raises(ValueError, match="Schema mismatch"):
        validate_record(record)


def test_unknown_label_is_rejected(record):
    record["label"] = "safe"
    with pytest.raises(ValueError, match="label"):
        validate_record(record)


@pytest.mark.parametrize(
    "url",
    ["example.com", "ftp://example.com", "https://", "https://example.com:99999"],
)
def test_invalid_url_is_rejected(record, url):
    record["url"] = url
    with pytest.raises(ValueError, match="url"):
        validate_record(record)


def test_surrounding_whitespace_is_rejected(record):
    record["url"] = " https://example.com/"
    with pytest.raises(ValueError, match="whitespace"):
        validate_record(record)


@pytest.mark.parametrize("field", ["collected_at", "reviewed_at"])
def test_timezone_is_required(record, field):
    record[field] = "2026-10-08T12:00:00"
    with pytest.raises(ValueError, match="timezone"):
        validate_record(record)


def test_invalid_timestamp_is_rejected(record):
    record["collected_at"] = "not-a-date"
    with pytest.raises(ValueError, match="timestamp"):
        validate_record(record)


def test_review_cannot_precede_collection(record):
    record["reviewed_at"] = "2026-10-08T11:00:00Z"
    with pytest.raises(ValueError, match="precede"):
        validate_record(record)


def test_duplicate_url_is_rejected(record):
    with pytest.raises(ValueError, match="CSV row 3: Duplicate URL"):
        validate_records([record, dict(record)])


def test_conflicting_labels_are_rejected(record):
    conflicting = {**record, "label": "malicious"}
    with pytest.raises(ValueError, match="CSV row 3: Conflicting labels"):
        validate_records([record, conflicting])


def test_distinct_hostnames_are_not_collapsed(record):
    other = {**record, "url": "http://www.example.com"}
    assert len(validate_records([record, other])) == 2


def test_empty_input_returns_empty_list():
    assert validate_records([]) == []
