"""Validate reviewed supplemental URL records without training or fetching."""

from datetime import datetime
from urllib.parse import urlsplit

FIELDS = (
    "url",
    "label",
    "source",
    "source_reference",
    "collected_at",
    "reviewed_at",
    "reviewer",
    "review_evidence",
)


def _http_url(value: str, field: str) -> None:
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme.lower() in {"http", "https"} and bool(
            parsed.hostname
        )
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field}: invalid HTTP(S) URL") from exc
    if not valid:
        raise ValueError(f"{field}: invalid HTTP(S) URL")


def _timestamp(value: str, field: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field}: invalid ISO timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"{field}: timezone is required")
    return result


def validate_record(record: dict) -> dict[str, str]:
    """Return a validated copy; never rewrite URLs or infer labels."""
    missing = set(FIELDS) - set(record)
    extra = set(record) - set(FIELDS)
    if missing or extra:
        raise ValueError(
            f"Schema mismatch: missing={sorted(missing)}, "
            f"extra={sorted(str(key) for key in extra)}"
        )

    for field in FIELDS:
        value = record[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field}: nonempty string required")
        if value != value.strip():
            raise ValueError(f"{field}: surrounding whitespace is not allowed")

    if record["label"] not in {"benign", "malicious"}:
        raise ValueError("label: expected benign or malicious")

    _http_url(record["url"], "url")
    collected = _timestamp(record["collected_at"], "collected_at")
    reviewed = _timestamp(record["reviewed_at"], "reviewed_at")
    if reviewed < collected:
        raise ValueError("reviewed_at: cannot precede collected_at")

    return {field: record[field] for field in FIELDS}


def validate_records(records) -> list[dict[str, str]]:
    """Reject exact duplicate URLs and exact-URL label conflicts."""
    validated = []
    seen = {}
    for row_number, record in enumerate(records, start=2):
        try:
            row = validate_record(record)
            url = row["url"]
            if url in seen:
                if seen[url] != row["label"]:
                    raise ValueError("Conflicting labels for identical URL")
                raise ValueError("Duplicate URL")
            seen[url] = row["label"]
            validated.append(row)
        except ValueError as exc:
            raise ValueError(f"CSV row {row_number}: {exc}") from exc
    return validated
