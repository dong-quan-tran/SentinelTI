from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from sentinelti.ml.features import extract_features


EXPERIMENTAL_FEATURE_VERSION = "fixed-http-outer-scheme-no-flags-v1"
EXCLUDED_FEATURE_NAMES = frozenset({"is_http", "is_https"})


def canonicalize_outer_scheme(url: str) -> str:
    """Build a candidate-only representation with a fixed outer scheme."""
    if not isinstance(url, str):
        raise ValueError("Candidate URL must be a string.")

    value = url.strip()

    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Candidate URL must use HTTP or HTTPS.")
        if not parsed.hostname:
            raise ValueError("Candidate URL must contain a hostname.")
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid candidate URL: {value!r}") from exc

    if not parsed.path:
        value = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/",
                parsed.query,
                parsed.fragment,
            )
        )

    _, separator, remainder = value.partition(":")
    if not separator:
        raise ValueError("Candidate URL is missing its scheme separator.")

    return "http:" + remainder


def extract_scheme_invariant_features(url: str) -> dict[str, float]:
    """Extract experimental numeric inputs without outer-scheme variation."""
    canonical_url = canonicalize_outer_scheme(url)
    raw_features = extract_features(canonical_url)

    return {
        name: float(value)
        for name, value in raw_features.items()
        if not name.startswith("_")
        and name not in EXCLUDED_FEATURE_NAMES
    }