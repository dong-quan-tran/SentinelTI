from __future__ import annotations

import math

import pytest

from sentinelti.ml import experimental_features as experimental
from sentinelti.ml.features import extract_features


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://example.com", "http://example.com/"),
        ("https://example.com", "http://example.com/"),
        ("  https://example.com  ", "http://example.com/"),
        ("HTTPS://example.com/a", "http://example.com/a"),
        (
            "https://example.com?x=1#section",
            "http://example.com/?x=1#section",
        ),
        (
            "https://user:pass@example.com:8443/a?x=1#section",
            "http://user:pass@example.com:8443/a?x=1#section",
        ),
        (
            "https://www.example.com/a",
            "http://www.example.com/a",
        ),
        (
            "https://example.com/a%2Fb?next=https://other.com/#section",
            "http://example.com/a%2Fb?next=https://other.com/#section",
        ),
        (
            "https://example.com/a?#",
            "http://example.com/a?#",
        ),
    ],
)
def test_canonicalization_changes_only_outer_scheme_and_empty_path(
    value, expected
):
    assert experimental.canonicalize_outer_scheme(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        "",
        "   ",
        "example.com",
        "//example.com/a",
        "ftp://example.com/a",
        "https:///path",
        "https://",
        "https://example.com:notaport/",
        "https://example.com:99999/",
        "https://[broken/",
    ],
)
def test_canonicalization_rejects_invalid_inputs(value):
    with pytest.raises(ValueError):
        experimental.canonicalize_outer_scheme(value)


@pytest.mark.parametrize(
    "remainder",
    [
        "example.com",
        "example.com/",
        "www.example.com/",
        "login.example.com/a",
        "example.co.uk/a",
        "alice.github.io/a",
        "127.0.0.1:8080/a",
        "[::1]:8080/a",
        "user:pass@example.com:8443/a",
        "example.com/articles/item42?lang=en",
        "example.com/login?next=https://other.com/path",
        "example.com/a#https://other.com/path",
        "example.com/a%2Fb?x=%2F#section",
    ],
)
def test_paired_http_https_features_are_exactly_equal(remainder):
    http_features = experimental.extract_scheme_invariant_features(
        f"http://{remainder}"
    )
    https_features = experimental.extract_scheme_invariant_features(
        f"https://{remainder}"
    )

    assert http_features == https_features
    assert list(http_features) == list(https_features)


def test_explicit_scheme_flags_and_private_metadata_are_excluded():
    features = experimental.extract_scheme_invariant_features(
        "https://example.com/"
    )

    assert "is_http" not in features
    assert "is_https" not in features
    assert "_tld_raw" not in features
    assert not any(name.startswith("_") for name in features)


def test_feature_order_matches_filtered_production_order():
    url = "https://example.com/articles/item42?lang=en"
    canonical = experimental.canonicalize_outer_scheme(url)
    original = extract_features(canonical)

    expected_names = [
        name
        for name in original
        if not name.startswith("_")
        and name not in experimental.EXCLUDED_FEATURE_NAMES
    ]
    actual = experimental.extract_scheme_invariant_features(url)

    assert list(actual) == expected_names
    assert actual == {
        name: float(original[name])
        for name in expected_names
    }


def test_experimental_values_are_finite_floats():
    features = experimental.extract_scheme_invariant_features(
        "https://example.com/login?next=https://other.com/a"
    )

    assert features
    assert all(isinstance(value, float) for value in features.values())
    assert all(math.isfinite(value) for value in features.values())


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "https://www.example.com/a?x=1#section",
        "http://example.com/a",
    ],
)
def test_canonicalization_is_idempotent(url):
    once = experimental.canonicalize_outer_scheme(url)
    twice = experimental.canonicalize_outer_scheme(once)

    assert once == twice


def test_www_is_not_removed_or_added():
    apex = experimental.canonicalize_outer_scheme(
        "https://example.com/"
    )
    www = experimental.canonicalize_outer_scheme(
        "https://www.example.com/"
    )

    assert apex == "http://example.com/"
    assert www == "http://www.example.com/"

    apex_features = experimental.extract_scheme_invariant_features(apex)
    www_features = experimental.extract_scheme_invariant_features(www)

    assert apex_features != www_features
    assert www_features["host_len"] == apex_features["host_len"] + 4
    assert www_features["dot_count_host"] == apex_features["dot_count_host"] + 1


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (
            "https://example.com/",
            "https://example.com/login",
        ),
        (
            "https://example.com/a?next=home",
            "https://example.com/a?next=https://other.com/",
        ),
        (
            "https://example.com/",
            "https://user:pass@example.com/",
        ),
        (
            "https://example.com/a",
            "https://example.com/a#section",
        ),
    ],
)
def test_non_scheme_differences_remain_visible(first, second):
    assert experimental.extract_scheme_invariant_features(
        first
    ) != experimental.extract_scheme_invariant_features(second)


def test_nested_scheme_is_not_canonicalized():
    url = "https://example.com/a?next=https://other.com/#https://third.com/"

    canonical = experimental.canonicalize_outer_scheme(url)

    assert canonical == (
        "http://example.com/a?next=https://other.com/#https://third.com/"
    )

    features = experimental.extract_scheme_invariant_features(url)
    assert features["has_nested_url_in_query"] == 1.0
    assert features["has_nested_url_in_fragment"] == 1.0


def test_production_extractor_remains_scheme_sensitive():
    http_url = "http://example.com/"
    https_url = "https://example.com/"

    before_http = extract_features(http_url)
    before_https = extract_features(https_url)

    experimental.extract_scheme_invariant_features(http_url)
    experimental.extract_scheme_invariant_features(https_url)

    assert extract_features(http_url) == before_http
    assert extract_features(https_url) == before_https
    assert before_http != before_https
    assert before_http["is_http"] == 1.0
    assert before_https["is_https"] == 1.0


def test_version_identifies_the_candidate_representation():
    assert experimental.EXPERIMENTAL_FEATURE_VERSION == (
        "fixed-http-outer-scheme-no-flags-v1"
    )