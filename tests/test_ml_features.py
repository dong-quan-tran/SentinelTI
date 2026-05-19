from __future__ import annotations

import pytest

from sentinelti.ml.features import extract_features


VALIDISH_URLS = [
    "http://example.com",
    "https://example.com/login",
    "https://sub.domain.example.com/path?q=1",
    "http://127.0.0.1:8080/test",
    "https://xn--pple-43d.com",
    "ftp://example.com/file.txt",
    "http://user:pass@example.com/login",
    "http://example.com/@signin",
    "http://example.com//double//slashes",
    "http://example.com/path-with-dashes_and_underscores",
]

MALFORMED_OR_INCOMPLETE_URLS = [
    "",
    "not a url",
    "example",
    "://broken",
    "http://",
    "https:///missing-host",
    "http://?",
    "/////",
]

SUSPICIOUS_STYLE_URLS = [
    "http://user:pass@example.com",
    "http://example.com/login?redirect=http://evil.com",
    "http://example.com/#@secure",
    "https://xn--pple-43d.com/security-update",
    "http://192.168.0.1/admin",
    "http://example.com:8080/login",
    "http://example.com/paypal/confirm/account/update",
    "http://very-long-subdomain-name-example.example.com/path/to/resource",
]


def _assert_feature_mapping(features):
    assert isinstance(features, dict)
    assert features
    assert all(isinstance(k, str) for k in features.keys())


def _assert_no_containers(features):
    for value in features.values():
        assert not isinstance(value, (dict, list, set, tuple))


@pytest.mark.parametrize("url", VALIDISH_URLS)
def test_extract_features_returns_nonempty_mapping_for_validish_urls(url):
    features = extract_features(url)

    _assert_feature_mapping(features)
    _assert_no_containers(features)


@pytest.mark.parametrize("url", MALFORMED_OR_INCOMPLETE_URLS)
def test_extract_features_handles_malformed_or_incomplete_inputs(url):
    features = extract_features(url)

    _assert_feature_mapping(features)
    _assert_no_containers(features)


def test_extract_features_is_deterministic_for_same_input():
    url = "https://example.com/login?next=http://evil.com&user=admin"

    first = extract_features(url)
    second = extract_features(url)

    assert first == second


@pytest.mark.parametrize(
    "url_a, url_b",
    [
        ("http://example.com", "https://example.com"),
        ("http://example.com", "http://example.com/login"),
        ("http://example.com/login", "http://example.com/login?next=home"),
        ("http://example.com", "http://user:pass@example.com"),
        ("http://apple.com", "http://xn--pple-43d.com"),
    ],
)
def test_extract_features_changes_for_meaningfully_different_urls(url_a, url_b):
    features_a = extract_features(url_a)
    features_b = extract_features(url_b)

    assert features_a != features_b


@pytest.mark.parametrize("url", SUSPICIOUS_STYLE_URLS)
def test_extract_features_supports_suspicious_style_urls(url):
    features = extract_features(url)

    _assert_feature_mapping(features)
    _assert_no_containers(features)


def test_extract_features_key_set_is_stable_across_inputs():
    urls = [
        "http://example.com",
        "https://example.com/login",
        "http://user:pass@example.com",
        "https://xn--pple-43d.com",
        "not a url",
    ]

    key_sets = [set(extract_features(url).keys()) for url in urls]

    first = key_sets[0]
    assert first
    assert all(keys == first for keys in key_sets)


def test_extract_features_includes_at_least_one_string_like_feature():
    features = extract_features("http://example.com")

    assert any(isinstance(v, str) for v in features.values())


def test_extract_features_includes_at_least_one_numeric_or_boolean_feature():
    features = extract_features("http://example.com")

    assert any(isinstance(v, (int, float, bool)) for v in features.values())


@pytest.mark.parametrize("url", VALIDISH_URLS[:3] + MALFORMED_OR_INCOMPLETE_URLS[:3])
def test_extract_features_values_are_scalar_types(url):
    features = extract_features(url)

    for value in features.values():
        assert value is None or isinstance(value, (str, int, float, bool))