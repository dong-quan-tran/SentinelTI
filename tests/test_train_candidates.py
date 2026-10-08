import sys

import numpy as np
import pytest

from sentinelti.ml import train_candidates as candidates


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com", "https://example.com/"),
        ("http://example.com", "http://example.com/"),
        ("  https://example.com  ", "https://example.com/"),
        ("https://example.com?x=1", "https://example.com/?x=1"),
        ("https://example.com#section", "https://example.com/#section"),
        (
            "https://example.com?x=1#section",
            "https://example.com/?x=1#section",
        ),
        (
            "https://example.com:8443",
            "https://example.com:8443/",
        ),
        (
            "https://example.com/a?x=1#section",
            "https://example.com/a?x=1#section",
        ),
        ("http://example.com/a", "http://example.com/a"),
    ],
)
def test_normalization_preserves_url_components(value, expected):
    assert candidates.normalize_candidate_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        np.nan,
        "",
        "   ",
        "example.com",
        "//example.com/path",
        "ftp://example.com/file",
        "https:///path",
        "https://",
        "https://example.com:notaport/",
        "https://example.com:99999/",
        "https://[broken/",
    ],
)
def test_normalization_rejects_missing_or_invalid_inputs(value):
    assert candidates.normalize_candidate_url(value) is None


def test_normalization_does_not_add_www_or_upgrade_http():
    assert (
        candidates.normalize_candidate_url("http://example.com")
        == "http://example.com/"
    )
    assert (
        candidates.normalize_candidate_url("https://www.example.com")
        == "https://www.example.com/"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "https://example.com?x=1#section",
        "http://www.example.com:8080/a",
    ],
)
def test_normalization_is_idempotent(url):
    normalized = candidates.normalize_candidate_url(url)
    assert candidates.normalize_candidate_url(normalized) == normalized


def test_metrics_use_class_specific_denominators():
    y_true = np.array([0, 0, 0, 1, 1])
    probabilities = np.array([0.1, 0.8, 0.2, 0.9, 0.4])

    result = candidates.slice_metrics(y_true, probabilities)

    assert result["rows"] == 5
    assert result["benign_rows"] == 3
    assert result["malicious_rows"] == 2
    assert result["confusion_matrix"] == [[2, 1], [1, 1]]
    assert result["false_positive_rate"] == pytest.approx(1 / 3)
    assert result["malicious_recall"] == pytest.approx(1 / 2)


def test_probability_at_threshold_is_malicious():
    threshold = candidates.THRESHOLD
    probabilities = np.array(
        [np.nextafter(threshold, -np.inf), threshold]
    )

    result = candidates.slice_metrics(
        np.array([0, 1]),
        probabilities,
    )

    assert result["confusion_matrix"] == [[1, 0], [0, 1]]


def test_malicious_only_slice_has_undefined_false_positive_rate():
    result = candidates.slice_metrics(
        np.array([1, 1]),
        np.array([0.9, 0.1]),
    )

    assert result["benign_rows"] == 0
    assert result["false_positive_rate"] is None
    assert result["malicious_recall"] == pytest.approx(0.5)
    assert result["confusion_matrix"] == [[0, 0], [1, 1]]


def test_benign_only_slice_has_undefined_malicious_recall():
    result = candidates.slice_metrics(
        np.array([0, 0]),
        np.array([0.9, 0.1]),
    )

    assert result["malicious_rows"] == 0
    assert result["malicious_recall"] is None
    assert result["false_positive_rate"] == pytest.approx(0.5)
    assert result["confusion_matrix"] == [[1, 1], [0, 0]]


def test_apex_regression_fixture_reports_46_false_positives_of_125():
    y_true = np.zeros(125, dtype=int)
    probabilities = np.concatenate(
        [np.full(46, 0.9), np.full(79, 0.1)]
    )

    result = candidates.slice_metrics(y_true, probabilities)

    assert result["benign_rows"] == 125
    assert result["confusion_matrix"] == [[79, 46], [0, 0]]
    assert result["false_positive_rate"] == pytest.approx(0.368)


def test_existing_output_directory_is_rejected_before_reading_data(
    tmp_path, monkeypatch
):
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "existing_candidate.joblib"
    sentinel.write_bytes(b"do-not-overwrite")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "train_candidates",
            "--csv-path",
            str(tmp_path / "missing.csv"),
            "--output-dir",
            str(output),
        ],
    )

    def unexpected_read(*args, **kwargs):
        pytest.fail("Dataset must not be read for an existing output directory")

    monkeypatch.setattr(candidates.pd, "read_csv", unexpected_read)

    with pytest.raises(FileExistsError):
        candidates.main()

    assert sentinel.read_bytes() == b"do-not-overwrite"
    assert {path.name for path in output.iterdir()} == {
        "existing_candidate.joblib"
    }


@pytest.fixture
def suffixes():
    return candidates.tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/", "example.com"),
        ("https://www.example.com/a", "example.com"),
        ("http://login.example.com/b", "example.com"),
        ("https://WWW.EXAMPLE.COM/", "example.com"),
        ("https://shop.example.co.uk/", "example.co.uk"),
        ("http://192.0.2.1/a", "192.0.2.1"),
        ("http://localhost/a", "localhost"),
        ("https://alice.github.io/", "alice.github.io"),
        ("https://login.alice.github.io/", "alice.github.io"),
        ("https://bob.github.io/", "bob.github.io"),
    ],
)
def test_domain_group(url, expected, suffixes):
    assert candidates.domain_group(url, suffixes) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://example.com/", ("http", "apex")),
        ("http://www.example.com/", ("http", "subdomain")),
        ("https://example.com/", ("https", "apex")),
        ("https://login.example.com/", ("https", "subdomain")),
        ("https://example.co.uk/", ("https", "apex")),
        ("https://www.example.co.uk/", ("https", "subdomain")),
        ("https://alice.github.io/", ("https", "apex")),
        (
            "https://login.alice.github.io/",
            ("https", "subdomain"),
        ),
    ],
)
def test_url_subgroup(url, expected, suffixes):
    assert candidates.url_subgroup(url, suffixes) == expected


def test_full_variant_preserves_feature_order():
    names = ["url_length", "is_https", "host_length", "is_http"]

    selected = candidates.selected_feature_indices(names, "full")

    assert selected == [0, 1, 2, 3]
    assert [names[index] for index in selected] == names


def test_no_scheme_removes_only_exact_scheme_features():
    names = [
        "url_length",
        "is_https",
        "http_token_count",
        "host_length",
        "is_http",
    ]

    selected = candidates.selected_feature_indices(names, "no_scheme")

    assert selected == [0, 2, 3]
    assert [names[index] for index in selected] == [
        "url_length",
        "http_token_count",
        "host_length",
    ]


def test_unknown_variant_is_rejected():
    with pytest.raises(ValueError, match="Unknown candidate variant"):
        candidates.selected_feature_indices(["url_length"], "typo")


def test_domain_groups_stay_together_across_split(suffixes):
    urls = [
        f"{scheme}://{prefix}fixture{index}.com/path"
        for index in range(12)
        for scheme, prefix in [
            ("http", ""),
            ("https", "www."),
            ("https", "login."),
        ]
    ]
    groups = np.asarray([
        candidates.domain_group(url, suffixes)
        for url in urls
    ])
    splitter = candidates.GroupShuffleSplit(
        n_splits=1,
        test_size=0.30,
        random_state=42,
    )

    train_index, test_index = next(
        splitter.split(np.zeros((len(urls), 1)), groups=groups)
    )

    assert len(train_index) > 0
    assert len(test_index) > 0
    assert set(groups[train_index]).isdisjoint(set(groups[test_index]))
    assert set(train_index) | set(test_index) == set(range(len(urls)))

    train_rows = set(train_index)
    test_rows = set(test_index)
    for group in set(groups):
        rows = set(np.flatnonzero(groups == group))
        assert rows <= train_rows or rows <= test_rows
