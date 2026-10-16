import pandas as pd
import pytest
import tldextract

from sentinelti.ml.weak_label_experiment import (
    _validate_unique_paired_slices,
    build_weak_supplement,
    normalize_weak_source_url,
    source_label_to_target,
)


@pytest.fixture
def suffixes():
    return tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )


def test_scheme_unspecified_url_is_not_claimed_to_be_http(suffixes):
    result = normalize_weak_source_url(
        "Example.com/path?a=1",
        suffixes,
    )

    assert result["source_scheme"] == "unspecified"
    assert result["original_url"] == "Example.com/path?a=1"
    assert result["model_url"] == "http://Example.com/path?a=1"
    assert result["host_type"] == "apex"
    assert result["url_shape"] == "path_bearing"


def test_explicit_source_scheme_is_retained_in_provenance(suffixes):
    result = normalize_weak_source_url("https://www.example.com", suffixes)

    assert result["source_scheme"] == "https"
    assert result["model_url"] == "https://www.example.com/"
    assert result["host_type"] == "subdomain"
    assert result["url_shape"] == "root_only"


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "ftp://example.com/",
        "localhost/path",
        "192.0.2.1/path",
        "https://user:password@example.com/",
        "example.com:8080/path",
        "https://example.com:8443/path",
        "https://example.com:notaport/path",
    ],
)
def test_weak_source_url_rejects_unsupported_inputs(value, suffixes):
    assert normalize_weak_source_url(value, suffixes) is None


@pytest.mark.parametrize(("source_label", "expected"), [("0", 0), ("1", 1)])
def test_weak_source_label_mapping_is_explicit(source_label, expected):
    assert source_label_to_target(source_label) == expected


def test_weak_source_label_mapping_rejects_other_values():
    with pytest.raises(ValueError, match="Unsupported PhishBenign source label"):
        source_label_to_target("benign")


def test_paired_slice_report_rejects_duplicate_scope_slice_rows():
    duplicate_rows = pd.DataFrame(
        [
            {"scope": "test", "slice": "overall"},
            {"scope": "test", "slice": "overall"},
        ]
    )

    with pytest.raises(ValueError, match="duplicate scope/slice"):
        _validate_unique_paired_slices(duplicate_rows)


def test_supplement_drops_conflicting_urls_and_domains_caps_and_overlap(
    tmp_path,
    suffixes,
):
    source_path = tmp_path / "weak.csv"
    pd.DataFrame(
        [
            ("alpha.example.com/a", "0"),
            ("alpha.example.com/b", "0"),
            ("mixed.example.net/", "0"),
            ("mixed.example.net/phish", "1"),
            ("conflict.example.org/", "0"),
            ("conflict.example.org", "1"),
            ("excluded.example.co.uk/path", "1"),
        ],
        columns=["url", "label"],
    ).to_csv(source_path, index=False)

    selected, audit = build_weak_supplement(
        source_path,
        suffixes,
        {"example.co.uk"},
    )

    assert len(selected) == 1
    assert selected.loc[0, "group"] == "example.com"
    assert selected.loc[0, "source_scheme"] == "unspecified"
    assert selected["group"].is_unique
    assert audit["normalized_url_conflict_groups"] == 1
    assert audit["mixed_label_domain_groups"] == 1
    assert audit["protected_domain_overlap_groups"] == 1
    assert audit["selected_pseudo_label_counts"] == {"0": 1}
