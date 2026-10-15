import json
import sys

import numpy as np
import pandas as pd
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
        ("https://example.com:8443", "https://example.com:8443/"),
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
    result = candidates.slice_metrics(
        np.array([0, 0, 0, 1, 1]),
        np.array([0.1, 0.8, 0.2, 0.9, 0.4]),
    )

    assert result["rows"] == 5
    assert result["benign_rows"] == 3
    assert result["malicious_rows"] == 2
    assert result["confusion_matrix"] == [[2, 1], [1, 1]]
    assert result["false_positive_rate"] == pytest.approx(1 / 3)
    assert result["malicious_recall"] == pytest.approx(1 / 2)


def test_probability_at_threshold_is_malicious():
    threshold = candidates.THRESHOLD
    result = candidates.slice_metrics(
        np.array([0, 1]),
        np.array([np.nextafter(threshold, -np.inf), threshold]),
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
    result = candidates.slice_metrics(
        np.zeros(125, dtype=int),
        np.concatenate([np.full(46, 0.9), np.full(79, 0.1)]),
    )

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
        ("https://login.alice.github.io/", ("https", "subdomain")),
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
        candidates.domain_group(url, suffixes) for url in urls
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


@pytest.fixture
def experiment_files(tmp_path, suffixes):
    main = pd.DataFrame(
        [
            ("http://trainalpha.com/base-one", "benign"),
            ("https://trainalpha.com/base-two", "benign"),
            ("http://trainbeta.com/bad", "malicious"),
            ("http://testalpha.com/good", "benign"),
            ("https://testbeta.com/bad", "malicious"),
        ],
        columns=["url", "label"],
    )
    main["normalized_url"] = main["url"].map(
        candidates.normalize_candidate_url
    )
    main["group"] = main["normalized_url"].map(
        lambda url: candidates.domain_group(url, suffixes)
    )
    main["y"] = main["label"].map({"benign": 0, "malicious": 1})

    assignments = pd.DataFrame(
        [
            ("trainalpha.com", "train"),
            ("trainbeta.com", "train"),
            ("testalpha.com", "test"),
            ("testbeta.com", "test"),
        ],
        columns=["group", "partition"],
    )
    manual = pd.DataFrame(
        [("https://manualfixture.com/", "benign")],
        columns=["url", "label"],
    )
    supplement = pd.DataFrame(
        [
            ("http://trainalpha.com/new-one", "benign"),
            ("http://trainalpha.com/new-two", "benign"),
        ],
        columns=["url", "label"],
    )

    paths = {
        "main": tmp_path / "main.csv",
        "split": tmp_path / "split.csv",
        "manual": tmp_path / "manual.csv",
        "supplement": tmp_path / "supplement.csv",
    }
    main[["url", "label"]].to_csv(paths["main"], index=False)
    assignments.to_csv(paths["split"], index=False)
    manual.to_csv(paths["manual"], index=False)
    supplement.to_csv(paths["supplement"], index=False)

    return {
        "main": main,
        "assignments": assignments,
        "supplement": supplement,
        "paths": paths,
        "train_groups": {"trainalpha.com", "trainbeta.com"},
        "test_groups": {"testalpha.com", "testbeta.com"},
    }


def test_saved_split_preserves_recorded_assignments(experiment_files):
    fixture = experiment_files
    train_index, test_index = candidates.load_saved_split(
        fixture["paths"]["split"],
        fixture["main"],
    )

    assert train_index.tolist() == [0, 1, 2]
    assert test_index.tolist() == [3, 4]
    assert set(fixture["main"].iloc[train_index]["group"]) == (
        fixture["train_groups"]
    )
    assert set(fixture["main"].iloc[test_index]["group"]) == (
        fixture["test_groups"]
    )


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing_columns", "must contain group and partition"),
        ("empty", "Split file is empty"),
        ("empty_group", "empty group"),
        ("duplicate", "duplicate group assignments"),
        ("bad_partition", "must be train or test"),
        ("missing_group", "does not match"),
        ("extra_group", "does not match"),
        ("all_train", "nonempty train and test"),
    ],
)
def test_saved_split_rejects_invalid_assignments(
    experiment_files, case, message
):
    fixture = experiment_files
    frame = fixture["assignments"].copy()

    if case == "missing_columns":
        frame = frame.drop(columns=["partition"])
    elif case == "empty":
        frame = frame.iloc[:0]
    elif case == "empty_group":
        frame.loc[0, "group"] = ""
    elif case == "duplicate":
        frame = pd.concat([frame, frame.iloc[[0]]], ignore_index=True)
    elif case == "bad_partition":
        frame.loc[0, "partition"] = "validation"
    elif case == "missing_group":
        frame = frame.iloc[1:]
    elif case == "extra_group":
        frame.loc[len(frame)] = ["extra.com", "train"]
    elif case == "all_train":
        frame["partition"] = "train"

    frame.to_csv(fixture["paths"]["split"], index=False)
    with pytest.raises(ValueError, match=message):
        candidates.load_saved_split(
            fixture["paths"]["split"],
            fixture["main"],
        )


def load_fixture_supplement(fixture, suffixes):
    return candidates.load_supplement(
        fixture["paths"]["supplement"],
        fixture["main"],
        fixture["train_groups"],
        fixture["test_groups"],
        fixture["paths"]["manual"],
        suffixes,
    )


def test_valid_supplement_is_training_only(experiment_files, suffixes):
    fixture = experiment_files
    result = load_fixture_supplement(fixture, suffixes)

    assert len(result) == 2
    assert result["label"].eq("benign").all()
    assert result["y"].eq(0).all()
    assert set(result["group"]).issubset(fixture["train_groups"])
    assert set(result["group"]).isdisjoint(fixture["test_groups"])
    assert set(result["normalized_url"]).isdisjoint(
        fixture["main"]["normalized_url"]
    )


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("empty", "Supplement is empty"),
        ("malicious", "only benign"),
        ("invalid_url", "invalid URLs"),
        ("duplicates", "normalized duplicates"),
        ("main_overlap", "normalized main dataset"),
        ("test_group", "recorded test groups"),
        ("test_subdomain", "recorded test groups"),
        ("new_group", "existing recorded training groups"),
        ("diagnostic", "diagnostic groups"),
        ("manual_url", "manual evaluation URLs"),
        ("manual_group", "manual evaluation groups"),
        ("https", "only HTTP/apex"),
        ("subdomain", "only HTTP/apex"),
        ("domain_cap", "domain cap"),
    ],
)
def test_supplement_rejects_unsafe_inputs(
    experiment_files, suffixes, case, message
):
    fixture = experiment_files
    frame = fixture["supplement"].copy()

    if case == "empty":
        frame = frame.iloc[:0]
    elif case == "malicious":
        frame.loc[0, "label"] = "malicious"
    elif case == "invalid_url":
        frame.loc[0, "url"] = "trainalpha.com/no-scheme"
    elif case == "duplicates":
        frame["url"] = ["http://trainalpha.com", "http://trainalpha.com/"]
    elif case == "main_overlap":
        frame.loc[0, "url"] = fixture["main"].loc[0, "url"]
    elif case == "test_group":
        frame.loc[0, "url"] = "http://testalpha.com/new"
    elif case == "test_subdomain":
        frame.loc[0, "url"] = "http://login.testalpha.com/new"
    elif case == "new_group":
        frame.loc[0, "url"] = "http://unassignedfixture.com/new"
    elif case == "diagnostic":
        fixture["train_groups"] = fixture["train_groups"] | {"example.com"}
        frame.loc[0, "url"] = "http://example.com/new"
    elif case == "manual_url":
        pd.DataFrame({
            "url": ["http://trainalpha.com/new-one"]
        }).to_csv(fixture["paths"]["manual"], index=False)
    elif case == "manual_group":
        pd.DataFrame({
            "url": ["https://login.trainalpha.com/evaluation"]
        }).to_csv(fixture["paths"]["manual"], index=False)
    elif case == "https":
        frame.loc[0, "url"] = "https://trainalpha.com/new-one"
    elif case == "subdomain":
        frame.loc[0, "url"] = "http://www.trainalpha.com/new-one"
    elif case == "domain_cap":
        frame = pd.DataFrame({
            "url": [
                f"http://trainalpha.com/new-{index}"
                for index in range(candidates.SUPPLEMENTAL_DOMAIN_CAP + 1)
            ],
            "label": "benign",
        })

    frame.to_csv(fixture["paths"]["supplement"], index=False)
    with pytest.raises(ValueError, match=message):
        load_fixture_supplement(fixture, suffixes)


def test_supplement_requires_saved_split(tmp_path, monkeypatch):
    output = tmp_path / "output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "train_candidates",
            "--output-dir",
            str(output),
            "--supplemental-csv",
            str(tmp_path / "supplement.csv"),
        ],
    )

    with pytest.raises(SystemExit) as error:
        candidates.main()

    assert error.value.code == 2
    assert not output.exists()


def test_partition_hash_is_order_independent_and_label_sensitive(
    experiment_files,
):
    frame = experiment_files["main"]
    original = candidates.partition_sha256(frame)

    assert candidates.partition_sha256(
        frame.iloc[::-1].reset_index(drop=True)
    ) == original

    changed = frame.copy()
    changed.loc[0, "label"] = "malicious"
    assert candidates.partition_sha256(changed) != original


def test_file_hash_changes_with_content(tmp_path):
    path = tmp_path / "fixture.txt"
    path.write_text("first", encoding="utf-8")
    first = candidates.file_sha256(path)

    assert len(first) == 64
    assert candidates.file_sha256(path) == first

    path.write_text("second", encoding="utf-8")
    assert candidates.file_sha256(path) != first


def test_fixed_split_comparison_preserves_test_and_class_weight(
    experiment_files, tmp_path, monkeypatch
):
    fixture = experiment_files
    models = []

    def fake_features(url):
        return {
            "url_length": float(len(url)),
            "is_http": float(url.startswith("http://")),
            "is_https": float(url.startswith("https://")),
            "bad_marker": float("/bad" in url),
        }

    class FakeClassifier:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.prediction_inputs = []
            models.append(self)

        def fit(self, X, y):
            self.fit_X = np.array(X, copy=True)
            self.fit_y = np.array(y, copy=True)
            return self

        def predict_proba(self, X):
            array = np.asarray(X)
            self.prediction_inputs.append(array.copy())
            probabilities = np.where(array[:, -1] > 0, 0.9, 0.1)
            return np.column_stack([1 - probabilities, probabilities])

    def fake_dump(artifact, path):
        path.write_bytes(b"fake-candidate-artifact")

    monkeypatch.setattr(candidates, "extract_features", fake_features)
    monkeypatch.setattr(candidates, "XGBClassifier", FakeClassifier)
    monkeypatch.setattr(candidates.joblib, "dump", fake_dump)

    def run(output, supplemental=False):
        argv = [
            "train_candidates",
            "--csv-path",
            str(fixture["paths"]["main"]),
            "--output-dir",
            str(output),
            "--split-groups",
            str(fixture["paths"]["split"]),
            "--manual-eval-path",
            str(fixture["paths"]["manual"]),
        ]
        if supplemental:
            argv.extend([
                "--supplemental-csv",
                str(fixture["paths"]["supplement"]),
            ])
        monkeypatch.setattr(sys, "argv", argv)
        candidates.main()

    baseline_output = tmp_path / "baseline"
    supplemented_output = tmp_path / "supplemented"
    run(baseline_output)
    run(supplemented_output, supplemental=True)

    assert len(models) == 4

    expected_files = {
        "split_groups.csv",
        "summary.csv",
        "full_diagnostics.csv",
        "no_scheme_diagnostics.csv",
        "full_metrics.json",
        "no_scheme_metrics.json",
        "full_candidate.joblib",
        "no_scheme_candidate.joblib",
    }
    for output in (baseline_output, supplemented_output):
        assert {path.name for path in output.iterdir()} == expected_files

    for index, variant in enumerate(("full", "no_scheme")):
        baseline_model = models[index]
        supplemented_model = models[index + 2]

        assert baseline_model.kwargs["scale_pos_weight"] == pytest.approx(2.0)
        assert supplemented_model.kwargs["scale_pos_weight"] == pytest.approx(
            2.0
        )
        assert baseline_model.kwargs == supplemented_model.kwargs

        assert baseline_model.fit_y.tolist() == [0, 0, 1]
        assert supplemented_model.fit_y.tolist() == [0, 0, 1, 0, 0]
        np.testing.assert_array_equal(
            baseline_model.fit_X,
            supplemented_model.fit_X[:3],
        )
        np.testing.assert_array_equal(
            baseline_model.prediction_inputs[0],
            supplemented_model.prediction_inputs[0],
        )

        baseline_report = json.loads(
            (baseline_output / f"{variant}_metrics.json").read_text(
                encoding="utf-8"
            )
        )
        supplemented_report = json.loads(
            (supplemented_output / f"{variant}_metrics.json").read_text(
                encoding="utf-8"
            )
        )

        assert baseline_report["split_method"] == "saved-domain-groups"
        assert supplemented_report["split_method"] == "saved-domain-groups"
        assert baseline_report["split_seed"] is None
        assert supplemented_report["split_seed"] is None

        assert baseline_report["train_rows"] == 3
        assert supplemented_report["train_rows"] == 5
        assert baseline_report["test_rows"] == 2
        assert supplemented_report["test_rows"] == 2
        assert baseline_report["supplemental_rows"] == 0
        assert supplemented_report["supplemental_rows"] == 2
        assert supplemented_report["supplemental_groups"] == 1
        assert supplemented_report["group_overlap"] == 0

        for key in (
            "csv_sha256",
            "split_groups_sha256",
            "baseline_train_partition_sha256",
            "test_partition_sha256",
            "scale_pos_weight",
            "feature_names",
        ):
            assert baseline_report[key] == supplemented_report[key]

        assert supplemented_report["supplemental_csv_sha256"] == (
            candidates.file_sha256(fixture["paths"]["supplement"])
        )
        assert supplemented_report["manual_eval_sha256"] == (
            candidates.file_sha256(fixture["paths"]["manual"])
        )
        assert baseline_report["overall"] == supplemented_report["overall"]
        assert baseline_report["slices"] == supplemented_report["slices"]

        if variant == "full":
            assert baseline_report["feature_names"] == [
                "url_length",
                "is_http",
                "is_https",
                "bad_marker",
            ]
        else:
            assert baseline_report["feature_names"] == [
                "url_length",
                "bad_marker",
            ]

        for output in (baseline_output, supplemented_output):
            diagnostics = pd.read_csv(
                output / f"{variant}_diagnostics.csv"
            )
            assert len(diagnostics) == len(candidates.DIAGNOSTIC_DOMAINS) * 4
            assert diagnostics["url"].is_unique
            assert diagnostics["url"].str.startswith("http://").sum() == (
                len(candidates.DIAGNOSTIC_DOMAINS) * 2
            )
            assert diagnostics["url"].str.startswith("https://").sum() == (
                len(candidates.DIAGNOSTIC_DOMAINS) * 2
            )

    baseline_split = pd.read_csv(baseline_output / "split_groups.csv")
    supplemented_split = pd.read_csv(supplemented_output / "split_groups.csv")
    pd.testing.assert_frame_equal(baseline_split, supplemented_split)



def test_scheme_invariant_feature_selection_excludes_flags():
    names = ["url_len", "is_http", "is_https", "host_len"]
    assert candidates.selected_feature_indices(
        names, "scheme_invariant"
    ) == [0, 3]


@pytest.mark.parametrize(
    "configuration",
    [
        ["--variants", "scheme_invariant"],
        [
            "--variants", "scheme_invariant",
            "--split-groups", "unused-split.csv",
            "--supplemental-csv", "unused-supplement.csv",
        ],
        [
            "--variants", "scheme_invariant", "scheme_invariant",
            "--split-groups", "unused-split.csv",
        ],
    ],
)
def test_scheme_invariant_cli_rejects_invalid_configuration(
    tmp_path, monkeypatch, configuration
):
    output = tmp_path / "invalid-experiment"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "train_candidates",
            "--output-dir", str(output),
            *configuration,
        ],
    )
    with pytest.raises(SystemExit) as error:
        candidates.main()
    assert error.value.code == 2
    assert not output.exists()


def test_scheme_invariant_training_uses_candidate_adapter(
    experiment_files, tmp_path, monkeypatch
):
    fixture = experiment_files
    output = tmp_path / "scheme-invariant"
    models = []
    artifacts = []

    def unexpected_production_extraction(url):
        pytest.fail("Invariant-only run must not use production extraction.")

    def fake_candidate_features(url):
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        return {
            "path_len": float(len(parsed.path)),
            "bad_marker": float("/bad" in parsed.path),
        }

    class FakeClassifier:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.prediction_inputs = []
            models.append(self)

        def fit(self, X, y):
            self.fit_X = np.array(X, copy=True)
            self.fit_y = np.array(y, copy=True)
            return self

        def predict_proba(self, X):
            array = np.asarray(X)
            self.prediction_inputs.append(array.copy())
            probabilities = np.where(array[:, -1] > 0, 0.9, 0.1)
            return np.column_stack([1 - probabilities, probabilities])

    def fake_dump(artifact, path):
        artifacts.append(artifact)
        path.write_bytes(b"fake-scheme-invariant-artifact")

    monkeypatch.setattr(
        candidates, "extract_features", unexpected_production_extraction
    )
    monkeypatch.setattr(
        candidates,
        "extract_scheme_invariant_features",
        fake_candidate_features,
    )
    monkeypatch.setattr(candidates, "XGBClassifier", FakeClassifier)
    monkeypatch.setattr(candidates.joblib, "dump", fake_dump)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "train_candidates",
            "--csv-path", str(fixture["paths"]["main"]),
            "--output-dir", str(output),
            "--split-groups", str(fixture["paths"]["split"]),
            "--variants", "scheme_invariant",
        ],
    )

    candidates.main()

    assert len(models) == 1
    model = models[0]
    assert model.fit_y.tolist() == [0, 0, 1]
    assert model.kwargs["scale_pos_weight"] == pytest.approx(2.0)

    expected_train = np.asarray([
        list(fake_candidate_features(url).values())
        for url in fixture["main"].iloc[:3]["normalized_url"]
    ])
    expected_test = np.asarray([
        list(fake_candidate_features(url).values())
        for url in fixture["main"].iloc[3:]["normalized_url"]
    ])
    np.testing.assert_array_equal(model.fit_X, expected_train)
    np.testing.assert_array_equal(
        model.prediction_inputs[0], expected_test
    )

    report = json.loads(
        (output / "scheme_invariant_metrics.json").read_text(encoding="utf-8")
    )
    assert report["variant"] == "scheme_invariant"
    assert report["feature_names"] == ["path_len", "bad_marker"]
    assert report["feature_representation"] == (
        candidates.EXPERIMENTAL_FEATURE_VERSION
    )
    assert report["supplemental_rows"] == 0
    assert report["train_rows"] == 3
    assert report["test_rows"] == 2
    assert report["test_partition_sha256"] == candidates.partition_sha256(
        fixture["main"].iloc[3:]
    )
    assert report["overall"]["confusion_matrix"] == [[1, 0], [0, 1]]

    assert len(artifacts) == 1
    assert artifacts[0]["candidate_only"] is True
    assert artifacts[0]["feature_representation"] == (
        candidates.EXPERIMENTAL_FEATURE_VERSION
    )

    diagnostics = pd.read_csv(output / "scheme_invariant_diagnostics.csv")
    assert len(diagnostics) == len(candidates.DIAGNOSTIC_DOMAINS) * 4
    paired = diagnostics.assign(
        remainder=diagnostics["url"].str.split("://", n=1).str[1]
    )
    assert paired.groupby("remainder")["prob_malicious"].nunique().eq(1).all()

    assert not (output / "full_candidate.joblib").exists()
    assert not (output / "no_scheme_candidate.joblib").exists()

    saved_split = pd.read_csv(output / "split_groups.csv")
    pd.testing.assert_frame_equal(
        saved_split.sort_values("group").reset_index(drop=True),
        fixture["assignments"].sort_values("group").reset_index(drop=True),
    )
