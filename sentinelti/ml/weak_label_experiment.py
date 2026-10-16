from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.metrics import confusion_matrix, roc_auc_score, average_precision_score
from xgboost import XGBClassifier

from sentinelti.ml.experimental_features import (
    EXPERIMENTAL_FEATURE_VERSION,
    extract_scheme_invariant_features,
)
from sentinelti.ml.train_candidates import (
    DIAGNOSTIC_DOMAINS,
    THRESHOLD,
    domain_group,
    file_sha256,
    load_saved_split,
    normalize_candidate_url,
    partition_sha256,
    read_string_csv,
)


SOURCE_NAME = "Mitake PhishingURLsANDBenignURLs"
SOURCE_URL = "https://huggingface.co/datasets/Mitake/PhishingURLsANDBenignURLs"
SOURCE_REVISION = "1f939bad78f95b470c5d058dfb23c7fce35275b7"
SOURCE_SHA256 = "a1e3fc9df5b9068b2f28237af3fe605801165daf7d1c4cb41f10c372fb57321c"
LABEL_POLICY = (
    "Weak labels only: source label 0 is treated as pseudo-benign and source "
    "label 1 as pseudo-phishing. The source card does not document label "
    "origins, annotation method, or per-row observation dates. Neither class "
    "is treated as a current safety verdict."
)
BOOTSTRAP_REPLICATES = 2000
BOOTSTRAP_SEED = 42
PROTECTED_EXTERNAL_EVALUATIONS = (
    (
        Path("docs/model_metrics/hannousse_external_eval_v1/urls.csv"),
        Path("docs/model_metrics/hannousse_external_eval_v1/manifest.json"),
        "evaluation_csv_sha256",
        "historical_hannousse",
    ),
    (
        Path("docs/model_metrics/external_http_path_challenge_v1/urls.csv"),
        Path("docs/model_metrics/external_http_path_challenge_v1/manifest.json"),
        "challenge_csv_sha256",
        "historical_http_apex_path_challenge",
    ),
)


def normalize_weak_source_url(value: object, suffixes) -> dict | None:
    if not isinstance(value, str):
        return None

    original = value.strip()
    if not original:
        return None

    try:
        parsed = urlsplit(original)
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"}:
            model_url = normalize_candidate_url(original)
            if model_url is None:
                return None
            parsed = urlsplit(model_url)
            source_scheme = scheme
            identity_scheme = scheme
        else:
            if scheme:
                return None
            reference = original if original.startswith("//") else f"//{original}"
            parsed = urlsplit(reference)
            if not parsed.hostname:
                return None
            model_url = normalize_candidate_url(f"http:{reference}")
            if model_url is None:
                return None
            source_scheme = "unspecified"
            identity_scheme = "unspecified"

        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port
        if source_scheme == "unspecified" and port is not None:
            return None
        if source_scheme == "http" and port not in (None, 80):
            return None
        if source_scheme == "https" and port not in (None, 443):
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return None

        extracted = suffixes(host)
        if not extracted.suffix:
            return None

        identity = urlunsplit(
            (
                identity_scheme,
                parsed.netloc.lower(),
                parsed.path or "/",
                parsed.query,
                parsed.fragment,
            )
        )
        shape = (
            "path_bearing"
            if parsed.path not in ("", "/")
            else (
                "root_with_query_or_fragment"
                if parsed.query or parsed.fragment
                else "root_only"
            )
        )
        return {
            "original_url": original,
            "identity": identity,
            "model_url": model_url,
            "source_scheme": source_scheme,
            "host_type": "subdomain" if extracted.subdomain else "apex",
            "url_shape": shape,
            "group": domain_group(model_url, suffixes),
        }
    except ValueError:
        return None


def source_label_to_target(value: object) -> int:
    if value == "0":
        return 0
    if value == "1":
        return 1
    raise ValueError(f"Unsupported PhishBenign source label: {value!r}")


def build_weak_supplement(path, suffixes, excluded_groups: set[str]):
    source = read_string_csv(path, usecols=["url", "label"])
    if source.empty:
        raise ValueError("Weak-label source is empty.")
    if not source["label"].isin(["0", "1"]).all():
        raise ValueError("Weak-label source has values outside the approved 0/1 mapping.")

    labels = source["label"].map(source_label_to_target)
    records = source["url"].map(
        lambda value: normalize_weak_source_url(value, suffixes)
    )
    valid = records.notna()
    invalid_rows = int((~valid).sum())
    frame = pd.DataFrame(records[valid].tolist())
    frame["source_label"] = source.loc[valid, "label"].to_numpy()
    frame["y"] = labels.loc[valid].to_numpy(dtype=int)

    conflicting_identities = set(
        frame.groupby("identity")["y"].nunique().loc[lambda values: values > 1].index
    )
    conflict_identity_rows = int(frame["identity"].isin(conflicting_identities).sum())
    frame = frame[~frame["identity"].isin(conflicting_identities)].copy()

    before_deduplication = len(frame)
    frame = frame.sort_values(["identity", "original_url"], kind="stable")
    frame = frame.drop_duplicates("identity", keep="first")
    same_label_duplicate_rows = before_deduplication - len(frame)

    conflicting_groups = set(
        frame.groupby("group")["y"].nunique().loc[lambda values: values > 1].index
    )
    conflicting_group_rows = int(frame["group"].isin(conflicting_groups).sum())
    frame = frame[~frame["group"].isin(conflicting_groups)].copy()

    source_group_set = set(frame["group"])
    protected_overlap_groups = source_group_set.intersection(excluded_groups)
    protected_overlap_rows = int(frame["group"].isin(protected_overlap_groups).sum())
    frame = frame[~frame["group"].isin(excluded_groups)].copy()

    frame["selection_key"] = frame["identity"].map(
        lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    )
    frame = frame.sort_values(["group", "selection_key"], kind="stable")
    selected = frame.drop_duplicates("group", keep="first").reset_index(drop=True)

    if selected.empty:
        raise ValueError("No eligible weak-label domains remain after exclusions.")
    if selected["group"].duplicated().any():
        raise ValueError("Weak-label selection exceeded one URL per domain.")
    if not set(selected["group"]).isdisjoint(excluded_groups):
        raise ValueError("Weak-label supplement overlaps protected domains.")

    audit = {
        "source_rows": int(len(source)),
        "invalid_or_unsupported_url_rows": invalid_rows,
        "source_label_counts": {
            str(label): int(count)
            for label, count in source["label"].value_counts().sort_index().items()
        },
        "normalized_url_conflict_groups": len(conflicting_identities),
        "rows_in_normalized_url_conflicts": conflict_identity_rows,
        "same_label_normalized_duplicate_rows_removed": same_label_duplicate_rows,
        "mixed_label_domain_groups": len(conflicting_groups),
        "rows_in_mixed_label_domain_groups": conflicting_group_rows,
        "protected_domain_overlap_groups": len(protected_overlap_groups),
        "rows_in_protected_domain_overlaps": protected_overlap_rows,
        "eligible_rows_before_one_per_domain_cap": int(len(frame)),
        "eligible_domain_groups": int(frame["group"].nunique()),
        "selected_rows": int(len(selected)),
        "selected_domain_groups": int(selected["group"].nunique()),
        "selected_pseudo_label_counts": {
            str(label): int(count)
            for label, count in selected["y"].value_counts().sort_index().items()
        },
        "selected_format_coverage": [
            {
                "source_scheme": str(row.source_scheme),
                "host_type": str(row.host_type),
                "url_shape": str(row.url_shape),
                "y": int(row.y),
                "rows": int(row.rows),
            }
            for row in (
                selected.groupby(
                    ["source_scheme", "host_type", "url_shape", "y"],
                    dropna=False,
                )
                .size()
                .rename("rows")
                .reset_index()
                .itertuples(index=False)
            )
        ],
    }
    return selected, audit


def load_main_dataset(csv_path, split_path):
    main = read_string_csv(csv_path, usecols=["url", "label"])
    main = main[main["label"].isin(["benign", "malicious"])].copy()
    original_rows = len(main)
    main["normalized_url"] = main["url"].map(normalize_candidate_url)
    main = main.dropna(subset=["normalized_url"]).copy()
    invalid_rows = original_rows - len(main)

    conflicts = main.groupby("normalized_url")["label"].nunique()
    if conflicts.gt(1).any():
        raise ValueError("Main dataset has conflicting labels after normalization.")
    main = main.drop_duplicates("normalized_url").copy()
    main["group"] = main["normalized_url"].map(
        lambda value: domain_group(value, _PUBLIC_SUFFIXES)
    )
    diagnostic_rows = int(main["group"].isin(DIAGNOSTIC_DOMAINS).sum())
    main = main[~main["group"].isin(DIAGNOSTIC_DOMAINS)].reset_index(drop=True)
    main["y"] = main["label"].map({"benign": 0, "malicious": 1})
    if main.empty:
        raise ValueError("No valid baseline rows remain.")

    train_index, test_index = load_saved_split(split_path, main)
    train_groups = set(main.iloc[train_index]["group"])
    test_groups = set(main.iloc[test_index]["group"])
    if not train_groups.isdisjoint(test_groups):
        raise ValueError("Saved baseline split has overlapping groups.")

    return main, train_index, test_index, {
        "rows_after_normalization": int(len(main)),
        "invalid_rows": invalid_rows,
        "diagnostic_domain_rows_excluded": diagnostic_rows,
        "baseline_train_rows": int(len(train_index)),
        "baseline_test_rows": int(len(test_index)),
        "baseline_train_groups": len(train_groups),
        "baseline_test_groups": len(test_groups),
        "baseline_train_partition_sha256": partition_sha256(
            main.iloc[train_index]
        ),
        "test_partition_sha256": partition_sha256(main.iloc[test_index]),
        "train_groups": train_groups,
        "test_groups": test_groups,
    }


def _load_protected_inputs(root: Path, split_groups: pd.DataFrame, suffixes):
    protected_groups = set(split_groups["group"]) | DIAGNOSTIC_DOMAINS
    records = []
    manual_path = root / "data/manual_eval_urls.csv"
    manual = read_string_csv(manual_path, usecols=["url"])
    manual_urls = [normalize_candidate_url(value) for value in manual["url"]]
    if any(url is None for url in manual_urls):
        raise ValueError("Manual evaluation contains an invalid URL.")
    manual_groups = {domain_group(url, suffixes) for url in manual_urls}
    protected_groups.update(manual_groups)
    records.append({
        "name": "manual_fixtures",
        "csv_path": manual_path.relative_to(root).as_posix(),
        "csv_sha256": file_sha256(manual_path),
        "domain_groups": len(manual_groups),
    })

    external = {}
    for csv_relative, manifest_relative, hash_key, name in PROTECTED_EXTERNAL_EVALUATIONS:
        csv_path = root / csv_relative
        manifest_path = root / manifest_relative
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        csv_hash = file_sha256(csv_path)
        if manifest.get(hash_key) != csv_hash:
            raise ValueError(f"Protected evaluation hash mismatch: {csv_path}")
        data = read_string_csv(csv_path)
        if data.empty or "url" not in data.columns:
            raise ValueError(f"Protected evaluation is empty or invalid: {csv_path}")
        normalized = data["url"].map(normalize_candidate_url)
        if normalized.isna().any():
            raise ValueError(f"Protected evaluation has invalid URLs: {csv_path}")
        groups = normalized.map(lambda url: domain_group(url, suffixes))
        if "group" in data.columns and not groups.reset_index(drop=True).equals(
            data["group"].reset_index(drop=True)
        ):
            raise ValueError(f"Stored domain groups differ: {csv_path}")
        group_set = set(groups)
        protected_groups.update(group_set)
        external[name] = (data, normalized.tolist(), groups.tolist(), manifest)
        records.append({
            "name": name,
            "csv_path": csv_path.relative_to(root).as_posix(),
            "csv_sha256": csv_hash,
            "manifest_path": manifest_path.relative_to(root).as_posix(),
            "manifest_sha256": file_sha256(manifest_path),
            "domain_groups": len(group_set),
        })

    return protected_groups, external, records


def _feature_matrix(urls, expected_names=None, description="URLs"):
    if len(urls) == 0:
        raise ValueError(f"No {description} to featurize.")
    first = extract_scheme_invariant_features(urls[0])
    names = list(first)
    if expected_names is not None and names != expected_names:
        raise ValueError("Scheme-invariant feature order differs from baseline artifact.")
    matrix = np.empty((len(urls), len(names)), dtype=np.float64)
    matrix[0] = [first[name] for name in names]
    for index, url in enumerate(urls[1:], start=1):
        row = extract_scheme_invariant_features(url)
        if list(row) != names:
            raise ValueError("Scheme-invariant feature order changed.")
        matrix[index] = [row[name] for name in names]
        if index % 50000 == 0:
            print(f"  {description}: {index:,}/{len(urls):,}", flush=True)
    if not np.isfinite(matrix).all():
        raise ValueError("Feature matrix contains nonfinite values.")
    return matrix, names


def _model_probabilities(model, matrix):
    if not np.array_equal(np.asarray(model.classes_), np.array([0, 1])):
        raise ValueError("Unexpected model class ordering.")
    if int(model.n_features_in_) != matrix.shape[1]:
        raise ValueError("Model feature count differs from the feature matrix.")
    probabilities = np.asarray(model.predict_proba(matrix), dtype=float)[:, 1]
    if not np.isfinite(probabilities).all():
        raise ValueError("Model returned nonfinite probabilities.")
    if ((probabilities < 0) | (probabilities > 1)).any():
        raise ValueError("Model returned out-of-range probabilities.")
    return probabilities


def _slice_masks(frame):
    masks = {"overall": np.ones(len(frame), dtype=bool)}
    for column, values in (
        ("scheme", ("http", "https")),
        ("host_type", ("apex", "subdomain")),
        ("url_shape", ("root_only", "path_bearing", "root_with_query_or_fragment")),
    ):
        for value in values:
            masks[f"{column}={value}"] = frame[column].eq(value).to_numpy()
    for scheme in ("http", "https"):
        for host_type in ("apex", "subdomain"):
            for shape in (
                "root_only",
                "path_bearing",
                "root_with_query_or_fragment",
            ):
                key = f"scheme={scheme}|host_type={host_type}|url_shape={shape}"
                masks[key] = (
                    frame["scheme"].eq(scheme)
                    & frame["host_type"].eq(host_type)
                    & frame["url_shape"].eq(shape)
                ).to_numpy()
    return {name: mask for name, mask in masks.items() if mask.any()}


def _validate_unique_paired_slices(frame):
    if frame.duplicated(["scope", "slice"]).any():
        raise ValueError("Paired slice report contains duplicate scope/slice rows.")


def _metrics(y_true, probabilities, groups):
    predicted = probabilities >= THRESHOLD
    tn, fp, fn, tp = confusion_matrix(
        y_true, predicted, labels=[0, 1]
    ).ravel()
    group_frame = pd.DataFrame({
        "group": groups,
        "y": y_true,
        "predicted": predicted.astype(int),
    })
    benign_domains = group_frame[group_frame["y"].eq(0)].groupby("group")
    phishing_domains = group_frame[group_frame["y"].eq(1)].groupby("group")
    macro_fpr = (
        float(benign_domains["predicted"].mean().mean())
        if len(benign_domains) else None
    )
    macro_recall = (
        float(phishing_domains["predicted"].mean().mean())
        if len(phishing_domains) else None
    )
    return {
        "rows": int(len(y_true)),
        "domain_groups": int(pd.Series(groups).nunique()),
        "benign_rows": int(tn + fp),
        "phishing_rows": int(fn + tp),
        "accuracy": float((tn + tp) / len(y_true)) if len(y_true) else None,
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "phishing_recall": float(tp / (tp + fn)) if tp + fn else None,
        "domain_macro_false_positive_rate": macro_fpr,
        "domain_macro_phishing_recall": macro_recall,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def _paired_counts(y_true, base_probabilities, weak_probabilities):
    base_flag = base_probabilities >= THRESHOLD
    weak_flag = weak_probabilities >= THRESHOLD
    benign = y_true == 0
    phishing = y_true == 1
    return {
        "benign_false_positives_reduced": int((benign & base_flag & ~weak_flag).sum()),
        "benign_false_positives_added": int((benign & ~base_flag & weak_flag).sum()),
        "phishing_true_positives_lost": int((phishing & base_flag & ~weak_flag).sum()),
        "phishing_true_positives_gained": int((phishing & ~base_flag & weak_flag).sum()),
    }


def _paired_bootstrap(y_true, base_probabilities, weak_probabilities, groups):
    base_flag = (base_probabilities >= THRESHOLD).astype(int)
    weak_flag = (weak_probabilities >= THRESHOLD).astype(int)
    group_codes, group_values = pd.factorize(groups, sort=True)
    size = len(group_values)
    if size == 0:
        raise ValueError("Cannot bootstrap an empty evaluation.")

    benign = y_true == 0
    phishing = y_true == 1
    benign_count = np.bincount(group_codes, weights=benign.astype(int), minlength=size)
    base_fp = np.bincount(
        group_codes, weights=(benign & (base_flag == 1)).astype(int), minlength=size
    )
    weak_fp = np.bincount(
        group_codes, weights=(benign & (weak_flag == 1)).astype(int), minlength=size
    )
    phishing_count = np.bincount(
        group_codes, weights=phishing.astype(int), minlength=size
    )
    base_tp = np.bincount(
        group_codes, weights=(phishing & (base_flag == 1)).astype(int), minlength=size
    )
    weak_tp = np.bincount(
        group_codes, weights=(phishing & (weak_flag == 1)).astype(int), minlength=size
    )

    rng = np.random.default_rng(BOOTSTRAP_SEED)
    weights = rng.multinomial(
        size, np.full(size, 1 / size), size=BOOTSTRAP_REPLICATES
    ).astype(np.int32)

    def ratio(numerator, denominator):
        return np.divide(
            numerator,
            denominator,
            out=np.full_like(numerator, np.nan, dtype=float),
            where=denominator > 0,
        )

    bootstrap = {}
    for metric, denom, base_num, weak_num in (
        ("false_positive_rate", benign_count, base_fp, weak_fp),
        ("phishing_recall", phishing_count, base_tp, weak_tp),
    ):
        base_row = ratio(weights @ base_num, weights @ denom)
        weak_row = ratio(weights @ weak_num, weights @ denom)
        valid_groups = (denom > 0).astype(int)
        base_rates = ratio(base_num, denom)
        weak_rates = ratio(weak_num, denom)
        base_macro = ratio(
            weights @ np.nan_to_num(base_rates),
            weights @ valid_groups,
        )
        weak_macro = ratio(
            weights @ np.nan_to_num(weak_rates),
            weights @ valid_groups,
        )
        for suffix, difference in (
            ("row_level", weak_row - base_row),
            ("domain_macro", weak_macro - base_macro),
        ):
            values = difference[np.isfinite(difference)]
            bootstrap[f"{metric}_{suffix}_ci_low"] = (
                float(np.quantile(values, 0.025)) if len(values) else None
            )
            bootstrap[f"{metric}_{suffix}_ci_high"] = (
                float(np.quantile(values, 0.975)) if len(values) else None
            )

    return {
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        **bootstrap,
    }


def evaluate_scope(name, frame, baseline_model, weak_model, feature_names):
    matrix, _ = _feature_matrix(
        frame["model_url"].tolist(),
        expected_names=feature_names,
        description=f"{name} evaluation URLs",
    )
    base_probabilities = _model_probabilities(baseline_model, matrix)
    weak_probabilities = _model_probabilities(weak_model, matrix)
    y_true = frame["y"].to_numpy(dtype=int)
    groups = frame["group"].to_numpy()
    records = []
    paired_records = []

    for slice_name, mask in _slice_masks(frame).items():
        for candidate, probabilities in (
            ("baseline_scheme_invariant", base_probabilities),
            ("phishbenign_weak_supplement", weak_probabilities),
        ):
            record = {
                "scope": name,
                "slice": slice_name,
                "candidate": candidate,
                "threshold": THRESHOLD,
                **_metrics(y_true[mask], probabilities[mask], groups[mask]),
            }
            if mask.sum() >= 2:
                selected_probabilities = probabilities[mask]
                if np.unique(y_true[mask]).size == 2:
                    record["roc_auc"] = float(
                        roc_auc_score(y_true[mask], selected_probabilities)
                    )
                    record["average_precision"] = float(
                        average_precision_score(y_true[mask], selected_probabilities)
                    )
                else:
                    record["roc_auc"] = None
                    record["average_precision"] = None
            records.append(record)

        selected_y = y_true[mask]
        selected_groups = groups[mask]
        selected_base = base_probabilities[mask]
        selected_weak = weak_probabilities[mask]
        baseline_metrics = _metrics(selected_y, selected_base, selected_groups)
        weak_metrics = _metrics(selected_y, selected_weak, selected_groups)
        paired_records.append({
            "scope": name,
            "slice": slice_name,
            "rows": int(mask.sum()),
            "domain_groups": int(pd.Series(selected_groups).nunique()),
            "threshold": THRESHOLD,
            "baseline_false_positive_rate": baseline_metrics["false_positive_rate"],
            "weak_false_positive_rate": weak_metrics["false_positive_rate"],
            "false_positive_rate_delta": (
                weak_metrics["false_positive_rate"] - baseline_metrics["false_positive_rate"]
                if baseline_metrics["false_positive_rate"] is not None
                and weak_metrics["false_positive_rate"] is not None else None
            ),
            "baseline_phishing_recall": baseline_metrics["phishing_recall"],
            "weak_phishing_recall": weak_metrics["phishing_recall"],
            "phishing_recall_delta": (
                weak_metrics["phishing_recall"] - baseline_metrics["phishing_recall"]
                if baseline_metrics["phishing_recall"] is not None
                and weak_metrics["phishing_recall"] is not None else None
            ),
            "baseline_domain_macro_false_positive_rate": (
                baseline_metrics["domain_macro_false_positive_rate"]
            ),
            "weak_domain_macro_false_positive_rate": (
                weak_metrics["domain_macro_false_positive_rate"]
            ),
            "domain_macro_false_positive_rate_delta": (
                weak_metrics["domain_macro_false_positive_rate"]
                - baseline_metrics["domain_macro_false_positive_rate"]
                if baseline_metrics["domain_macro_false_positive_rate"] is not None
                and weak_metrics["domain_macro_false_positive_rate"] is not None
                else None
            ),
            "baseline_domain_macro_phishing_recall": (
                baseline_metrics["domain_macro_phishing_recall"]
            ),
            "weak_domain_macro_phishing_recall": (
                weak_metrics["domain_macro_phishing_recall"]
            ),
            "domain_macro_phishing_recall_delta": (
                weak_metrics["domain_macro_phishing_recall"]
                - baseline_metrics["domain_macro_phishing_recall"]
                if baseline_metrics["domain_macro_phishing_recall"] is not None
                and weak_metrics["domain_macro_phishing_recall"] is not None
                else None
            ),
            **_paired_counts(selected_y, selected_base, selected_weak),
        })

    bootstrap = _paired_bootstrap(
        y_true,
        base_probabilities,
        weak_probabilities,
        groups,
    )
    return records, paired_records, bootstrap


_PUBLIC_SUFFIXES = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def main():
    root = Path.cwd()
    if not (root / "sentinelti/ml/features.py").is_file():
        raise RuntimeError("Run this experiment from the SentinelTI repository root.")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-csv",
        default=r"C:\Users\God\Downloads\PhishBenignDataset.csv",
    )
    parser.add_argument(
        "--output-dir",
        default="docs/model_metrics/phishbenign_weak_label_experiment_v1",
    )
    args = parser.parse_args()

    source_path = Path(args.source_csv)
    if not source_path.is_file():
        raise FileNotFoundError(f"Approved weak-label source not found: {source_path}")
    if file_sha256(source_path) != SOURCE_SHA256:
        raise ValueError("PhishBenign bytes differ from the provenance-reviewed source.")

    main_path = root / "data/urldata.csv"
    split_path = root / "docs/model_metrics/format_shortcut_experiment/split_groups.csv"
    manual_path = root / "data/manual_eval_urls.csv"
    baseline_metrics_path = (
        root / "docs/model_metrics/scheme_invariant_baseline_v1/"
        "scheme_invariant_metrics.json"
    )
    baseline_artifact_path = (
        root / "docs/model_metrics/scheme_invariant_baseline_v1/"
        "scheme_invariant_candidate.joblib"
    )
    output = Path(args.output_dir)
    if not output.is_absolute():
        output = root / output
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite experiment directory: {output}")
    if not baseline_artifact_path.is_file():
        raise FileNotFoundError(
            f"Baseline candidate artifact is required: {baseline_artifact_path}"
        )

    baseline_report = json.loads(baseline_metrics_path.read_text(encoding="utf-8"))
    expected_inputs = {
        main_path: baseline_report["csv_sha256"],
        split_path: baseline_report["split_groups_sha256"],
    }
    for path, expected_hash in expected_inputs.items():
        if file_sha256(path) != expected_hash:
            raise ValueError(f"Baseline input fingerprint mismatch: {path}")
    if file_sha256(manual_path) != "1518c8a1c6a2544caf3d69576e39355fd414a3047334e04c0cc73d2c238fa77c":
        raise ValueError("Manual fixture fingerprint differs from protected record.")

    baseline_artifact = joblib.load(baseline_artifact_path)
    if not isinstance(baseline_artifact, dict) or baseline_artifact.get(
        "candidate_only"
    ) is not True:
        raise ValueError("Baseline artifact is not a candidate-only model.")
    for key, expected in (
        ("variant", "scheme_invariant"),
        ("threshold", THRESHOLD),
        ("preprocessing", baseline_report["preprocessing"]),
        ("feature_representation", EXPERIMENTAL_FEATURE_VERSION),
    ):
        if baseline_artifact.get(key) != expected:
            raise ValueError(f"Baseline candidate metadata mismatch: {key}")
    if (
        baseline_report.get("variant") != "scheme_invariant"
        or baseline_report.get("feature_representation")
        != EXPERIMENTAL_FEATURE_VERSION
        or baseline_report.get("threshold") != THRESHOLD
    ):
        raise ValueError("Baseline report is not the fixed-threshold scheme-invariant run.")
    feature_names = baseline_artifact["feature_names"]

    main, train_index, test_index, split_audit = load_main_dataset(
        main_path, split_path
    )
    split_frame = read_string_csv(split_path)
    protected_groups, external, protected_records = _load_protected_inputs(
        root, split_frame, _PUBLIC_SUFFIXES
    )
    protected_groups.update(main["group"])
    weak, source_audit = build_weak_supplement(
        source_path,
        _PUBLIC_SUFFIXES,
        protected_groups,
    )

    baseline_train = main.iloc[train_index]
    baseline_test = main.iloc[test_index]
    train_groups = set(baseline_train["group"])
    weak_groups = set(weak["group"])
    test_groups = set(baseline_test["group"])
    if not weak_groups.isdisjoint(train_groups | test_groups | protected_groups):
        raise ValueError("Weak supplement overlaps an original or protected domain.")
    if not train_groups.isdisjoint(test_groups):
        raise ValueError("Baseline training/test domains overlap.")
    if partition_sha256(baseline_test) != baseline_report["test_partition_sha256"]:
        raise ValueError("Original test partition fingerprint changed.")
    if partition_sha256(baseline_train) != baseline_report[
        "baseline_train_partition_sha256"
    ]:
        raise ValueError("Original training partition fingerprint changed.")

    baseline_y = baseline_train["y"].to_numpy(dtype=int)
    if not np.array_equal(
        np.unique(baseline_y), np.array([0, 1])
    ):
        raise ValueError("Baseline training must contain both classes.")
    scale_pos_weight = float((baseline_y == 0).sum() / (baseline_y == 1).sum())
    if scale_pos_weight != baseline_report["scale_pos_weight"]:
        raise ValueError("Baseline class weight differs from the recorded candidate.")

    baseline_model = baseline_artifact["model"]
    baseline_features, _ = _feature_matrix(
        baseline_train["normalized_url"].tolist(),
        expected_names=feature_names,
        description="Baseline training URLs",
    )
    weak_features, _ = _feature_matrix(
        weak["model_url"].tolist(),
        expected_names=feature_names,
        description="Weak-label training URLs",
    )
    test_features, _ = _feature_matrix(
        baseline_test["normalized_url"].tolist(),
        expected_names=feature_names,
        description="Unchanged baseline test URLs",
    )
    baseline_test_probabilities = _model_probabilities(baseline_model, test_features)

    model = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
        random_state=42,
    )
    train_features = np.concatenate((baseline_features, weak_features), axis=0)
    train_y = np.concatenate((
        baseline_y,
        weak["y"].to_numpy(dtype=int),
    ))
    print(
        f"Training candidate on {len(baseline_y):,} baseline rows and "
        f"{len(weak):,} weak-label new-domain rows...",
        flush=True,
    )
    model.fit(train_features, train_y)
    weak_test_probabilities = _model_probabilities(model, test_features)

    baseline_diagnostic_path = (
        root / "docs/model_metrics/scheme_invariant_baseline_v1/"
        "scheme_invariant_diagnostics.csv"
    )
    diagnostic = read_string_csv(baseline_diagnostic_path)
    diagnostic_urls = diagnostic["url"].map(normalize_candidate_url)
    if diagnostic_urls.isna().any():
        raise ValueError("Baseline diagnostic URLs are invalid.")
    diagnostic_features, _ = _feature_matrix(
        diagnostic_urls.tolist(),
        expected_names=feature_names,
        description="Baseline diagnostic URLs",
    )
    reproduced = _model_probabilities(baseline_model, diagnostic_features)
    recorded = diagnostic["prob_malicious"].to_numpy(dtype=float)
    if not np.allclose(reproduced, recorded, atol=1e-6, rtol=0):
        raise ValueError("Baseline saved diagnostics failed reproduction.")

    test_frame = pd.DataFrame({
        "model_url": baseline_test["normalized_url"].tolist(),
        "y": baseline_test["y"].to_numpy(dtype=int),
        "group": baseline_test["group"].to_numpy(),
    })
    test_meta = [
        _PUBLIC_SUFFIXES(urlsplit(url).hostname or "")
        for url in test_frame["model_url"]
    ]
    test_frame["scheme"] = [
        urlsplit(url).scheme.lower() for url in test_frame["model_url"]
    ]
    test_frame["host_type"] = [
        "subdomain" if extracted.subdomain else "apex"
        for extracted in test_meta
    ]
    test_frame["url_shape"] = [
        (
            "path_bearing"
            if urlsplit(url).path not in ("", "/")
            else (
                "root_with_query_or_fragment"
                if urlsplit(url).query or urlsplit(url).fragment
                else "root_only"
            )
        )
        for url in test_frame["model_url"]
    ]

    records = []
    paired_records = []
    bootstrap_records = []

    # Reuse the already-computed test scores so the paired comparison is exact.
    base_test_frame = test_frame.copy()
    base_test_frame["model_url"] = baseline_test["normalized_url"].tolist()
    test_records = []
    test_paired = []
    for slice_name, mask in _slice_masks(base_test_frame).items():
        for candidate, probabilities in (
            ("baseline_scheme_invariant", baseline_test_probabilities),
            ("phishbenign_weak_supplement", weak_test_probabilities),
        ):
            test_records.append({
                "scope": "original_saved_test",
                "slice": slice_name,
                "candidate": candidate,
                "threshold": THRESHOLD,
                **_metrics(
                    base_test_frame["y"].to_numpy(dtype=int)[mask],
                    probabilities[mask],
                    base_test_frame["group"].to_numpy()[mask],
                ),
                "roc_auc": (
                    float(roc_auc_score(
                        base_test_frame["y"].to_numpy(dtype=int)[mask],
                        probabilities[mask],
                    ))
                    if np.unique(base_test_frame["y"].to_numpy(dtype=int)[mask]).size == 2
                    else None
                ),
                "average_precision": (
                    float(average_precision_score(
                        base_test_frame["y"].to_numpy(dtype=int)[mask],
                        probabilities[mask],
                    ))
                    if np.unique(base_test_frame["y"].to_numpy(dtype=int)[mask]).size == 2
                    else None
                ),
            })
            if candidate == "phishbenign_weak_supplement":
                y_slice = base_test_frame["y"].to_numpy(dtype=int)[mask]
                groups_slice = base_test_frame["group"].to_numpy()[mask]
                base_metrics = _metrics(
                    y_slice, baseline_test_probabilities[mask], groups_slice
                )
                weak_metrics = _metrics(
                    y_slice, weak_test_probabilities[mask], groups_slice
                )
                test_paired.append({
                    "scope": "original_saved_test",
                    "slice": slice_name,
                    "rows": int(mask.sum()),
                    "domain_groups": int(pd.Series(groups_slice).nunique()),
                    "threshold": THRESHOLD,
                    "baseline_false_positive_rate": base_metrics[
                        "false_positive_rate"
                    ],
                    "weak_false_positive_rate": weak_metrics[
                        "false_positive_rate"
                    ],
                    "false_positive_rate_delta": (
                        weak_metrics["false_positive_rate"]
                        - base_metrics["false_positive_rate"]
                        if base_metrics["false_positive_rate"] is not None
                        and weak_metrics["false_positive_rate"] is not None
                        else None
                    ),
                    "baseline_phishing_recall": base_metrics[
                        "phishing_recall"
                    ],
                    "weak_phishing_recall": weak_metrics[
                        "phishing_recall"
                    ],
                    "phishing_recall_delta": (
                        weak_metrics["phishing_recall"]
                        - base_metrics["phishing_recall"]
                        if base_metrics["phishing_recall"] is not None
                        and weak_metrics["phishing_recall"] is not None
                        else None
                    ),
                    "baseline_domain_macro_false_positive_rate": base_metrics[
                        "domain_macro_false_positive_rate"
                    ],
                    "weak_domain_macro_false_positive_rate": weak_metrics[
                        "domain_macro_false_positive_rate"
                    ],
                    "domain_macro_false_positive_rate_delta": (
                        weak_metrics["domain_macro_false_positive_rate"]
                        - base_metrics["domain_macro_false_positive_rate"]
                        if base_metrics[
                            "domain_macro_false_positive_rate"
                        ] is not None
                        and weak_metrics[
                            "domain_macro_false_positive_rate"
                        ] is not None
                        else None
                    ),
                    "baseline_domain_macro_phishing_recall": base_metrics[
                        "domain_macro_phishing_recall"
                    ],
                    "weak_domain_macro_phishing_recall": weak_metrics[
                        "domain_macro_phishing_recall"
                    ],
                    "domain_macro_phishing_recall_delta": (
                        weak_metrics["domain_macro_phishing_recall"]
                        - base_metrics["domain_macro_phishing_recall"]
                        if base_metrics[
                            "domain_macro_phishing_recall"
                        ] is not None
                        and weak_metrics[
                            "domain_macro_phishing_recall"
                        ] is not None
                        else None
                    ),
                    **_paired_counts(
                        y_slice,
                        baseline_test_probabilities[mask],
                        weak_test_probabilities[mask],
                    ),
                })
    records.extend(test_records)
    paired_records.extend(test_paired)
    bootstrap_records.append({
        "scope": "original_saved_test",
        **_paired_bootstrap(
            base_test_frame["y"].to_numpy(dtype=int),
            baseline_test_probabilities,
            weak_test_probabilities,
            base_test_frame["group"].to_numpy(),
        ),
    })

    for scope_name, (data, urls, groups, manifest) in external.items():
        if scope_name == "historical_hannousse":
            if not data["label"].isin(["benign", "malicious"]).all():
                raise ValueError("Unexpected labels in protected Hannousse evaluation.")
            labels = data["label"].map({"benign": 0, "malicious": 1}).to_numpy(dtype=int)
            if manifest.get("current_safety_verified") is not False:
                raise ValueError("Hannousse manifest safety status changed.")
        else:
            if not data["label"].eq("benign").all():
                raise ValueError("Unexpected labels in frozen HTTP-path challenge.")
            labels = np.zeros(len(data), dtype=int)

        frame = pd.DataFrame({
            "model_url": urls,
            "y": labels,
            "group": groups,
            "scheme": [urlsplit(url).scheme.lower() for url in urls],
        })
        extracted = [
            _PUBLIC_SUFFIXES(urlsplit(url).hostname or "") for url in urls
        ]
        frame["host_type"] = [
            "subdomain" if item.subdomain else "apex" for item in extracted
        ]
        frame["url_shape"] = [
            (
                "path_bearing"
                if urlsplit(url).path not in ("", "/")
                else (
                    "root_with_query_or_fragment"
                    if urlsplit(url).query or urlsplit(url).fragment
                    else "root_only"
                )
            )
            for url in urls
        ]
        scope_records, scope_paired, scope_bootstrap = evaluate_scope(
            scope_name,
            frame,
            baseline_model,
            model,
            feature_names,
        )
        records.extend(scope_records)
        paired_records.extend(scope_paired)
        bootstrap_records.append({
            "scope": scope_name,
            **scope_bootstrap,
        })

    metrics_frame = pd.DataFrame(records)
    paired_frame = pd.DataFrame(paired_records)
    _validate_unique_paired_slices(paired_frame)

    baseline_test_metrics = _metrics(
        base_test_frame["y"].to_numpy(dtype=int),
        baseline_test_probabilities,
        base_test_frame["group"].to_numpy(),
    )
    recorded_overall = baseline_report["overall"]
    for metric_key, report_key in (
        ("rows", "rows"),
        ("benign_rows", "benign_rows"),
        ("phishing_rows", "malicious_rows"),
        ("confusion_matrix", "confusion_matrix"),
    ):
        if baseline_test_metrics[metric_key] != recorded_overall[report_key]:
            raise ValueError(f"Reproduced baseline metric differs: {metric_key}")
    if not np.isclose(
        baseline_test_metrics["false_positive_rate"],
        recorded_overall["false_positive_rate"],
        atol=1e-12,
    ) or not np.isclose(
        baseline_test_metrics["phishing_recall"],
        recorded_overall["malicious_recall"],
        atol=1e-12,
    ):
        raise ValueError("Reproduced baseline test metrics differ from saved report.")

    output.mkdir(parents=True, exist_ok=False)
    joblib.dump(
        {
            "candidate_only": True,
            "model": model,
            "feature_names": feature_names,
            "feature_representation": EXPERIMENTAL_FEATURE_VERSION,
            "preprocessing": baseline_report["preprocessing"],
            "threshold": THRESHOLD,
            "variant": "scheme_invariant",
            "training_source": SOURCE_NAME,
            "training_label_policy": LABEL_POLICY,
            "pseudo_labels_not_current_safety_verification": True,
        },
        output / "phishbenign_weak_candidate.joblib",
    )
    metrics_frame.to_csv(output / "metrics_by_slice.csv", index=False)
    paired_frame.to_csv(output / "paired_changes_by_slice.csv", index=False)
    pd.DataFrame(bootstrap_records).to_csv(
        output / "paired_domain_bootstrap.csv", index=False
    )
    metrics_frame[metrics_frame["slice"].eq("overall")][
        [
            "scope",
            "candidate",
            "threshold",
            "rows",
            "domain_groups",
            "accuracy",
            "false_positive_rate",
            "phishing_recall",
            "domain_macro_false_positive_rate",
            "domain_macro_phishing_recall",
            "roc_auc",
            "average_precision",
            "confusion_matrix",
        ]
    ].to_csv(output / "summary.csv", index=False)
    selected_label_counts = {
        str(label): int(count)
        for label, count in weak["y"].value_counts().sort_index().items()
    }
    train_label_counts = {
        str(label): int(count)
        for label, count in pd.Series(train_y).value_counts().sort_index().items()
    }
    output_manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "experiment": "phishbenign_weak_label_candidate_v1",
        "approval": {
            "status": "user_approved_for_isolated_weak_label_experiment",
            "approved_at": "2026-10-15T16:30:31-05:00",
            "label_policy": LABEL_POLICY,
            "current_safety_verification": False,
        },
        "source": {
            "name": SOURCE_NAME,
            "url": SOURCE_URL,
            "revision": SOURCE_REVISION,
            "license_declared_by_host": "CC BY-SA 4.0",
            "local_filename": source_path.name,
            "sha256": file_sha256(source_path),
            "class_mapping": {
                "0": "pseudo_benign",
                "1": "pseudo_phishing",
            },
            "per_row_provenance_and_observation_dates_documented": False,
            "scheme_coverage": (
                "The source contains mostly scheme-unspecified URL strings. "
                "For feature parsing only, these strings receive the same fixed "
                "outer-scheme canonicalization used by the scheme-invariant "
                "candidate. No source row is asserted to be HTTP or HTTPS."
            ),
        },
        "source_audit": source_audit,
        "input_fingerprints": {
            "main_csv_sha256": file_sha256(main_path),
            "baseline_split_sha256": file_sha256(split_path),
            "manual_fixture_sha256": file_sha256(manual_path),
            "baseline_report_sha256": file_sha256(baseline_metrics_path),
            "baseline_artifact_sha256": file_sha256(baseline_artifact_path),
            "protected_inputs": protected_records,
            "experiment_code_sha256": file_sha256(Path(__file__)),
            "production_feature_code_sha256": file_sha256(
                root / "sentinelti/ml/features.py"
            ),
            "experimental_feature_code_sha256": file_sha256(
                root / "sentinelti/ml/experimental_features.py"
            ),
        },
        "baseline_split": {
            key: value for key, value in split_audit.items()
            if key not in {"train_groups", "test_groups"}
        },
        "training": {
            "baseline_train_rows": int(len(baseline_y)),
            "weak_label_rows": int(len(weak)),
            "total_train_rows": int(len(train_y)),
            "baseline_train_domain_groups": len(train_groups),
            "new_weak_label_domain_groups": len(weak_groups),
            "post_supplement_train_domain_groups": len(train_groups | weak_groups),
            "test_rows": int(len(test_index)),
            "test_domain_groups": len(test_groups),
            "train_test_group_overlap": 0,
            "source_test_group_overlap": 0,
            "baseline_class_counts": {
                str(label): int(count)
                for label, count in pd.Series(baseline_y).value_counts().sort_index().items()
            },
            "weak_pseudo_label_counts": selected_label_counts,
            "total_train_class_counts": train_label_counts,
            "baseline_scale_pos_weight": scale_pos_weight,
            "scale_pos_weight_preserved": True,
            "threshold": THRESHOLD,
            "feature_representation": EXPERIMENTAL_FEATURE_VERSION,
            "training_parameters": {
                "n_estimators": 400,
                "max_depth": 6,
                "learning_rate": 0.1,
                "subsample": 0.8,
                "colsample_bytree": 0.8,
                "objective": "binary:logistic",
                "eval_metric": "logloss",
                "random_state": 42,
            },
        },
        "evaluation_policy": {
            "threshold_selection": "not_performed; fixed at 0.75",
            "hannousse_status": (
                "Previously examined during development; used only as a fixed-threshold "
                "exploratory external score, not as an untouched final benchmark."
            ),
            "historical_labels_are_current_safety_verification": False,
            "test_partition_sha256": split_audit["test_partition_sha256"],
            "baseline_test_partition_unchanged": True,
        },
        "output_integrity": {
            "metrics_scope_slice_candidate_rows_unique": not metrics_frame.duplicated(
                ["scope", "slice", "candidate"]
            ).any(),
            "paired_scope_slice_rows": len(paired_frame),
            "paired_scope_slice_rows_unique": not paired_frame.duplicated(
                ["scope", "slice"]
            ).any(),
        },
        "candidate_artifact": {
            "path": "phishbenign_weak_candidate.joblib",
            "sha256": file_sha256(output / "phishbenign_weak_candidate.joblib"),
            "candidate_only": True,
            "production_artifacts_modified": False,
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(output_manifest, indent=2), encoding="utf-8"
    )
    print(f"\nExperiment reports and candidate: {output}")
    print("No production artifacts, main data, or frozen evaluations were changed.")


if __name__ == "__main__":
    main()
