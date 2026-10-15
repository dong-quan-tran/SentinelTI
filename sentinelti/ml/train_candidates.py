from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from sentinelti.ml.features import extract_features
from sentinelti.ml.experimental_features import (
    EXPERIMENTAL_FEATURE_VERSION,
    extract_scheme_invariant_features,
)


THRESHOLD = 0.75
PREPROCESSING = "http-empty-path-to-root-v1"
SUPPLEMENTAL_DOMAIN_CAP = 20
DIAGNOSTIC_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "google.com",
    "microsoft.com",
    "github.com",
    "wikipedia.org",
}


def normalize_candidate_url(value: object) -> str | None:
    if pd.isna(value):
        return None

    url = str(value).strip()
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.hostname:
            return None
        _ = parsed.port
    except ValueError:
        return None

    if not parsed.path:
        return urlunsplit(
            (parsed.scheme, parsed.netloc, "/", parsed.query, parsed.fragment)
        )
    return url


def slice_metrics(y_true, probabilities) -> dict:
    predictions = (probabilities >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()
    return {
        "rows": int(len(y_true)),
        "benign_rows": int(tn + fp),
        "malicious_rows": int(fn + tp),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "malicious_recall": float(tp / (tp + fn)) if tp + fn else None,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def domain_group(url: str, suffixes) -> str:
    host = urlsplit(url).hostname or ""
    result = suffixes(host)
    return result.top_domain_under_public_suffix or host.lower()


def url_subgroup(url: str, suffixes) -> tuple[str, str]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host_type = (
        "subdomain"
        if suffixes(parsed.hostname or "").subdomain
        else "apex"
    )
    return scheme, host_type


def selected_feature_indices(names, variant: str) -> list[int]:
    if variant not in {"full", "no_scheme", "scheme_invariant"}:
        raise ValueError(f"Unknown candidate variant: {variant}")

    return [
        index
        for index, name in enumerate(names)
        if variant == "full" or name not in {"is_http", "is_https"}
    ]


def read_string_csv(path, usecols=None) -> pd.DataFrame:
    return pd.read_csv(
        path,
        usecols=usecols,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
        low_memory=False,
    )


def file_sha256(path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def partition_sha256(frame: pd.DataFrame) -> str:
    records = sorted(
        zip(
            frame["normalized_url"],
            frame["label"],
            frame["group"],
        )
    )
    payload = json.dumps(
        records,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_saved_split(
    path,
    df: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray]:
    assignments = read_string_csv(path)

    if not {"group", "partition"}.issubset(assignments.columns):
        raise ValueError("Split file must contain group and partition.")

    if assignments.empty:
        raise ValueError("Split file is empty.")

    if assignments["group"].eq("").any():
        raise ValueError("Split file contains an empty group.")

    if assignments["group"].duplicated().any():
        raise ValueError("Split file contains duplicate group assignments.")

    if not assignments["partition"].isin(["train", "test"]).all():
        raise ValueError("Split partitions must be train or test.")

    current_groups = set(df["group"])
    saved_groups = set(assignments["group"])

    if current_groups != saved_groups:
        missing = current_groups - saved_groups
        extra = saved_groups - current_groups
        raise ValueError(
            "Saved split does not match the normalized main dataset: "
            f"{len(missing)} current groups missing from split; "
            f"{len(extra)} saved groups absent from dataset."
        )

    partition_by_group = assignments.set_index("group")["partition"]
    partitions = df["group"].map(partition_by_group)

    train_index = np.flatnonzero(partitions.eq("train").to_numpy())
    test_index = np.flatnonzero(partitions.eq("test").to_numpy())

    if len(train_index) == 0 or len(test_index) == 0:
        raise ValueError("Saved split must contain nonempty train and test sets.")

    return train_index, test_index


def load_supplement(
    path,
    main_df: pd.DataFrame,
    train_groups: set[str],
    test_groups: set[str],
    manual_eval_path,
    suffixes,
) -> pd.DataFrame:
    supplement = read_string_csv(path, usecols=["url", "label"])

    if supplement.empty:
        raise ValueError("Supplement is empty.")

    if not supplement["label"].eq("benign").all():
        raise ValueError("This experiment accepts only benign supplements.")

    supplement["normalized_url"] = supplement["url"].map(
        normalize_candidate_url
    )

    if supplement["normalized_url"].isna().any():
        raise ValueError("Supplement contains invalid URLs.")

    if supplement["normalized_url"].duplicated().any():
        raise ValueError("Supplement contains normalized duplicates.")

    if supplement["normalized_url"].isin(main_df["normalized_url"]).any():
        raise ValueError("Supplement overlaps the normalized main dataset.")

    supplement["group"] = supplement["normalized_url"].map(
        lambda url: domain_group(url, suffixes)
    )

    if supplement["group"].isin(test_groups).any():
        raise ValueError("Supplement contains recorded test groups.")

    if not supplement["group"].isin(train_groups).all():
        raise ValueError(
            "Supplement must use existing recorded training groups only."
        )

    if supplement["group"].isin(DIAGNOSTIC_DOMAINS).any():
        raise ValueError("Supplement contains diagnostic groups.")

    manual = read_string_csv(manual_eval_path, usecols=["url"])
    manual_urls = [
        normalized
        for value in manual["url"]
        if (normalized := normalize_candidate_url(value)) is not None
    ]
    manual_groups = {
        domain_group(url, suffixes) for url in manual_urls
    }

    if supplement["normalized_url"].isin(manual_urls).any():
        raise ValueError("Supplement overlaps manual evaluation URLs.")

    if supplement["group"].isin(manual_groups).any():
        raise ValueError("Supplement overlaps manual evaluation groups.")

    slices = supplement["normalized_url"].map(
        lambda url: url_subgroup(url, suffixes)
    )
    if not slices.map(lambda value: value == ("http", "apex")).all():
        raise ValueError("Supplement must contain only HTTP/apex URLs.")

    if supplement.groupby("group").size().max() > SUPPLEMENTAL_DOMAIN_CAP:
        raise ValueError(
            f"Supplement exceeds the {SUPPLEMENTAL_DOMAIN_CAP}-URL domain cap."
        )

    supplement["y"] = 0
    return supplement



REVIEWED_SUPPLEMENT_SCHEMA = "reviewed-new-domains-v1"
REVIEWED_SUPPLEMENT_DOMAIN_CAP = 1
PROTECTED_EXTERNAL_EVALUATIONS = (
    (
        "docs/model_metrics/hannousse_external_eval_v1/urls.csv",
        "docs/model_metrics/hannousse_external_eval_v1/manifest.json",
        "evaluation_csv_sha256",
    ),
    (
        "docs/model_metrics/external_http_path_challenge_v1/urls.csv",
        "docs/model_metrics/external_http_path_challenge_v1/manifest.json",
        "challenge_csv_sha256",
    ),
)


def load_reviewed_supplement(
    path,
    manifest_path,
    main_df: pd.DataFrame,
    train_groups: set[str],
    test_groups: set[str],
    manual_eval_path,
    suffixes,
    *,
    baseline_csv_sha256: str,
    baseline_split_sha256: str,
    protected_evaluations=PROTECTED_EXTERNAL_EVALUATIONS,
) -> pd.DataFrame:
    """Validate experiment approvals and isolation; do not infer safe labels."""
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def nonempty(value):
        return isinstance(value, str) and bool(value.strip())

    def is_hash(value):
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(char in "0123456789abcdef" for char in value)
        )

    manifest_bytes = Path(manifest_path).read_bytes()
    csv_bytes = Path(path).read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    require(isinstance(manifest, dict), "Supplement manifest must be an object.")
    require(
        manifest.get("schema_version") == REVIEWED_SUPPLEMENT_SCHEMA,
        "Unsupported reviewed supplement schema.",
    )
    require(
        manifest.get("supplement_csv_sha256")
        == hashlib.sha256(csv_bytes).hexdigest(),
        "Reviewed supplement CSV hash mismatch.",
    )
    require(
        manifest.get("baseline_csv_sha256") == baseline_csv_sha256
        and manifest.get("baseline_split_sha256") == baseline_split_sha256,
        "Reviewed supplement baseline fingerprints differ.",
    )
    manual_bytes = Path(manual_eval_path).read_bytes()
    require(
        manifest.get("manual_fixture_sha256")
        == hashlib.sha256(manual_bytes).hexdigest(),
        "Reviewed supplement manual fixture hash mismatch.",
    )
    require(
        manifest.get("preprocessing") == PREPROCESSING,
        "Reviewed supplement preprocessing differs.",
    )
    basis = manifest.get("label_basis")
    require(
        basis in {"historical_source_label", "registry_associated_assumed_benign"},
        "Unsupported or unassigned supplement label basis.",
    )
    approval = manifest.get("approval")
    require(isinstance(approval, dict), "Explicit experiment approval required.")
    require(
        approval.get("status") == "approved_for_experiment"
        and nonempty(approval.get("reviewer"))
        and nonempty(approval.get("label_policy"))
        and approval.get("not_current_safety_verification") is True,
        "Explicit experiment approval and label policy required.",
    )
    try:
        reviewed_at = datetime.fromisoformat(approval["reviewed_at_utc"])
        require(reviewed_at.utcoffset() is not None, "Approval timestamp needs a timezone.")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Approval needs a timezone-aware review timestamp.") from exc
    source = manifest.get("source")
    require(
        isinstance(source, dict)
        and nonempty(source.get("name"))
        and nonempty(source.get("url"))
        and is_hash(source.get("sha256")),
        "Documented source name, URL, and SHA256 required.",
    )
    require(
        type(manifest.get("per_domain_cap")) is int
        and manifest["per_domain_cap"] == REVIEWED_SUPPLEMENT_DOMAIN_CAP,
        "Reviewed supplements require a one-URL-per-domain cap.",
    )

    import io
    supplement = read_string_csv(io.BytesIO(csv_bytes))
    required = {
        "url", "label", "label_basis", "review_status",
        "review_evidence_url", "reviewer", "source_sha256",
    }
    require(required.issubset(supplement.columns), "Missing reviewed supplement columns.")
    require(not supplement.empty, "Reviewed supplement is empty.")
    require(supplement["label"].eq("benign").all(), "Only explicit benign labels accepted.")
    require(supplement["label_basis"].eq(basis).all(), "Per-row label basis differs.")
    require(
        supplement["review_status"].eq("approved_for_experiment").all(),
        "Every row requires experiment approval; corroboration alone is insufficient.",
    )
    for column in ("review_evidence_url", "reviewer"):
        require(supplement[column].str.strip().ne("").all(), f"Blank {column}.")
    for evidence_url in [source["url"], *supplement["review_evidence_url"]]:
        require(
            normalize_candidate_url(evidence_url) is not None,
            "Evidence and source URLs must be explicit HTTP(S) URLs.",
        )
    require(
        supplement["source_sha256"].eq(source["sha256"]).all(),
        "Per-row source hash differs.",
    )
    supplement["normalized_url"] = supplement["url"].map(normalize_candidate_url)
    require(supplement["normalized_url"].notna().all(), "Invalid reviewed supplement URLs.")
    require(
        not supplement["normalized_url"].duplicated().any(),
        "Reviewed supplement contains normalized duplicates or conflicting labels.",
    )
    require(
        not supplement["normalized_url"].isin(main_df["normalized_url"]).any(),
        "Reviewed supplement overlaps normalized main URLs.",
    )

    import ipaddress
    for url in supplement["normalized_url"]:
        parsed = urlsplit(url)
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise ValueError("IP-literal supplements are outside this experiment.")
        require(
            parsed.username is None and parsed.password is None,
            "Credential-bearing supplements are outside this experiment.",
        )
        default_port = 80 if parsed.scheme.lower() == "http" else 443
        require(
            parsed.port in (None, default_port),
            "Nondefault-port supplements are outside this experiment.",
        )
        require(bool(suffixes(parsed.hostname).suffix), "Public-suffix hostname required.")

    supplement["group"] = supplement["normalized_url"].map(
        lambda url: domain_group(url, suffixes)
    )
    groups = set(supplement["group"])
    require(groups.isdisjoint(test_groups), "Supplement overlaps saved test domains.")
    require(
        groups.isdisjoint(set(main_df["group"]) | train_groups),
        "Reviewed supplement must contain new domain groups only.",
    )
    require(groups.isdisjoint(DIAGNOSTIC_DOMAINS), "Supplement overlaps diagnostic domains.")
    require(
        not supplement["group"].duplicated().any(),
        "Reviewed supplement exceeds the one-URL-per-domain cap.",
    )

    def protected_groups(data, description):
        urls = data["url"].map(normalize_candidate_url)
        require(urls.notna().all(), f"Invalid URL in {description}.")
        computed = urls.map(lambda url: domain_group(url, suffixes))
        if "group" in data.columns:
            require(computed.equals(data["group"]), f"Stored groups differ in {description}.")
        return set(computed)

    manual = read_string_csv(io.BytesIO(manual_bytes), usecols=["url"])
    require(
        groups.isdisjoint(protected_groups(manual, "manual fixture")),
        "Supplement overlaps manual evaluation domains.",
    )
    require(bool(protected_evaluations), "Protected external evaluations are required.")
    declared = manifest.get("protected_evaluations")
    require(isinstance(declared, list), "Protected evaluation fingerprints required.")
    actual_records = []
    for csv_path, evaluation_manifest_path, hash_key in protected_evaluations:
        evaluation_bytes = Path(csv_path).read_bytes()
        evaluation_manifest_bytes = Path(evaluation_manifest_path).read_bytes()
        evaluation_manifest = json.loads(evaluation_manifest_bytes.decode("utf-8-sig"))
        evaluation_hash = hashlib.sha256(evaluation_bytes).hexdigest()
        require(
            isinstance(evaluation_manifest, dict)
            and evaluation_manifest.get(hash_key) == evaluation_hash,
            "Protected evaluation CSV hash mismatch.",
        )
        data = read_string_csv(io.BytesIO(evaluation_bytes))
        require("url" in data.columns and not data.empty, "Empty/invalid protected evaluation.")
        require(
            groups.isdisjoint(protected_groups(data, "protected evaluation")),
            "Supplement overlaps protected external evaluation domains.",
        )
        actual_records.append({
            "csv_path": str(csv_path),
            "csv_sha256": evaluation_hash,
            "manifest_path": str(evaluation_manifest_path),
            "manifest_sha256": hashlib.sha256(evaluation_manifest_bytes).hexdigest(),
        })
    require(declared == actual_records, "Protected evaluation fingerprints differ.")
    require(
        type(manifest.get("rows")) is int and manifest["rows"] == len(supplement)
        and type(manifest.get("domain_groups")) is int
        and manifest["domain_groups"] == len(groups),
        "Reviewed supplement row/domain counts differ.",
    )
    require(
        Path(path).read_bytes() == csv_bytes
        and Path(manifest_path).read_bytes() == manifest_bytes
        and Path(manual_eval_path).read_bytes() == manual_bytes,
        "Reviewed supplement inputs changed during validation.",
    )
    for record in actual_records:
        require(
            file_sha256(record["csv_path"]) == record["csv_sha256"]
            and file_sha256(record["manifest_path"]) == record["manifest_sha256"],
            "Protected evaluation changed during validation.",
        )
    supplement["y"] = 0
    supplement.attrs["reviewed_provenance"] = {
        "schema_version": REVIEWED_SUPPLEMENT_SCHEMA,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "label_basis": basis,
        "approval": approval,
        "source": source,
        "protected_evaluations": actual_records,
        "current_safety_verified": False,
    }
    return supplement


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv-path", default="data/urldata.csv")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--split-groups")
    parser.add_argument("--supplemental-csv")
    parser.add_argument(
        "--supplemental-mode",
        choices=("legacy-http-apex", "reviewed-new-domains"),
        default="legacy-http-apex",
    )
    parser.add_argument("--supplemental-manifest")
    parser.add_argument("--variants",
        nargs="+",
        choices=("full", "no_scheme", "scheme_invariant"),
        default=["full", "no_scheme"],
    )
    parser.add_argument(
        "--manual-eval-path",
        default="data/manual_eval_urls.csv",
    )
    args = parser.parse_args()

    if args.supplemental_mode == "reviewed-new-domains":
        if not (args.supplemental_csv and args.supplemental_manifest and args.split_groups):
            parser.error("reviewed-new-domains requires supplement CSV, manifest, and saved split.")
        if args.variants != ["full"]:
            parser.error("The first reviewed-new-domains experiment requires --variants full.")
    elif args.supplemental_manifest:
        parser.error("--supplemental-manifest requires reviewed-new-domains mode.")

    if args.supplemental_csv and not args.split_groups:
        parser.error("--supplemental-csv requires --split-groups.")
    if len(args.variants) != len(set(args.variants)):
        parser.error("--variants must not contain duplicates.")
    if "scheme_invariant" in args.variants:
        if not args.split_groups:
            parser.error("scheme_invariant requires --split-groups.")
        if args.supplemental_csv:
            parser.error(
                "Run the first scheme_invariant experiment without a supplement."
            )

    output = Path(args.output_dir)
    if output.exists():
        raise FileExistsError(f"Output directory already exists: {output}")

    suffixes = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )

    df = read_string_csv(args.csv_path, usecols=["url", "label"])
    df = df[df["label"].isin(["benign", "malicious"])].copy()
    original_rows = len(df)

    df["normalized_url"] = df["url"].map(normalize_candidate_url)
    df = df.dropna(subset=["normalized_url"]).copy()
    invalid_rows = original_rows - len(df)

    if df.empty:
        raise ValueError("No valid labeled URLs remain in the main dataset.")

    conflicts = df.groupby("normalized_url")["label"].nunique()
    if conflicts.gt(1).any():
        raise ValueError(
            "Conflicting labels after normalization; investigate before training."
        )

    before_dedup = len(df)
    df = df.drop_duplicates("normalized_url").copy()
    deduplicated_rows = before_dedup - len(df)

    df["group"] = df["normalized_url"].map(
        lambda url: domain_group(url, suffixes)
    )
    excluded_rows = int(df["group"].isin(DIAGNOSTIC_DOMAINS).sum())
    df = df[~df["group"].isin(DIAGNOSTIC_DOMAINS)].reset_index(drop=True)
    df["y"] = df["label"].map({"benign": 0, "malicious": 1})

    if df.empty:
        raise ValueError("No rows remain after diagnostic-group exclusions.")

    if args.split_groups:
        train_index, test_index = load_saved_split(args.split_groups, df)
        split_method = "saved-domain-groups"
    else:
        splitter = GroupShuffleSplit(
            n_splits=1,
            test_size=0.30,
            random_state=42,
        )
        train_index, test_index = next(
            splitter.split(df, df["y"], groups=df["group"])
        )
        split_method = "group-shuffle"

    train_groups = set(df.iloc[train_index]["group"])
    test_groups = set(df.iloc[test_index]["group"])

    if not train_groups.isdisjoint(test_groups):
        raise ValueError("Training and test groups overlap.")

    baseline_train_y = df.iloc[train_index]["y"]
    baseline_test_y = df.iloc[test_index]["y"]

    if baseline_train_y.nunique() != 2 or baseline_test_y.nunique() != 2:
        raise ValueError("Both classes must be present in each partition.")

    baseline_scale_pos_weight = float(
        baseline_train_y.eq(0).sum() / baseline_train_y.eq(1).sum()
    )
    baseline_train_rows = len(train_index)
    baseline_train_sha256 = partition_sha256(df.iloc[train_index])
    test_partition_sha256 = partition_sha256(df.iloc[test_index])
    main_csv_sha256 = file_sha256(args.csv_path)

    supplemental_rows = 0
    supplemental_groups = 0
    supplemental_sha256 = None
    manual_eval_sha256 = None
    reviewed_provenance = None
    baseline_train_group_count = len(train_groups)

    if args.supplemental_csv:
        if args.supplemental_mode == "reviewed-new-domains":
            supplement = load_reviewed_supplement(
                args.supplemental_csv,
                args.supplemental_manifest,
                df,
                train_groups,
                test_groups,
                args.manual_eval_path,
                suffixes,
                baseline_csv_sha256=main_csv_sha256,
                baseline_split_sha256=file_sha256(args.split_groups),
            )
            reviewed_provenance = supplement.attrs["reviewed_provenance"]
        else:
            supplement = load_supplement(
                args.supplemental_csv,
                df,
                train_groups,
                test_groups,
                args.manual_eval_path,
                suffixes,
            )
        supplemental_rows = len(supplement)
        supplemental_groups = supplement["group"].nunique()
        supplemental_sha256 = file_sha256(args.supplemental_csv)
        manual_eval_sha256 = file_sha256(args.manual_eval_path)

        original_length = len(df)
        df = pd.concat([df, supplement], ignore_index=True)
        train_index = np.concatenate([
            train_index,
            np.arange(original_length, len(df)),
        ])

    train_groups = set(df.iloc[train_index]["group"])
    if not train_groups.isdisjoint(set(df.iloc[test_index]["group"])):
        raise ValueError("Supplement introduced train/test group overlap.")

    if partition_sha256(df.iloc[test_index]) != test_partition_sha256:
        raise ValueError("Test partition changed during supplementation.")

    y = df["y"].to_numpy()
    y_train, y_test = y[train_index], y[test_index]

    output.mkdir(parents=True, exist_ok=False)

    print(
        f"Baseline training rows: {baseline_train_rows:,}; "
        f"supplemental rows: {supplemental_rows:,}; "
        f"test rows: {len(test_index):,}",
        flush=True,
    )
    print(f"Extracting features for {len(df):,} URLs...", flush=True)

    names = []
    X = None
    if any(variant in {"full", "no_scheme"} for variant in args.variants):
        dictionaries = [
            extract_features(url) for url in df["normalized_url"]
        ]
        names = [
            name for name in dictionaries[0] if not name.startswith("_")
        ]
        X = np.asarray(
            [[features[name] for name in names] for features in dictionaries],
            dtype=float,
        )
        del dictionaries

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "csv_path": args.csv_path,
        "csv_sha256": main_csv_sha256,
        "preprocessing": PREPROCESSING,
        "threshold": THRESHOLD,
        "invalid_rows": invalid_rows,
        "deduplicated_rows": deduplicated_rows,
        "diagnostic_domain_rows_excluded": excluded_rows,
        "baseline_train_rows": baseline_train_rows,
        "train_rows": len(train_index),
        "test_rows": len(test_index),
        "train_groups": len(train_groups),
        "test_groups": len(test_groups),
        "group_overlap": 0,
        "split_method": split_method,
        "split_seed": 42 if not args.split_groups else None,
        "split_groups_path": args.split_groups,
        "split_groups_sha256": (
            file_sha256(args.split_groups) if args.split_groups else None
        ),
        "baseline_train_partition_sha256": baseline_train_sha256,
        "test_partition_sha256": test_partition_sha256,
        "supplemental_csv": args.supplemental_csv,
        "supplemental_csv_sha256": supplemental_sha256,
        "supplemental_rows": supplemental_rows,
        "supplemental_groups": supplemental_groups,
        "supplemental_domain_cap": (
            (REVIEWED_SUPPLEMENT_DOMAIN_CAP if reviewed_provenance else SUPPLEMENTAL_DOMAIN_CAP)
            if args.supplemental_csv else None
        ),
        "manual_eval_path": (
            args.manual_eval_path if args.supplemental_csv else None
        ),
        "manual_eval_sha256": manual_eval_sha256,
        "scale_pos_weight": baseline_scale_pos_weight,
        "scale_pos_weight_basis": "baseline-training-class-ratio",
    }

    if reviewed_provenance is not None:
        manifest.update({
            "supplemental_mode": "reviewed-new-domains",
            "supplemental_manifest": args.supplemental_manifest,
            "reviewed_supplement": reviewed_provenance,
            "baseline_train_groups": baseline_train_group_count,
            "new_training_groups": len(train_groups) - baseline_train_group_count,
        })

    pd.DataFrame({
        "group": sorted(train_groups | test_groups),
    }).assign(
        partition=lambda frame: frame["group"].map(
            lambda group: "train" if group in train_groups else "test"
        )
    ).to_csv(output / "split_groups.csv", index=False)

    test_urls = df.iloc[test_index]["normalized_url"]
    subgroups = [
        url_subgroup(url, suffixes) for url in test_urls
    ]
    schemes = np.asarray([scheme for scheme, _ in subgroups])
    host_types = np.asarray([host_type for _, host_type in subgroups])
    summaries = []

    for variant in args.variants:
        if variant == "scheme_invariant":
            dictionaries = [
                extract_scheme_invariant_features(url)
                for url in df["normalized_url"]
            ]
            candidate_names = list(dictionaries[0])
            if not candidate_names:
                raise ValueError("Experimental feature mapping is empty.")
            if any(list(row) != candidate_names for row in dictionaries):
                raise ValueError("Experimental feature order is inconsistent.")
            if {"is_http", "is_https"}.intersection(candidate_names):
                raise ValueError("Experimental features contain scheme flags.")
            if any(name.startswith("_") for name in candidate_names):
                raise ValueError("Experimental features contain private metadata.")
            variant_X = np.asarray(
                [[row[name] for name in candidate_names] for row in dictionaries],
                dtype=float,
            )
            del dictionaries
            feature_representation = EXPERIMENTAL_FEATURE_VERSION
        else:
            selected = selected_feature_indices(names, variant)
            candidate_names = [names[index] for index in selected]
            variant_X = X[:, selected]
            feature_representation = (
                "production-full-v1"
                if variant == "full"
                else "production-explicit-scheme-flags-removed-v1"
            )

        if not np.isfinite(variant_X).all():
            raise ValueError("Candidate feature matrix contains nonfinite values.")

        model = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="binary:logistic",
            eval_metric="logloss",
            scale_pos_weight=baseline_scale_pos_weight,
            n_jobs=-1,
            random_state=42,
        )

        print(f"Training {variant}...", flush=True)
        model.fit(variant_X[train_index], y_train)
        probabilities = model.predict_proba(
            variant_X[test_index]
        )[:, 1]

        report = {
            **manifest,
            "variant": variant,
            "feature_names": candidate_names,
            "feature_representation": feature_representation,
            "roc_auc": float(roc_auc_score(y_test, probabilities)),
            "average_precision": float(
                average_precision_score(y_test, probabilities)
            ),
            "overall": slice_metrics(y_test, probabilities),
            "classification_report": classification_report(
                y_test,
                (probabilities >= THRESHOLD).astype(int),
                labels=[0, 1],
                output_dict=True,
                zero_division=0,
            ),
            "slices": {},
        }

        for scheme in ("http", "https"):
            for host_type in ("apex", "subdomain"):
                mask = (schemes == scheme) & (host_types == host_type)
                if mask.any():
                    report["slices"][f"{scheme}_{host_type}"] = (
                        slice_metrics(y_test[mask], probabilities[mask])
                    )

        diagnostics = []
        for domain in sorted(DIAGNOSTIC_DOMAINS):
            for scheme in ("http", "https"):
                for prefix in ("", "www."):
                    url = f"{scheme}://{prefix}{domain}/"
                    normalized = normalize_candidate_url(url)
                    features = (
                        extract_scheme_invariant_features(normalized)
                        if variant == "scheme_invariant"
                        else extract_features(normalized)
                    )
                    vector = np.asarray(
                        [[features[name] for name in candidate_names]],
                        dtype=float,
                    )
                    diagnostics.append({
                        "url": url,
                        "prob_malicious": float(
                            model.predict_proba(vector)[0, 1]
                        ),
                    })

        pd.DataFrame(diagnostics).to_csv(
            output / f"{variant}_diagnostics.csv",
            index=False,
        )
        (output / f"{variant}_metrics.json").write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )
        joblib.dump(
            {
                "candidate_only": True,
                "model": model,
                "feature_names": candidate_names,
                "feature_representation": feature_representation,
                "preprocessing": PREPROCESSING,
                "threshold": THRESHOLD,
                "variant": variant,
            },
            output / f"{variant}_candidate.joblib",
        )

        summaries.append({
            "variant": variant,
            "roc_auc": report["roc_auc"],
            "average_precision": report["average_precision"],
            **report["overall"],
        })

    summary = pd.DataFrame(summaries)
    summary.to_csv(output / "summary.csv", index=False)
    print(summary.to_string(index=False))
    print(f"\nCandidate reports and artifacts: {output}")


if __name__ == "__main__":
    main()
