from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path.cwd()
if not (ROOT / "sentinelti/ml/features.py").is_file():
    raise RuntimeError("Run this script from the SentinelTI repository root.")
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
import tldextract

from sentinelti.ml.features import extract_features
from sentinelti.ml.experimental_features import (
    EXPERIMENTAL_FEATURE_VERSION,
    extract_scheme_invariant_features,
)
from sentinelti.ml.train_candidates import (
    DIAGNOSTIC_DOMAINS,
    PREPROCESSING,
    domain_group,
    file_sha256,
    normalize_candidate_url,
    read_string_csv,
    url_subgroup,
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def feature_matrix(urls, extractor, names, variant):
    dictionaries = [extractor(url) for url in urls]
    require(bool(dictionaries), "No URLs to score.")

    available = [
        name for name in dictionaries[0]
        if not name.startswith("_")
    ]
    expected = (
        available
        if variant == "full"
        else [name for name in available if name not in {"is_http", "is_https"}]
    )
    require(names == expected, f"{variant}: saved feature order/schema mismatch.")

    for row in dictionaries:
        row_names = [
            name for name in row
            if not name.startswith("_")
            and (variant == "full" or name not in {"is_http", "is_https"})
        ]
        require(row_names == names, f"{variant}: inconsistent feature schema.")

    matrix = np.asarray(
        [[row[name] for name in names] for row in dictionaries],
        dtype=float,
    )
    require(np.isfinite(matrix).all(), "Nonfinite feature values.")
    return matrix


def probabilities(model, matrix):
    require(
        np.array_equal(np.asarray(model.classes_), np.array([0, 1])),
        "Unexpected model class ordering.",
    )
    require(
        int(model.n_features_in_) == matrix.shape[1],
        "Model feature count does not match input matrix.",
    )
    result = np.asarray(model.predict_proba(matrix), dtype=float)
    require(result.shape == (len(matrix), 2), "Unexpected probability shape.")
    require(np.isfinite(result).all(), "Nonfinite model probabilities.")
    require(((result >= 0) & (result <= 1)).all(), "Out-of-range probabilities.")
    require(
        np.allclose(result.sum(axis=1), 1.0, atol=1e-6, rtol=0),
        "Probability rows do not sum to one.",
    )
    return result[:, 1]


def main():
    challenge_dir = Path("docs/model_metrics/external_http_path_challenge_v1")
    csv_path = challenge_dir / "urls.csv"
    manifest_path = challenge_dir / "manifest.json"
    output = challenge_dir / "scores_original_candidates_v1"
    require(not output.exists(), f"Refusing to overwrite: {output}")

    manifest = read_json(manifest_path)
    require(
        file_sha256(csv_path) == manifest["challenge_csv_sha256"],
        "Challenge CSV hash mismatch.",
    )

    split_path = Path(
        "docs/model_metrics/format_shortcut_experiment/split_groups.csv"
    )
    manual_path = Path("data/manual_eval_urls.csv")
    main_path = Path("data/urldata.csv")

    for path, expected in (
        (split_path, manifest["baseline_split_sha256"]),
        (manual_path, manifest["manual_fixture_sha256"]),
        (main_path, manifest["baseline_csv_sha256"]),
    ):
        require(file_sha256(path) == expected, f"Input hash mismatch: {path}")

    suffixes = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )
    challenge = read_string_csv(csv_path)
    require(len(challenge) == manifest["challenge_rows"], "Row count mismatch.")
    require(not challenge.empty, "Challenge is empty.")
    require(challenge["label"].eq("benign").all(), "Unexpected challenge labels.")
    require(
        challenge["label_basis"].eq("historical_source_label").all(),
        "Unexpected label basis.",
    )
    require(
        challenge["current_safety_verified"].str.lower().eq("false").all(),
        "Unexpected safety-verification status.",
    )
    require(
        challenge["source_sha256"].eq(manifest["source_sha256"]).all(),
        "Source hash metadata mismatch.",
    )
    require(
        challenge["source_url"].eq(manifest["source_url"]).all(),
        "Source URL metadata mismatch.",
    )

    urls = [normalize_candidate_url(value) for value in challenge["url"]]
    require(all(url is not None for url in urls), "Invalid challenge URL.")
    require(len(set(urls)) == len(urls), "Normalized challenge duplicates.")
    groups = [domain_group(url, suffixes) for url in urls]
    require(groups == challenge["group"].tolist(), "Stored domain groups differ.")

    for url in urls:
        require(url_subgroup(url, suffixes) == ("http", "apex"),
                "Challenge contains a URL outside HTTP/apex.")
        require(urlsplit(url).path not in ("", "/"),
                "Challenge contains a root-only/root-path URL.")

    require(
        set(challenge["scheme"]) == {"http"}
        and set(challenge["host_type"]) == {"apex"}
        and set(challenge["url_shape"]) == {"path_bearing"},
        "Challenge slice metadata differs.",
    )

    splits = read_string_csv(split_path)
    require(not splits["group"].duplicated().any(), "Duplicate saved groups.")
    require(splits["partition"].isin(["train", "test"]).all(),
            "Unexpected saved partitions.")
    manual = read_string_csv(manual_path, usecols=["url"])
    manual_groups = {
        domain_group(normalized, suffixes)
        for value in manual["url"]
        if (normalized := normalize_candidate_url(value)) is not None
    }
    excluded = set(splits["group"]) | manual_groups | DIAGNOSTIC_DOMAINS
    require(set(groups).isdisjoint(excluded), "Challenge domain overlap.")
    require(
        len(set(groups)) == manifest["challenge_domain_groups"],
        "Domain count mismatch.",
    )
    require(
        challenge.groupby("group").size().max() <= manifest["per_domain_cap"],
        "Domain cap exceeded.",
    )

    experiments = [
        ("full", Path("docs/model_metrics/http_apex_supplement_baseline_v1")),
        ("no_scheme", Path("docs/model_metrics/http_apex_supplement_baseline_v1")),
        ("scheme_invariant", Path("docs/model_metrics/scheme_invariant_baseline_v1")),
    ]
    reference = read_json(experiments[0][1] / "full_metrics.json")
    expected_representations = {
        "full": "production-full-v1",
        "no_scheme": "production-explicit-scheme-flags-removed-v1",
        "scheme_invariant": EXPERIMENTAL_FEATURE_VERSION,
    }

    summaries = []
    predictions = []
    domain_results = []
    artifact_provenance = []

    for variant, directory in experiments:
        report_path = directory / f"{variant}_metrics.json"
        artifact_path = directory / f"{variant}_candidate.joblib"
        diagnostic_path = directory / f"{variant}_diagnostics.csv"
        report = read_json(report_path)

        require(report["variant"] == variant, "Report variant mismatch.")
        require(report["supplemental_rows"] == 0, "Unexpected supplemented model.")
        require(report["group_overlap"] == 0, "Report contains group overlap.")
        require(report["csv_sha256"] == manifest["baseline_csv_sha256"],
                "Report dataset hash differs from challenge provenance.")
        require(report["split_groups_sha256"] == manifest["baseline_split_sha256"],
                "Report split hash differs from challenge provenance.")

        for field in (
            "csv_sha256", "split_groups_sha256",
            "baseline_train_partition_sha256", "test_partition_sha256",
            "scale_pos_weight", "threshold", "train_rows", "test_rows",
        ):
            require(report[field] == reference[field],
                    f"{variant}: baseline comparison mismatch for {field}")

        # Load only the trusted, locally trained artifacts listed above.
        artifact = joblib.load(artifact_path)
        require(isinstance(artifact, dict), "Unexpected artifact structure.")
        require(artifact.get("candidate_only") is True, "Not a candidate artifact.")

        for field in ("variant", "feature_names", "threshold", "preprocessing"):
            require(artifact[field] == report[field],
                    f"{variant}: artifact/report mismatch for {field}")
        require(artifact["preprocessing"] == PREPROCESSING,
                "Unsupported preprocessing version.")

        representation = expected_representations[variant]
        for metadata in (artifact, report):
            recorded = metadata.get("feature_representation")
            if variant == "scheme_invariant":
                require(recorded == representation,
                        "Invariant representation metadata mismatch.")
            else:
                require(recorded in (None, representation),
                        "Unsupported production representation metadata.")

        names = artifact["feature_names"]
        require(
            isinstance(names, list) and names
            and all(isinstance(name, str) for name in names)
            and len(set(names)) == len(names),
            "Invalid saved feature names.",
        )
        threshold = float(artifact["threshold"])
        require(np.isfinite(threshold) and 0 <= threshold <= 1,
                "Invalid threshold.")

        extractor = (
            extract_scheme_invariant_features
            if variant == "scheme_invariant"
            else extract_features
        )
        model = artifact["model"]

        diagnostic = pd.read_csv(diagnostic_path)
        diagnostic_urls = [
            normalize_candidate_url(value) for value in diagnostic["url"]
        ]
        require(all(value is not None for value in diagnostic_urls),
                "Invalid saved diagnostic URL.")
        reproduced = probabilities(
            model,
            feature_matrix(diagnostic_urls, extractor, names, variant),
        )
        saved = diagnostic["prob_malicious"].to_numpy(dtype=float)
        require(
            np.isfinite(saved).all()
            and np.allclose(reproduced, saved, atol=1e-6, rtol=0),
            f"{variant}: saved diagnostics were not reproduced. Stop scoring.",
        )

        print(f"Scoring {variant}: {len(urls):,} URLs...", flush=True)
        scores = probabilities(
            model, feature_matrix(urls, extractor, names, variant)
        )
        flagged = scores >= threshold
        frame = pd.DataFrame({
            "variant": variant,
            "url": urls,
            "group": groups,
            "source_label": "benign",
            "prob_malicious": scores,
            "threshold": threshold,
            "flagged": flagged,
        })
        predictions.append(frame)

        domain_frame = (
            frame.groupby("group", sort=True)
            .agg(
                urls=("url", "size"),
                flagged_urls=("flagged", "sum"),
                mean_probability=("prob_malicious", "mean"),
            )
            .reset_index()
        )
        domain_frame["flag_rate"] = (
            domain_frame["flagged_urls"] / domain_frame["urls"]
        )
        domain_frame.insert(0, "variant", variant)
        domain_results.append(domain_frame)

        summaries.append({
            "variant": variant,
            "urls": len(frame),
            "flagged_urls": int(flagged.sum()),
            "url_flag_rate": float(flagged.mean()),
            "domain_groups": len(domain_frame),
            "domains_with_any_flag": int(domain_frame["flagged_urls"].gt(0).sum()),
            "domains_with_all_flagged": int(
                domain_frame["flagged_urls"].eq(domain_frame["urls"]).sum()
            ),
            "domain_macro_flag_rate": float(domain_frame["flag_rate"].mean()),
            "threshold": threshold,
        })
        artifact_provenance.append({
            "variant": variant,
            "artifact_path": str(artifact_path),
            "artifact_sha256": file_sha256(artifact_path),
            "report_sha256": file_sha256(report_path),
            "diagnostic_csv_sha256": file_sha256(diagnostic_path),
            "feature_representation": representation,
            "legacy_representation_inferred": (
                "feature_representation" not in artifact
            ),
            "saved_diagnostics_reproduced": True,
            "feature_names": names,
        })

    summary = pd.DataFrame(summaries)
    output.mkdir(parents=True, exist_ok=False)
    summary.to_csv(output / "summary.csv", index=False)
    pd.concat(predictions, ignore_index=True).to_csv(
        output / "predictions.csv", index=False
    )
    pd.concat(domain_results, ignore_index=True).to_csv(
        output / "domain_results.csv", index=False
    )
    run_manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "challenge_csv_sha256": file_sha256(csv_path),
        "challenge_manifest_sha256": file_sha256(manifest_path),
        "scorer_sha256": file_sha256(Path(__file__)),
        "production_features_sha256": file_sha256(
            Path("sentinelti/ml/features.py")
        ),
        "experimental_features_sha256": file_sha256(
            Path("sentinelti/ml/experimental_features.py")
        ),
        "artifacts": artifact_provenance,
        "interpretation": (
            "Exploratory flag rates against historical benign source labels; "
            "not current-safety verification, malicious recall, or root-only evaluation."
        ),
        "summary": summaries,
    }
    (output / "run_manifest.json").write_text(
        json.dumps(run_manifest, indent=2), encoding="utf-8"
    )

    display = summary.copy()
    for column in ("url_flag_rate", "domain_macro_flag_rate"):
        display[column] = display[column].map(lambda value: f"{100 * value:.2f}%")
    print("\nHistorical benign HTTP/apex-path challenge:")
    print(display.to_string(index=False))
    print(f"\nReports saved to: {output}")
    print("No training performed. No URLs visited. Input files unchanged.")


if __name__ == "__main__":
    main()