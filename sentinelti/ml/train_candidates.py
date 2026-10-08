from __future__ import annotations

import argparse
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

THRESHOLD = 0.75
PREPROCESSING = "http-empty-path-to-root-v1"
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv-path", default="data/urldata.csv")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=False)

    suffixes = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )
    df = pd.read_csv(args.csv_path, usecols=["url", "label"])
    df = df[df["label"].isin(["benign", "malicious"])].copy()
    original_rows = len(df)
    df["normalized_url"] = df["url"].map(normalize_candidate_url)
    df = df.dropna(subset=["normalized_url"]).copy()
    invalid_rows = original_rows - len(df)

    conflicts = df.groupby("normalized_url")["label"].nunique()
    if conflicts.gt(1).any():
        raise ValueError(
            "Conflicting labels after normalization; investigate before training."
        )

    before_dedup = len(df)
    df = df.drop_duplicates("normalized_url").copy()
    deduplicated_rows = before_dedup - len(df)

    def domain_group(url: str) -> str:
        host = urlsplit(url).hostname or ""
        result = suffixes(host)
        return result.top_domain_under_public_suffix or host.lower()

    df["group"] = df["normalized_url"].map(domain_group)
    excluded_rows = int(df["group"].isin(DIAGNOSTIC_DOMAINS).sum())
    df = df[~df["group"].isin(DIAGNOSTIC_DOMAINS)].reset_index(drop=True)
    df["y"] = df["label"].map({"benign": 0, "malicious": 1})

    splitter = GroupShuffleSplit(
        n_splits=1, test_size=0.30, random_state=42
    )
    train_index, test_index = next(
        splitter.split(df, df["y"], groups=df["group"])
    )
    train_groups = set(df.iloc[train_index]["group"])
    test_groups = set(df.iloc[test_index]["group"])
    assert train_groups.isdisjoint(test_groups)

    y = df["y"].to_numpy()
    y_train, y_test = y[train_index], y[test_index]
    if len(np.unique(y_train)) != 2 or len(np.unique(y_test)) != 2:
        raise ValueError("Both classes must be present in each partition.")

    print(f"Extracting features for {len(df):,} URLs...", flush=True)
    dictionaries = [
        extract_features(url) for url in df["normalized_url"]
    ]
    names = [name for name in dictionaries[0] if not name.startswith("_")]
    X = np.asarray(
        [[features[name] for name in names] for features in dictionaries],
        dtype=float,
    )
    del dictionaries

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "csv_path": args.csv_path,
        "preprocessing": PREPROCESSING,
        "threshold": THRESHOLD,
        "invalid_rows": invalid_rows,
        "deduplicated_rows": deduplicated_rows,
        "diagnostic_domain_rows_excluded": excluded_rows,
        "train_rows": len(train_index),
        "test_rows": len(test_index),
        "train_groups": len(train_groups),
        "test_groups": len(test_groups),
        "group_overlap": 0,
        "split_seed": 42,
    }
    pd.DataFrame({
        "group": sorted(train_groups | test_groups),
    }).assign(
        partition=lambda frame: frame["group"].map(
            lambda group: "train" if group in train_groups else "test"
        )
    ).to_csv(output / "split_groups.csv", index=False)

    test_urls = df.iloc[test_index]["normalized_url"]
    schemes = test_urls.map(lambda url: urlsplit(url).scheme.lower()).to_numpy()
    host_types = test_urls.map(
        lambda url: "subdomain"
        if suffixes(urlsplit(url).hostname or "").subdomain
        else "apex"
    ).to_numpy()
    summaries = []

    for variant in ("full", "no_scheme"):
        selected = [
            index for index, name in enumerate(names)
            if variant == "full" or name not in {"is_http", "is_https"}
        ]
        candidate_names = [names[index] for index in selected]
        model = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="binary:logistic",
            eval_metric="logloss",
            scale_pos_weight=float((y_train == 0).sum() / (y_train == 1).sum()),
            n_jobs=-1,
            random_state=42,
        )
        print(f"Training {variant}...", flush=True)
        model.fit(X[train_index][:, selected], y_train)
        probabilities = model.predict_proba(X[test_index][:, selected])[:, 1]

        report = {
            **manifest,
            "variant": variant,
            "feature_names": candidate_names,
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
                    report["slices"][f"{scheme}_{host_type}"] = slice_metrics(
                        y_test[mask], probabilities[mask]
                    )

        diagnostics = []
        for domain in sorted(DIAGNOSTIC_DOMAINS):
            for prefix in ("", "www."):
                url = f"https://{prefix}{domain}/"
                features = extract_features(normalize_candidate_url(url))
                vector = np.asarray(
                    [[features[name] for name in candidate_names]],
                    dtype=float,
                )
                diagnostics.append({
                    "url": url,
                    "prob_malicious": float(model.predict_proba(vector)[0, 1]),
                })

        pd.DataFrame(diagnostics).to_csv(
            output / f"{variant}_diagnostics.csv", index=False
        )
        (output / f"{variant}_metrics.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        joblib.dump({
            "candidate_only": True,
            "model": model,
            "feature_names": candidate_names,
            "preprocessing": PREPROCESSING,
            "threshold": THRESHOLD,
            "variant": variant,
        }, output / f"{variant}_candidate.joblib")

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