"""Audit local supplemental records without modifying training data."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import tldextract

from sentinelti.ml.supplemental_data import FIELDS, validate_records
from sentinelti.ml.train_candidates import (
    DIAGNOSTIC_DOMAINS,
    domain_group,
    normalize_candidate_url,
    url_subgroup,
)


def read_csv(path, required, exact=False):
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames or []
        if len(headers) != len(set(headers)):
            raise ValueError(f"{path}: duplicate CSV headers")
        if not set(required).issubset(headers):
            raise ValueError(f"{path}: missing required CSV headers")
        if exact and set(headers) != set(required):
            raise ValueError(f"{path}: unexpected CSV headers")
        rows = list(reader)
        if any(
            None in row or any(value is None for value in row.values())
            for row in rows
        ):
            raise ValueError(f"{path}: malformed CSV row")
        return rows


def audit(supplemental, original, manifest):
    records = validate_records(read_csv(supplemental, FIELDS, exact=True))
    suffixes = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )

    partitions = {}
    for row in read_csv(manifest, ("group", "partition")):
        group, partition = row["group"], row["partition"]
        if not group or partition not in {"train", "test"}:
            raise ValueError("Invalid split manifest entry")
        if group in partitions:
            raise ValueError("Duplicate group in split manifest")
        partitions[group] = partition

    base_labels = {}
    base_counts = Counter()
    for row in read_csv(original, ("url", "label")):
        base_counts["rows"] += 1
        if row["label"] not in {"benign", "malicious"}:
            base_counts["unsupported_label_rows"] += 1
            continue
        normalized = normalize_candidate_url(row["url"])
        if normalized is None:
            base_counts["invalid_url_rows"] += 1
            continue
        base_labels.setdefault(normalized, set()).add(row["label"])

    findings = Counter()
    coverage = Counter()
    domain_overlap = Counter()
    seen = {}
    for record in records:
        normalized = normalize_candidate_url(record["url"])
        if normalized is None:
            raise ValueError("Supplemental URL failed candidate normalization")

        if normalized in seen:
            key = (
                "normalized_label_conflicts"
                if seen[normalized] != record["label"]
                else "normalized_duplicates"
            )
            findings[key] += 1
        else:
            seen[normalized] = record["label"]

        labels = base_labels.get(normalized, set())
        if labels:
            findings["original_url_overlap_rows"] += 1
            if labels - {record["label"]}:
                findings["original_label_conflict_rows"] += 1

        group = domain_group(normalized, suffixes)
        domain_overlap[partitions.get(group, "unseen")] += 1
        if group in DIAGNOSTIC_DOMAINS:
            findings["diagnostic_domain_rows"] += 1

        scheme, host_type = url_subgroup(normalized, suffixes)
        coverage[f"{record['label']}:{scheme}_{host_type}"] += 1

    blocking_keys = (
        "normalized_label_conflicts",
        "original_label_conflict_rows",
    )
    review_keys = (
        "normalized_duplicates",
        "original_url_overlap_rows",
        "diagnostic_domain_rows",
    )
    if not records:
        status = "empty"
    elif any(findings[key] for key in blocking_keys):
        status = "blocked"
    elif (
        any(findings[key] for key in review_keys)
        or domain_overlap["test"]
    ):
        status = "review_required"
    else:
        status = "checks_passed"

    return {
        "schema_version": 1,
        "status": status,
        "training_authorized": False,
        "supplemental_rows": len(records),
        "original": {
            "rows": base_counts["rows"],
            "unsupported_label_rows": base_counts["unsupported_label_rows"],
            "invalid_url_rows": base_counts["invalid_url_rows"],
            "normalized_conflicting_urls": sum(
                len(labels) > 1 for labels in base_labels.values()
            ),
        },
        "findings": {
            key: findings[key]
            for key in blocking_keys + review_keys
        },
        "coverage_rows": dict(sorted(coverage.items())),
        "manifest_domain_overlap_rows": {
            key: domain_overlap[key]
            for key in ("train", "test", "unseen")
        },
        "limitations": [
            "Evidence and label truth are not independently verified.",
            "Coverage counts are rows, not distinct domains.",
            "Existing test-domain overlap requires an explicit partition decision.",
            "Passing this audit does not authorize training or model promotion.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--supplemental-csv", required=True)
    parser.add_argument("--original-csv", required=True)
    parser.add_argument("--split-manifest", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    output = Path(args.output_json)
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")

    report = audit(
        args.supplemental_csv,
        args.original_csv,
        args.split_manifest,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")

    print(json.dumps(report, indent=2))
    return 2 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
