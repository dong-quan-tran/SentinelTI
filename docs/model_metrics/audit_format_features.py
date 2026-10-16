from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only audit of feature changes caused by HTTP/HTTPS "
            "and apex/www URL transformations."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        required=True,
        help="Path to the SentinelTI repository.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()

    required_files = [
        repo_root / "sentinelti" / "ml" / "features.py",
        repo_root / "sentinelti" / "ml" / "train_candidates.py",
    ]
    for path in required_files:
        if not path.is_file():
            raise FileNotFoundError(f"Required file not found: {path}")

    sys.path.insert(0, str(repo_root))

    from sentinelti.ml.features import extract_features
    from sentinelti.ml.train_candidates import (
        DIAGNOSTIC_DOMAINS,
        normalize_candidate_url,
        selected_feature_indices,
    )

    def numeric_features(url: str) -> dict[str, float]:
        normalized = normalize_candidate_url(url)
        if normalized is None:
            raise ValueError(f"Invalid audit URL: {url}")

        extracted = extract_features(normalized)
        return {
            name: float(value)
            for name, value in extracted.items()
            if not name.startswith("_")
        }

    def compare(before_url: str, after_url: str) -> list[dict]:
        before = numeric_features(before_url)
        after = numeric_features(after_url)

        if list(before) != list(after):
            raise ValueError("Feature names or ordering changed between URLs.")

        names = list(before)
        retained_indices = selected_feature_indices(names, "no_scheme")
        retained_names = {names[index] for index in retained_indices}

        changes = []
        for name in names:
            before_value = before[name]
            after_value = after[name]

            if not (
                math.isfinite(before_value)
                and math.isfinite(after_value)
            ):
                raise ValueError(f"Nonfinite feature value: {name}")

            if before_value != after_value:
                changes.append({
                    "feature": name,
                    "before": before_value,
                    "after": after_value,
                    "delta": after_value - before_value,
                    "retained": name in retained_names,
                })

        return changes

    domains = sorted(DIAGNOSTIC_DOMAINS)

    def pairs_for(domain: str, suffix: str) -> dict[str, tuple[str, str]]:
        return {
            "scheme_apex": (
                f"http://{domain}{suffix}",
                f"https://{domain}{suffix}",
            ),
            "scheme_www": (
                f"http://www.{domain}{suffix}",
                f"https://www.{domain}{suffix}",
            ),
            "www_http": (
                f"http://{domain}{suffix}",
                f"http://www.{domain}{suffix}",
            ),
            "www_https": (
                f"https://{domain}{suffix}",
                f"https://www.{domain}{suffix}",
            ),
        }

    print("READ-ONLY FORMAT FEATURE AUDIT")
    print(f"Repository: {repo_root}")
    print("Uses current local feature and normalization functions.")
    print("No network requests, model loading, training, or file writes.")
    print(
        "Changed inputs identify format sensitivity, "
        "not causal model-feature importance."
    )

    for transformation in (
        "scheme_apex",
        "scheme_www",
        "www_http",
        "www_https",
    ):
        changed_counts = Counter()
        retained_counts = Counter()
        minimum_deltas = {}
        maximum_deltas = {}

        for domain in domains:
            before_url, after_url = pairs_for(domain, "/")[transformation]
            for change in compare(before_url, after_url):
                name = change["feature"]
                delta = change["delta"]

                changed_counts[name] += 1
                if change["retained"]:
                    retained_counts[name] += 1

                minimum_deltas[name] = min(
                    minimum_deltas.get(name, delta),
                    delta,
                )
                maximum_deltas[name] = max(
                    maximum_deltas.get(name, delta),
                    delta,
                )

        print(f"\n{'=' * 88}")
        print(f"ROOT-URL TRANSFORMATION: {transformation}")
        print(f"Domain pairs audited: {len(domains)}")
        print(
            f"{'feature':28} {'changed':>9} {'retained':>10} "
            f"{'min delta':>16} {'max delta':>16}"
        )

        for name in sorted(changed_counts):
            print(
                f"{name:28} "
                f"{changed_counts[name]:>5}/{len(domains):<3} "
                f"{('yes' if retained_counts[name] else 'no'):>10} "
                f"{minimum_deltas[name]:>16.9g} "
                f"{maximum_deltas[name]:>16.9g}"
            )

    detailed_cases = [
        (
            "ROOT: HTTP -> HTTPS, apex",
            "http://google.com/",
            "https://google.com/",
        ),
        (
            "ROOT: HTTP -> HTTPS, www",
            "http://www.google.com/",
            "https://www.google.com/",
        ),
        (
            "ROOT: apex -> www, HTTPS",
            "https://google.com/",
            "https://www.google.com/",
        ),
        (
            "PATH/QUERY: HTTP -> HTTPS, apex",
            "http://google.com/articles/item42?lang=en",
            "https://google.com/articles/item42?lang=en",
        ),
    ]

    for title, before_url, after_url in detailed_cases:
        changes = compare(before_url, after_url)

        print(f"\n{'=' * 88}")
        print(title)
        print(f"Before: {before_url}")
        print(f"After:  {after_url}")
        print(
            f"{'feature':28} {'before':>14} {'after':>14} "
            f"{'delta':>14} {'no_scheme':>11}"
        )

        for change in changes:
            print(
                f"{change['feature']:28} "
                f"{change['before']:>14.9g} "
                f"{change['after']:>14.9g} "
                f"{change['delta']:>14.9g} "
                f"{('retained' if change['retained'] else 'removed'):>11}"
            )

        print(
            "Changed retained features:",
            sum(change["retained"] for change in changes),
        )

    print("\nAudit complete. No files were changed.")


if __name__ == "__main__":
    main()