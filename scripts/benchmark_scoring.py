from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import numpy as np

from sentinelti.heuristics import analyze_url
from sentinelti.ml.predict import _build_feature_vector, load_model
from sentinelti.scoring import enrich_score


DEFAULT_URLS = [
    "https://www.google.com",
    "https://github.com/login",
    "https://example.com",
    "http://192.0.2.10/login/verify-account",
    "https://secure-paypal-login.example/verify",
    "https://accounts-microsoft-security.example.com/login",
    "https://normal.example.org/products/item?id=123",
    "http://203.0.113.66/verify/account",
]


def percentile(values: list[float], percentile_value: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=float), percentile_value))


def summarize(values_ms: list[float]) -> dict[str, float]:
    return {
        "count": len(values_ms),
        "mean_ms": round(statistics.mean(values_ms), 3),
        "median_ms": round(statistics.median(values_ms), 3),
        "p95_ms": round(percentile(values_ms, 95), 3),
        "p99_ms": round(percentile(values_ms, 99), 3),
        "min_ms": round(min(values_ms), 3),
        "max_ms": round(max(values_ms), 3),
        "throughput_urls_per_sec": round(
            1000 / statistics.mean(values_ms), 2
        ),
    }


def time_calls(fn: Callable[[str], object], urls: list[str], iterations: int) -> list[float]:
    durations_ms: list[float] = []

    for index in range(iterations):
        url = urls[index % len(urls)]
        start = time.perf_counter()
        fn(url)
        durations_ms.append((time.perf_counter() - start) * 1000)

    return durations_ms


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark SentinelTI deterministic scoring."
    )
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=25)
    parser.add_argument(
        "--output",
        default="docs/model_metrics/benchmark_scoring.json",
        help="JSON path for benchmark results.",
    )
    args = parser.parse_args()

    if args.iterations < 1 or args.warmup < 0:
        raise SystemExit("--iterations must be >= 1 and --warmup must be >= 0")

    model, feature_names, metadata = load_model(prefer="xgb")

    def warm_core_score(url: str) -> float:
        vector = _build_feature_vector(url, feature_names)
        probability = float(model.predict_proba(vector)[0][1])
        analyze_url(url)
        return probability

    for index in range(args.warmup):
        url = DEFAULT_URLS[index % len(DEFAULT_URLS)]
        warm_core_score(url)
        enrich_score(url)

    core_ms = time_calls(warm_core_score, DEFAULT_URLS, args.iterations)
    enriched_ms = time_calls(enrich_score, DEFAULT_URLS, args.iterations)

    payload = {
        "benchmark_name": "sentinelti_deterministic_scoring",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "model_type": metadata.get("model_type"),
            "feature_version": metadata.get("feature_version"),
            "threshold": metadata.get("threshold"),
            "iterations": args.iterations,
            "warmup_iterations": args.warmup,
            "url_count": len(DEFAULT_URLS),
            "ai_included": False,
            "notes": [
                "core_score includes feature extraction, XGBoost predict_proba, and heuristics",
                "enrich_score includes ML scoring, heuristics, DNS resolution, local reputation checks, decision fusion, and deterministic explanation generation",
                "network-dependent DNS behavior can affect end-to-end results",
            ],
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor() or "not reported",
        },
        "results": {
            "warm_core_score": summarize(core_ms),
            "end_to_end_enrich_score": summarize(enriched_ms),
        },
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(json.dumps(payload, indent=2))
    print(f"\nSaved benchmark results to: {output_path}")


if __name__ == "__main__":
    main()