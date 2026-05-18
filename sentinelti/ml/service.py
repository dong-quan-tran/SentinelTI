from __future__ import annotations

from typing import Dict, List

from sentinelti.ml.predict import predict_url_with_metadata


def score_url(url: str) -> Dict[str, object]:
    result = predict_url_with_metadata(url)
    return {
        "url": url,
        "label": result["label"],
        "prob_malicious": result["prob_malicious"],
        "threshold": result["threshold"],
        "model_meta": result["model_meta"],
    }


def score_urls(urls: List[str]) -> List[Dict[str, object]]:
    return [score_url(u) for u in urls]