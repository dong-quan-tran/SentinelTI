from __future__ import annotations

from typing import Dict, List

from sentinelti.ml.predict import predict_url, get_malicious_threshold


def score_url(url: str) -> Dict[str, object]:
    label, prob_malicious = predict_url(url)
    return {
        "url": url,
        "label": label,
        "prob_malicious": prob_malicious,
        "threshold": get_malicious_threshold(),
    }


def score_urls(urls: List[str]) -> List[Dict[str, object]]:
    return [score_url(u) for u in urls]