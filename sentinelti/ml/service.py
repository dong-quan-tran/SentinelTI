from __future__ import annotations

from typing import Dict, List

from sentinelti.ml.predict import predict_url_with_model_info


def score_url(url: str) -> Dict[str, object]:
    label, prob_malicious, model_type = predict_url_with_model_info(url)
    return {
        "url": url,
        "label": label,
        "prob_malicious": prob_malicious,
        "model_type": model_type,
    }


def score_urls(urls: List[str]) -> List[Dict[str, object]]:
    return [score_url(u) for u in urls]