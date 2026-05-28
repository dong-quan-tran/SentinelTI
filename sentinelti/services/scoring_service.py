from __future__ import annotations

from typing import Any, Dict

from sentinelti.ml.predict import get_loaded_model_metadata
from sentinelti.scoring import enrich_score
from sentinelti.services.model_metadata import build_model_meta


def build_model_meta_response() -> Dict[str, Any]:
    metadata = get_loaded_model_metadata()
    return build_model_meta(metadata)


def build_score_response(url: str) -> Dict[str, Any]:
    result = enrich_score(url)
    model_meta = build_model_meta_response()

    return {
        "schema_version": "1.2",
        "url": result["url"],
        "label": result["label"],
        "prob_malicious": result["prob_malicious"],
        "threshold": model_meta["threshold"],
        "heuristic": result["heuristic"],
        "final_label": result["final_label"],
        "risk": result["risk"],
        "reasons": result["reasons"],
        "explanation": result["explanation"],
        "model_meta": model_meta,
    }


def build_explanation_response(url: str) -> Dict[str, Any]:
    result = enrich_score(url)
    return result["explanation"]