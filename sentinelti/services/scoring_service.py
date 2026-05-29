from __future__ import annotations

from typing import Any, Dict

from sentinelti import scoring
from sentinelti.ml import predict
from sentinelti.services import model_metadata


def build_model_meta_response() -> Dict[str, Any]:
    metadata = predict.get_loaded_model_metadata()
    return model_metadata.build_model_meta(metadata)


def build_score_response(url: str) -> Dict[str, Any]:
    result = scoring.enrich_score(url)
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
    result = scoring.enrich_score(url)
    return result["explanation"]