from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware

from .ml.predict import get_loaded_model_metadata
from .scoring import enrich_score


origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("sentinelti.api")


RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW = 60
_rate_limit_store: dict[str, list[float]] = {}


async def check_rate_limit(request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    timestamps = _rate_limit_store.get(client_ip, [])
    timestamps = [t for t in timestamps if t > window_start]

    used = len(timestamps)
    remaining = max(RATE_LIMIT_REQUESTS - used, 0)

    if used >= RATE_LIMIT_REQUESTS:
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = "0"
        response.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )

    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps

    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Remaining"] = str(remaining - 1 if remaining > 0 else 0)
    response.headers["X-RateLimit-Reset"] = str(int(window_start + RATE_LIMIT_WINDOW - now))


class HeuristicResult(BaseModel):
    score: float
    reasons: List[str]


class ModelMetricsSummary(BaseModel):
    roc_auc: float | None = None
    average_precision: float | None = None


class ModelClassLabels(BaseModel):
    benign: int | None = None
    malicious: int | None = None


class ModelClassCounts(BaseModel):
    train_0: int | None = None
    train_1: int | None = None
    test_0: int | None = None
    test_1: int | None = None


class ModelMetadataResponse(BaseModel):
    artifact_version: str | None = None
    model_type: str
    trained_at: str | None = None
    dataset_name: str | None = None
    dataset_source: Dict[str, Any] = Field(default_factory=dict)
    feature_version: str | None = None
    threshold: float
    metrics: ModelMetricsSummary = Field(default_factory=ModelMetricsSummary)
    class_labels: ModelClassLabels = Field(default_factory=ModelClassLabels)
    class_counts: ModelClassCounts = Field(default_factory=ModelClassCounts)
    training_params: Dict[str, Any] = Field(default_factory=dict)
    artifact_path: str | None = None


class ModelInfoResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    model_meta: ModelMetadataResponse


class ScoreResponse(BaseModel):
    schema_version: Literal["1.1"] = "1.1"
    url: str
    label: int
    prob_malicious: float
    threshold: float
    heuristic: HeuristicResult
    final_label: Literal["benign", "suspicious", "malicious"]
    risk: Literal["low", "medium", "high"]
    reasons: List[str]
    model_meta: ModelMetadataResponse


class ScoreUrlRequest(BaseModel):
    url: str = Field(
        ...,
        examples=["https://example.com"],
        description="URL to score",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"url": "https://example.com"},
                {"url": "https://phishy.example/login"},
            ]
        }
    )


class ScoreUrlsRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        examples=[
            "https://example.com",
            "https://phishy.example/login",
        ],
        description="List of URLs to score",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "urls": [
                        "https://example.com",
                        "https://phishy.example/login",
                    ]
                }
            ]
        }
    )


class ScoreUrlsResponse(BaseModel):
    results: List[ScoreResponse]


API_KEY_NAME = "X-API-KEY"
API_KEY = os.getenv("SENTINELTI_API_KEY", "change-me")

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def require_api_key(api_key: str | None = Depends(api_key_header)):
    if api_key is None or api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path

        logger.info(f"Request: {method} {path} from {client_ip}")
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(f"Error handling request: {method} {path} from {client_ip}")
            raise

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            f"Response: {method} {path} -> {response.status_code} "
            f"to {client_ip} in {duration_ms}ms"
        )
        return response


def _build_model_meta() -> Dict[str, Any]:
    metadata = get_loaded_model_metadata()
    metrics = metadata.get("metrics", {}) or {}

    return {
        "artifact_version": metadata.get("artifact_version"),
        "model_type": metadata.get("model_type", "unknown"),
        "trained_at": metadata.get("trained_at"),
        "dataset_name": metadata.get("dataset_name"),
        "dataset_source": metadata.get("dataset_source", {}),
        "feature_version": metadata.get("feature_version"),
        "threshold": float(metadata.get("threshold", 0.75)),
        "metrics": {
            "roc_auc": metrics.get("roc_auc"),
            "average_precision": metrics.get("average_precision"),
        },
        "class_labels": metadata.get("class_labels", {}),
        "class_counts": metadata.get("class_counts", {}),
        "training_params": metadata.get("training_params", {}),
        "artifact_path": metadata.get("artifact_path"),
    }


def _build_score_response(url: str) -> Dict[str, Any]:
    result = enrich_score(url)
    model_meta = _build_model_meta()

    return {
        "schema_version": "1.1",
        "url": result["url"],
        "label": result["label"],
        "prob_malicious": result["prob_malicious"],
        "threshold": model_meta["threshold"],
        "heuristic": result["heuristic"],
        "final_label": result["final_label"],
        "risk": result["risk"],
        "reasons": result["reasons"],
        "model_meta": model_meta,
    }


app = FastAPI(title="SentinelTI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestLoggingMiddleware)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get(
    "/model-info",
    response_model=ModelInfoResponse,
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def model_info():
    return {
        "schema_version": "1.0",
        "model_meta": _build_model_meta(),
    }


@app.post(
    "/score-url",
    response_model=ScoreResponse,
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def score_url(body: ScoreUrlRequest):
    return _build_score_response(body.url)


@app.post(
    "/score-urls",
    response_model=ScoreUrlsResponse,
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def score_urls(body: ScoreUrlsRequest):
    return {"results": [_build_score_response(url) for url in body.urls]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sentinelti.api:app", host="0.0.0.0", port=8000, reload=True)