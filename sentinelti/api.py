from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
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

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST_DIR = BASE_DIR / "frontend" / "dist"


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


class ModelTopFeature(BaseModel):
    feature: str
    importance: float


class ModelMetadataResponse(BaseModel):
    artifact_version: str | None = None
    model_type: str
    trained_at: str | None = None
    dataset_name: str | None = None
    dataset_source: Dict[str, Any] = Field(default_factory=dict)
    feature_version: str | None = None
    threshold: float
    threshold_source: Literal["metadata", "env", "default"] | None = None
    recommended_threshold: float | None = None
    recommended_threshold_source: str | None = None
    metrics: ModelMetricsSummary = Field(default_factory=ModelMetricsSummary)
    class_labels: ModelClassLabels = Field(default_factory=ModelClassLabels)
    class_counts: ModelClassCounts = Field(default_factory=ModelClassCounts)
    training_params: Dict[str, Any] = Field(default_factory=dict)
    training_notes: List[str] = Field(default_factory=list)
    top_features: List[ModelTopFeature] = Field(default_factory=list)
    artifact_path: str | None = None


class ExplanationResponse(BaseModel):
    summary: str
    why_flagged: str
    user_action: str
    technical_notes: List[str] = Field(default_factory=list)
    risk: Literal["low", "medium", "high"]
    final_label: Literal["benign", "suspicious", "malicious"]


class ModelInfoResponse(BaseModel):
    schema_version: Literal["1.1"] = "1.1"
    model_meta: ModelMetadataResponse


class ScoreResponse(BaseModel):
    schema_version: Literal["1.2"] = "1.2"
    url: str
    label: int
    prob_malicious: float
    threshold: float
    heuristic: HeuristicResult
    final_label: Literal["benign", "suspicious", "malicious"]
    risk: Literal["low", "medium", "high"]
    reasons: List[str]
    explanation: ExplanationResponse
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

        logger.info("Request: %s %s from %s", method, path, client_ip)
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Error handling request: %s %s from %s", method, path, client_ip)
            raise

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "Response: %s %s -> %s to %s in %sms",
            method,
            path,
            response.status_code,
            client_ip,
            duration_ms,
        )
        return response


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except (HTTPException, StarletteHTTPException) as ex:
            if ex.status_code == 404:
                return await super().get_response("index.html", scope)
            raise ex


def _coerce_top_features(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []

    cleaned: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        feature = item.get("feature")
        importance = item.get("importance")
        if feature is None or importance is None:
            continue
        try:
            cleaned.append(
                {
                    "feature": str(feature),
                    "importance": float(importance),
                }
            )
        except (TypeError, ValueError):
            continue
    return cleaned


def _coerce_training_notes(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    cleaned: list[str] = []
    for item in raw:
        if item is None:
            continue
        text = str(item).strip()
        if text:
            cleaned.append(text)
    return cleaned


def _build_model_meta() -> Dict[str, Any]:
    metadata = get_loaded_model_metadata()
    metrics = metadata.get("metrics", {}) or {}

    threshold = float(metadata.get("threshold", 0.75))
    threshold_source = metadata.get("threshold_source")
    if threshold_source not in ("metadata", "env", "default"):
        threshold_source = "metadata"

    return {
        "artifact_version": metadata.get("artifact_version"),
        "model_type": metadata.get("model_type", "unknown"),
        "trained_at": metadata.get("trained_at"),
        "dataset_name": metadata.get("dataset_name"),
        "dataset_source": metadata.get("dataset_source", {}),
        "feature_version": metadata.get("feature_version"),
        "threshold": threshold,
        "threshold_source": threshold_source,
        "recommended_threshold": metadata.get("recommended_threshold"),
        "recommended_threshold_source": metadata.get("recommended_threshold_source"),
        "metrics": {
            "roc_auc": metrics.get("roc_auc"),
            "average_precision": metrics.get("average_precision"),
        },
        "class_labels": metadata.get("class_labels", {}),
        "class_counts": metadata.get("class_counts", {}),
        "training_params": metadata.get("training_params", {}),
        "training_notes": _coerce_training_notes(
            metadata.get("training_notes", metrics.get("training_notes", []))
        ),
        "top_features": _coerce_top_features(
            metadata.get("top_features", metadata.get("top_feature_importance", []))
        ),
        "artifact_path": metadata.get("artifact_path"),
    }


def _build_score_response(url: str) -> Dict[str, Any]:
    result = enrich_score(url)
    model_meta = _build_model_meta()

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


app = FastAPI(title="SentinelTI", version="0.1.0")


@app.exception_handler(RuntimeError)
async def runtime_error_handler(request: Request, exc: RuntimeError):
    logger.exception(
        "Runtime error while handling %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal scoring error",
            "error_type": "runtime_error",
        },
    )


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
        "schema_version": "1.1",
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


@app.post(
    "/explain-score",
    response_model=ExplanationResponse,
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def explain_score(body: ScoreUrlRequest):
    result = enrich_score(body.url)
    return result["explanation"]


if FRONTEND_DIST_DIR.exists():
    app.mount(
        "/",
        SPAStaticFiles(directory=str(FRONTEND_DIST_DIR), html=True),
        name="frontend",
    )
else:
    logger.info("Frontend dist not found at %s; serving API only.", FRONTEND_DIST_DIR)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sentinelti.api:app", host="0.0.0.0", port=8000, reload=True)