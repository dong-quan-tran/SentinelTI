from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import List

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from .schemas import (
    AIExplainScoreRequest,
    AIExplainScoreResponse,
    AIModelsResponse,
    AI_EXPLAIN_SCORE_DISABLED_EXAMPLE,
    AI_EXPLAIN_SCORE_ERROR_EXAMPLE,
    AI_EXPLAIN_SCORE_MODEL_UNAVAILABLE_EXAMPLE,
    AI_EXPLAIN_SCORE_REQUEST_EXAMPLES,
    AI_EXPLAIN_SCORE_SUCCESS_EXAMPLE,
    ExplanationResponse,
    ModelInfoResponse,
    RateLimitErrorResponse,
    ScoreResponse,
    ScoreUrlRequest,
    ScoreUrlsRequest,
    ScoreUrlsResponse,
    ScoringErrorResponse,
    UnauthorizedErrorResponse,
)
from ..services import ai_explanations
from ..services.ai_explanations import AIExplanationError, AIModelNotAvailableError
from ..services.ai_score_service import (
    AIEndpointDisabledError,
    build_ai_explanation_response,
)
from ..services.scoring_service import (
    build_explanation_response,
    build_model_meta_response,
    build_score_response,
)

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

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST_DIR = BASE_DIR / "frontend" / "dist"

API_KEY_NAME = "X-API-KEY"
API_KEY = os.getenv("SENTINELTI_API_KEY", "change-me")

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def check_rate_limit(request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    timestamps = _rate_limit_store.get(client_ip, [])
    timestamps = [t for t in timestamps if t > window_start]

    used = len(timestamps)
    remaining = max(RATE_LIMIT_REQUESTS - used, 0)

    if used >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
            headers={
                "X-RateLimit-Limit": str(RATE_LIMIT_REQUESTS),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "0",
                "Retry-After": str(RATE_LIMIT_WINDOW),
            },
        )

    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps

    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Remaining"] = str(remaining - 1 if remaining > 0 else 0)
    response.headers["X-RateLimit-Reset"] = str(int(window_start + RATE_LIMIT_WINDOW - now))


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


app = FastAPI(
    title="SentinelTI",
    version="0.1.0",
    description="""
SentinelTI provides deterministic URL scoring, heuristic analysis, and optional AI-assisted explanations.

## Core behavior

- Deterministic scoring is the source of truth.
- AI-assisted explanations are optional and advisory only.
- AI output never changes the underlying score, threshold, risk, or final label.

## AI endpoints

- `POST /ai-explain-score` returns the deterministic explanation alongside a separate AI-generated rewrite.
- `GET /ai-models` returns the configured AI provider and available Ollama models when applicable.
- If AI is disabled, the AI explanation endpoint returns `503` with `error_type: "ai_disabled"`.
- If AI generation or model discovery fails, the endpoint returns `500` with `error_type: "ai_explanation_error"`.
""",
    openapi_tags=[
        {
            "name": "health",
            "description": "Basic health and readiness checks.",
        },
        {
            "name": "model-info",
            "description": "Model metadata, thresholds, and training summary.",
        },
        {
            "name": "scoring",
            "description": "Deterministic URL scoring and explanations.",
        },
        {
            "name": "ai",
            "description": (
                "Optional AI-assisted explanations that rewrite deterministic results "
                "in friendlier language. AI output is advisory only."
            ),
        },
    ],
)


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


@app.exception_handler(AIModelNotAvailableError)
async def ai_model_not_available_error_handler(request: Request, exc: AIModelNotAvailableError):
    logger.warning(
        "AI model unavailable while handling %s %s: %s",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "detail": str(exc),
            "error_type": "ai_model_unavailable",
        },
    )


@app.exception_handler(AIExplanationError)
async def ai_explanation_error_handler(request: Request, exc: AIExplanationError):
    logger.exception(
        "AI explanation error while handling %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": str(exc),
            "error_type": "ai_explanation_error",
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


@app.get("/health", tags=["health"], summary="Health check")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get(
    "/model-info",
    tags=["model-info"],
    summary="Get loaded model metadata",
    description=(
        "Returns normalized metadata for the currently loaded model, including "
        "the effective threshold, recommended threshold if available, metrics, "
        "top features, and a short model summary."
    ),
    response_model=ModelInfoResponse,
    responses={
        401: {
            "model": UnauthorizedErrorResponse,
            "description": "Missing or invalid API key.",
        },
        429: {
            "model": RateLimitErrorResponse,
            "description": "Too many requests from the same client.",
        },
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def model_info():
    return {
        "schema_version": "1.1",
        "model_meta": build_model_meta_response(),
    }


@app.post(
    "/score-url",
    tags=["scoring"],
    summary="Score a single URL",
    description=(
        "Runs deterministic URL scoring and heuristic analysis for one URL. "
        "Returns the raw model output, final label, risk, explanation, and "
        "normalized model metadata. This deterministic result is the source of truth."
    ),
    response_model=ScoreResponse,
    responses={
        401: {
            "model": UnauthorizedErrorResponse,
            "description": "Missing or invalid API key.",
        },
        422: {
            "description": "Validation error in the request body.",
        },
        429: {
            "model": RateLimitErrorResponse,
            "description": "Too many requests from the same client.",
        },
        500: {
            "model": ScoringErrorResponse,
            "description": "Internal scoring error while processing the URL.",
        },
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def score_url(body: ScoreUrlRequest):
    return build_score_response(body.url)


@app.post(
    "/score-urls",
    tags=["scoring"],
    summary="Score multiple URLs",
    description=(
        "Runs deterministic URL scoring for multiple URLs and returns a list of "
        "independent scoring results. Each result includes explanation and model metadata."
    ),
    response_model=ScoreUrlsResponse,
    responses={
        401: {
            "model": UnauthorizedErrorResponse,
            "description": "Missing or invalid API key.",
        },
        422: {
            "description": "Validation error in the request body.",
        },
        429: {
            "model": RateLimitErrorResponse,
            "description": "Too many requests from the same client.",
        },
        500: {
            "model": ScoringErrorResponse,
            "description": "Internal scoring error while processing one or more URLs.",
        },
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def score_urls(body: ScoreUrlsRequest):
    return {"results": [build_score_response(url) for url in body.urls]}


@app.post(
    "/explain-score",
    tags=["scoring"],
    summary="Get deterministic explanation for a URL",
    description=(
        "Returns only the deterministic explanation for a scored URL. "
        "This endpoint does not include the full score payload."
    ),
    response_model=ExplanationResponse,
    responses={
        401: {
            "model": UnauthorizedErrorResponse,
            "description": "Missing or invalid API key.",
        },
        422: {
            "description": "Validation error in the request body.",
        },
        429: {
            "model": RateLimitErrorResponse,
            "description": "Too many requests from the same client.",
        },
        500: {
            "model": ScoringErrorResponse,
            "description": "Internal scoring error while generating an explanation.",
        },
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def explain_score(body: ScoreUrlRequest):
    return build_explanation_response(body.url)


@app.get(
    "/ai-models",
    tags=["ai"],
    summary="List available AI models",
    description=(
        "Returns the current AI provider and the locally available AI models when "
        "using Ollama. This helps clients choose a valid ai_model override."
    ),
    response_model=AIModelsResponse,
    responses={
        401: {
            "model": UnauthorizedErrorResponse,
            "description": "Missing or invalid API key.",
        },
        429: {
            "model": RateLimitErrorResponse,
            "description": "Too many requests from the same client.",
        },
        500: {
            "model": ScoringErrorResponse,
            "description": "Internal error while listing AI models.",
        },
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def ai_models():
    provider_name = ai_explanations.get_ai_provider_name()
    default_model = None
    models: List[str] = []

    if provider_name == "ollama":
        default_model = ai_explanations.get_ollama_model()
        models = ai_explanations.list_ollama_models()

    return {
        "provider": provider_name,
        "default_model": default_model,
        "models": models,
    }


@app.post(
    "/ai-explain-score",
    tags=["ai"],
    summary="Generate an AI-assisted explanation",
    description=(
        "Returns the deterministic explanation alongside a separate AI-generated "
        "plain-language rewrite. Deterministic scoring remains the source of truth; "
        "AI output never changes the score, threshold, risk, or final label. "
        "An optional ai_model field can override the configured Ollama model."
    ),
    response_model=AIExplainScoreResponse,
    responses={
        200: {
            "description": "Deterministic explanation with an additional AI-generated rewrite.",
            "content": {
                "application/json": {
                    "example": AI_EXPLAIN_SCORE_SUCCESS_EXAMPLE,
                }
            },
        },
        401: {
            "model": UnauthorizedErrorResponse,
            "description": "Missing or invalid API key.",
        },
        422: {
            "model": ScoringErrorResponse,
            "description": (
                "Validation error in the request body, or the requested AI model "
                "is not available."
            ),
            "content": {
                "application/json": {
                    "example": AI_EXPLAIN_SCORE_MODEL_UNAVAILABLE_EXAMPLE,
                }
            },
        },
        429: {
            "model": RateLimitErrorResponse,
            "description": "Too many requests from the same client.",
        },
        500: {
            "model": ScoringErrorResponse,
            "description": "Internal error while generating AI-assisted explanation.",
            "content": {
                "application/json": {
                    "example": AI_EXPLAIN_SCORE_ERROR_EXAMPLE,
                }
            },
        },
        503: {
            "model": ScoringErrorResponse,
            "description": "AI-assisted explanations are currently disabled.",
            "content": {
                "application/json": {
                    "example": AI_EXPLAIN_SCORE_DISABLED_EXAMPLE,
                }
            },
        },
    },
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def ai_explain_score(
    body: AIExplainScoreRequest = Body(..., openapi_examples=AI_EXPLAIN_SCORE_REQUEST_EXAMPLES)
):
    try:
        return build_ai_explanation_response(body.url, ai_model=body.ai_model)
    except AIEndpointDisabledError as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": str(exc),
                "error_type": "ai_disabled",
            },
        )


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

    uvicorn.run("sentinelti.api.app:app", host="0.0.0.0", port=8000, reload=True)