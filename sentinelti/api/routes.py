from __future__ import annotations

from typing import List

from fastapi import APIRouter, Body, Depends, status
from fastapi.responses import JSONResponse

from .dependencies import check_rate_limit, require_api_key
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
from ..services.ai_score_service import (
    AIEndpointDisabledError,
    build_ai_explanation_response,
)
from ..services.scoring_service import (
    build_explanation_response,
    build_model_meta_response,
    build_score_response,
)

router = APIRouter()


def _build_ai_explain_public_response(result: dict) -> dict:
    deterministic = result.get("deterministic_explanation") or result.get("explanation") or {}
    ai_block = result.get("ai") or {}

    if not ai_block:
        ai_summary = result.get("ai_summary") or result.get("ai_explanation_text") or ""
        ai_guidance = result.get("ai_guidance") or deterministic.get("user_action") or ""
        ai_block = {
            "summary": ai_summary,
            "guidance": ai_guidance,
        }

    return {
        "deterministic_explanation": {
            "summary": deterministic.get("summary", ""),
            "why_flagged": deterministic.get("why_flagged", ""),
            "user_action": deterministic.get("user_action", ""),
            "technical_notes": deterministic.get("technical_notes", []),
            "risk": deterministic.get("risk", "low"),
            "final_label": deterministic.get("final_label", "benign"),
        },
        "ai": {
            "summary": ai_block.get("summary", ""),
            "guidance": ai_block.get("guidance", ""),
        },
    }


@router.get("/health", tags=["health"], summary="Health check")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@router.get(
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


@router.post(
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


@router.post(
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


@router.post(
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


@router.get(
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


@router.post(
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
    if not ai_explanations.ai_enabled():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": "AI explanations are currently disabled.",
                "error_type": "ai_disabled",
            },
        )

    try:
        result = build_ai_explanation_response(body.url, ai_model=body.ai_model)
        return _build_ai_explain_public_response(result)
    except AIEndpointDisabledError as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "detail": str(exc),
                "error_type": "ai_disabled",
            },
        )