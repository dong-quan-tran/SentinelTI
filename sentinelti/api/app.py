from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from .dependencies import API_KEY, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW, _rate_limit_store
from .routes import router
from ..services.ai_explanations import AIExplanationError, AIModelNotAvailableError

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

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST_DIR = BASE_DIR / "frontend" / "dist"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import time

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
        {"name": "health", "description": "Basic health and readiness checks."},
        {"name": "model-info", "description": "Model metadata, thresholds, and training summary."},
        {"name": "scoring", "description": "Deterministic URL scoring and explanations."},
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
        status_code=500,
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
        status_code=422,
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
        status_code=500,
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
app.include_router(router)


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