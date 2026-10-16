from __future__ import annotations

import logging
import os
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
from ..ml import predict

LOCAL_DEVELOPMENT_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "SENTINELTI_CORS_ORIGINS",
        ",".join(LOCAL_DEVELOPMENT_ORIGINS),
    ).split(",")
    if origin.strip()
]
MAX_REQUEST_BODY_BYTES = 128 * 1024

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
        method = request.method
        path = request.url.path

        logger.info("Request: %s %s", method, path)
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Error handling request: %s %s", method, path)
            raise

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "Response: %s %s -> %s in %sms",
            method,
            path,
            response.status_code,
            duration_ms,
        )
        return response


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int = MAX_REQUEST_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_content_length = headers.get(b"content-length")
        if raw_content_length:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
                await response(scope, receive, send)
                return
            if content_length < 0 or content_length > self.max_bytes:
                await self._too_large(scope, receive, send)
                return

        messages = []
        total_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            total_bytes += len(message.get("body", b""))
            if total_bytes > self.max_bytes:
                await self._too_large(scope, receive, send)
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive():
            nonlocal message_index
            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    async def _too_large(self, scope, receive, send):
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body exceeds the allowed size."},
        )
        await response(scope, receive, send)


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
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["Content-Type", "X-API-KEY"],
)

app.add_middleware(RequestBodyLimitMiddleware)
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

    uvicorn.run(
        "sentinelti.api.app:app",
        host=os.getenv("SENTINELTI_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )