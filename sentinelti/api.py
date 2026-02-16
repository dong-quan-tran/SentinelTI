import os
import time
from typing import List, Literal, Dict, Any

import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from .scoring import enrich_score  # adjust import if needed


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("sentinelti.api")

# -------- Rate limiting (simple in-memory, per IP) --------

RATE_LIMIT_REQUESTS = 60   # allowed requests
RATE_LIMIT_WINDOW = 60     # window in seconds
_rate_limit_store: dict[str, list[float]] = {}


async def check_rate_limit(request: Request, response: Response):
    client_ip = request.client.host or "unknown"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    timestamps = _rate_limit_store.get(client_ip, [])
    # Keep only timestamps in the current window
    timestamps = [t for t in timestamps if t > window_start]

    used = len(timestamps)
    remaining = max(RATE_LIMIT_REQUESTS - used, 0)

    if used >= RATE_LIMIT_REQUESTS:
        # Over limit: set headers and raise
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = "0"
        response.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )

    # Allow request: record this call and set headers
    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps

    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Remaining"] = str(remaining - 1 if remaining > 0 else 0)
    # Optional: when the window resets (approx seconds until window end)
    response.headers["X-RateLimit-Reset"] = str(int(window_start + RATE_LIMIT_WINDOW - now))


# -------- Response models --------

class HeuristicResult(BaseModel):
    score: float
    reasons: List[str]


class ScoreResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    url: str
    label: int
    prob_malicious: float
    heuristic: HeuristicResult
    final_label: Literal["benign", "suspicious", "malicious"]
    risk: Literal["low", "medium", "high"]
    reasons: List[str]
    meta: Dict[str, Any] | None = None


class ScoreUrlRequest(BaseModel):
    url: str


class ScoreUrlsRequest(BaseModel):
    urls: List[str]


class ScoreUrlsResponse(BaseModel):
    results: List[ScoreResponse]


# -------- API key auth --------

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
        client_ip = request.client.host or "unknown"
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

# -------- FastAPI app & routes --------

app = FastAPI(title="SentinelTI", version="0.1.0")

app.add_middleware(RequestLoggingMiddleware)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post(
    "/score-url",
    response_model=ScoreResponse,
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def score_url(body: ScoreUrlRequest):
    result = enrich_score(body.url)
    result["schema_version"] = "1.0"
    result["meta"] = {"model": "xgb", "source": "kaggle+urlhaus"}
    return result


@app.post(
    "/score-urls",
    response_model=ScoreUrlsResponse,
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
async def score_urls(body: ScoreUrlsRequest):
    results: List[Dict[str, Any]] = []
    for url in body.urls:
        r = enrich_score(url)
        r["schema_version"] = "1.0"
        r["meta"] = {"model": "xgb", "source": "kaggle+urlhaus"}
        results.append(r)
    return {"results": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("sentinelti.api:app", host="0.0.0.0", port=8000, reload=True)
