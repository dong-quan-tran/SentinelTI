from __future__ import annotations

import os
import time

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import APIKeyHeader

def _positive_int_setting(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer.") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer.")
    return value


RATE_LIMIT_REQUESTS = _positive_int_setting(
    "SENTINELTI_RATE_LIMIT_REQUESTS",
    60,
)
RATE_LIMIT_WINDOW = _positive_int_setting(
    "SENTINELTI_RATE_LIMIT_WINDOW_SECONDS",
    60,
)
_rate_limit_store: dict[str, list[float]] = {}

API_KEY_NAME = "X-API-KEY"
API_KEY = os.getenv("SENTINELTI_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "SENTINELTI_API_KEY must be set before starting SentinelTI."
    )
if (
    os.getenv("SENTINELTI_ENV", "").lower() == "production"
    and len(API_KEY) < 32
):
    raise RuntimeError(
        "SENTINELTI_API_KEY must be at least 32 characters in production."
    )

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