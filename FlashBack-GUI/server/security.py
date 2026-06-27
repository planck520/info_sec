# coding: utf-8
"""Local API security helpers for FlashBack.

The desktop frontend receives a per-session token from the launcher.  Browser
pages that are not loaded by FlashBack should not be able to call the local API
or subscribe to WebSocket task logs.
"""
from __future__ import annotations

import hmac
import os

from fastapi import Request, WebSocket
from starlette.responses import JSONResponse

AUTH_HEADER = "X-FlashBack-Token"
TOKEN_ENV = "FLASHBACK_TOKEN"
ALLOWED_ORIGIN_ENV = "FLASHBACK_ALLOWED_ORIGIN"
DEFAULT_ALLOWED_ORIGIN = "http://127.0.0.1:18920"


def get_auth_token() -> str:
    """Return the current session token, if configured."""
    return os.environ.get(TOKEN_ENV, "").strip()


def get_allowed_origins() -> list[str]:
    """Return configured CORS origins.

    ``FLASHBACK_ALLOWED_ORIGIN`` may contain a comma-separated list for local
    development, but production launchers set a single exact origin.
    """
    raw = os.environ.get(ALLOWED_ORIGIN_ENV, DEFAULT_ALLOWED_ORIGIN)
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or [DEFAULT_ALLOWED_ORIGIN]


def _token_matches(provided: str | None) -> bool:
    expected = get_auth_token()
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided, expected)


def is_authorized_request(request: Request) -> bool:
    """Validate the HTTP API token."""
    return _token_matches(request.headers.get(AUTH_HEADER))


def is_authorized_websocket(websocket: WebSocket) -> bool:
    """Validate the WebSocket token passed as a query parameter."""
    return _token_matches(websocket.query_params.get("token"))


def unauthorized_response() -> JSONResponse:
    return JSONResponse(
        {"detail": "Unauthorized FlashBack API request"},
        status_code=401,
        headers={"Cache-Control": "no-store"},
    )


def is_protected_api_path(path: str) -> bool:
    """Only protect API routes; static frontend assets must load unauthenticated."""
    return path.startswith("/api/")
