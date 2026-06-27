# coding: utf-8
"""FastAPI 应用创建 — CORS + lifespan + 静态文件 + 路由注册。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from server.security import (
    AUTH_HEADER,
    get_allowed_origins,
    is_authorized_request,
    is_protected_api_path,
    unauthorized_response,
)


def create_app(resource_dir: Path) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.resource_dir = resource_dir
        app.state.tasks = {}  # task_id → TaskState (供 scan.py)
        yield
        for _tid, state in list(app.state.tasks.items()):
            proc = state.get("process")
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass

    app = FastAPI(
        title="FlashBack API",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_allowed_origins(),
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", AUTH_HEADER],
    )

    @app.middleware("http")
    async def require_api_token(request: Request, call_next):
        """Protect local API routes from arbitrary browser pages."""
        if request.method != "OPTIONS" and is_protected_api_path(request.url.path):
            if not is_authorized_request(request):
                return unauthorized_response()
        return await call_next(request)

    # API 路由（先注册，优先级高于静态文件）
    from server.routes.scan import router as scan_router
    from server.routes.results import router as results_router
    from server.routes.settings import router as settings_router
    from server.routes.llm import router as llm_router
    from server.routes.history import router as history_router
    from server.websocket import router as ws_router

    app.include_router(scan_router, prefix="/api")
    app.include_router(results_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(llm_router, prefix="/api")
    app.include_router(history_router, prefix="/api")
    app.include_router(ws_router)

    # 静态文件（最后挂载，API 路由优先匹配）
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return app
