# coding: utf-8
"""FastAPI 应用创建 — CORS + lifespan + 静态文件 + 路由注册。"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from server.persistence import load_persisted_tasks


def create_app(resource_dir: Path) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.resource_dir = resource_dir
        app.state.tasks = {}  # task_id → TaskState (供 scan.py)
        app.state.persisted_tasks = load_persisted_tasks()
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
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    if getattr(sys, "frozen", False):
        frontend_dir = Path(sys.executable).parent.parent / "frontend"
    else:
        frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return app
