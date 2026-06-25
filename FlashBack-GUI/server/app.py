# coding: utf-8
"""FastAPI 应用创建 — CORS + lifespan + 静态文件 + 路由注册。"""
from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

_TASKS_FILE = "completed_tasks.json"


def _load_persisted_tasks(resource_dir: Path) -> dict:
    """Load completed task metadata that survives restarts."""
    path = resource_dir / _TASKS_FILE
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_persisted_task(resource_dir: Path, task_id: str, data: dict) -> None:
    """Persist a completed task so it survives backend restart."""
    path = resource_dir / _TASKS_FILE
    all_tasks = _load_persisted_tasks(resource_dir)
    all_tasks[task_id] = data
    try:
        path.write_text(json.dumps(all_tasks, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def create_app(resource_dir: Path) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.resource_dir = resource_dir
        app.state.tasks = {}  # task_id → TaskState (供 scan.py)
        app.state.persisted_tasks = _load_persisted_tasks(resource_dir)
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
