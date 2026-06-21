# coding: utf-8
"""扫描 + 分析任务路由。"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from engine.config_manager import get_config
from engine.orchestrator import FlashBackRunner
from server.websocket import broadcast_task_event

router = APIRouter(tags=["scan"])

VALID_MODES = {"standard", "nocache", "nopropagator"}
TERMINAL_STATUS = {"done", "error", "stopped"}


class ScanStartRequest(BaseModel):
    firmwares: List[str] = Field(default_factory=list)
    output_dir: str
    mode: str = "standard"
    parallel: int = 1


class TaskState:
    """线程安全任务状态。"""

    def __init__(self, task_id: str, firmwares: list[str], output_dir: str, mode: str, parallel: int, runner: FlashBackRunner):
        self.task_id = task_id
        self.firmwares = firmwares
        self.output_dir = output_dir
        self.mode = mode
        self.parallel = parallel
        self.runner = runner
        self.cancel_event = threading.Event()
        self.lock = threading.RLock()
        self.status = "queued"
        self.completed = 0
        self.total = len(firmwares)
        self.current: Optional[str] = None
        self.success = 0
        self.fail = 0
        self.progress = 0
        self.error: Optional[str] = None
        self.result_files: list[str] = []
        self.logs: list[dict[str, Any]] = []
        self.created_at = datetime.now().isoformat(timespec="seconds")
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None

    def add_log(self, level: str, message: str, firmware: Optional[str] = None) -> dict[str, Any]:
        event = {
            "level": level.upper(),
            "message": message,
            "firmware": firmware,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        with self.lock:
            self.logs.append(event)
            self.logs = self.logs[-500:]
        return event

    def update_progress(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.completed = int(payload.get("completed", self.completed) or 0)
            self.total = int(payload.get("total", self.total) or 0)
            self.current = payload.get("current")
            self.success = int(payload.get("success", self.success) or 0)
            self.fail = int(payload.get("fail", self.fail) or 0)
            self.status = payload.get("status") or self.status
            self.progress = int(payload.get("progress", self.progress) or 0)
            return self.snapshot(include_logs=False)

    def snapshot(self, include_logs: bool = True) -> dict[str, Any]:
        with self.lock:
            data = {
                "task_id": self.task_id,
                "status": self.status,
                "completed": self.completed,
                "total": self.total,
                "current": self.current,
                "success": self.success,
                "fail": self.fail,
                "progress": self.progress,
                "mode": self.mode,
                "parallel": self.parallel,
                "output_dir": self.output_dir,
                "result_files": list(self.result_files),
                "error": self.error,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            }
            if include_logs:
                data["logs"] = list(self.logs[-100:])
            return data


def _get_config_path(resource_dir: Path) -> Path:
    return resource_dir / "config" / "config.json"


def _get_runner(resource_dir: Path, ida_path: str = "") -> FlashBackRunner:
    return FlashBackRunner(
        ida_path=Path(ida_path) if ida_path else Path(),
        resource_dir=resource_dir,
        config_path=_get_config_path(resource_dir),
    )


def _get_task(request: Request, task_id: str) -> TaskState:
    task = request.app.state.tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return task


def _select_file_dialog(title: str = "选择固件二进制文件") -> Optional[str]:
    """打开系统文件选择窗口并返回文件路径。"""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        raise RuntimeError("当前 Python 环境不支持 tkinter 文件选择窗口") from exc

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        path = filedialog.askopenfilename(title=title or "选择固件二进制文件", parent=root)
        return path or None
    finally:
        root.destroy()


def _select_directory_dialog(title: str = "选择目录") -> Optional[str]:
    """打开系统文件夹选择窗口并返回目录路径。"""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        raise RuntimeError("当前 Python 环境不支持 tkinter 文件夹选择窗口") from exc

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        path = filedialog.askdirectory(title=title or "选择目录", mustexist=False, parent=root)
        return path or None
    finally:
        root.destroy()


@router.get("/scan/select-dir")
async def select_directory(title: str = "选择目录"):
    """打开 Windows 文件夹选择窗口。"""
    import asyncio

    try:
        path = await asyncio.to_thread(_select_directory_dialog, title)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"path": path}


@router.get("/scan/select-file")
async def select_file(title: str = "选择固件二进制文件"):
    """打开 Windows 文件选择窗口。"""
    import asyncio

    try:
        path = await asyncio.to_thread(_select_file_dialog, title)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"path": path}


@router.get("/scan/dir")
async def scan_directory(request: Request, path: str):
    """扫描固件目录或单个二进制文件。"""
    target = Path(path)
    if not path or not target.exists():
        raise HTTPException(status_code=400, detail="路径不存在")

    runner = _get_runner(Path(request.app.state.resource_dir), get_config().get("ida_path"))
    try:
        if target.is_file():
            if not runner._looks_like_program_binary(target):
                raise HTTPException(status_code=400, detail="所选文件不是可直接分析的程序二进制，请选择 ELF/PE/Mach-O 文件或解包后的目录")
            return {"firmwares": [{
                "name": target.stem,
                "device": target.parent.name,
                "path": str(target),
                "bits": runner._detect_bits(target),
                "size": target.stat().st_size,
            }]}
        if not target.is_dir():
            raise HTTPException(status_code=400, detail="路径不是目录或文件")
        return {"firmwares": runner.scan_directory(target)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/scan/start")
async def start_scan(request: Request, body: ScanStartRequest):
    """启动分析任务。"""
    if not body.firmwares:
        raise HTTPException(status_code=400, detail="请至少选择一个固件文件")
    if body.mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail="分析模式不合法")
    for item in body.firmwares:
        if not Path(item).exists() or not Path(item).is_file():
            raise HTTPException(status_code=400, detail=f"固件文件不存在：{item}")
    if not body.output_dir:
        raise HTTPException(status_code=400, detail="输出目录不能为空")

    resource_dir = Path(request.app.state.resource_dir)
    max_parallel = int(get_config().get("max_parallel") or 4)
    parallel = max(1, min(int(body.parallel or 1), max_parallel, len(body.firmwares)))
    task_id = str(uuid.uuid4())
    runner = _get_runner(resource_dir, get_config().get("ida_path"))
    task = TaskState(task_id, body.firmwares, body.output_dir, body.mode, parallel, runner)
    request.app.state.tasks[task_id] = task

    def log_callback(payload: dict[str, Any]) -> None:
        event = task.add_log(payload.get("level", "INFO"), payload.get("message", ""), payload.get("firmware"))
        broadcast_task_event(task_id, {"type": "log", **event})

    def progress_callback(payload: dict[str, Any]) -> None:
        snapshot = task.update_progress(payload)
        broadcast_task_event(task_id, {"type": "progress", **snapshot})

    def worker() -> None:
        with task.lock:
            task.status = "running"
            task.started_at = datetime.now().isoformat(timespec="seconds")
        log_callback({"level": "INFO", "message": f"任务启动：{task_id}"})
        broadcast_task_event(task_id, {"type": "progress", **task.snapshot(include_logs=False)})
        try:
            results = runner.run_batch(
                firmwares=[Path(p) for p in body.firmwares],
                output_dir=Path(body.output_dir),
                mode=body.mode,
                parallel=parallel,
                on_progress=progress_callback,
                on_log=log_callback,
                cancel_event=task.cancel_event,
            )
            with task.lock:
                task.result_files = [
                    str(Path(body.output_dir) / Path(path).parent.name / f"{Path(path).stem}.json")
                    for path, ok in results.items() if ok
                ]
                if task.cancel_event.is_set():
                    task.status = "stopped"
                elif any(not ok for ok in results.values()):
                    task.status = "error" if not any(results.values()) else "done"
                    if task.status == "error":
                        task.error = "所有固件分析均失败"
                else:
                    task.status = "done"
                task.progress = 100 if task.total else 0
                task.finished_at = datetime.now().isoformat(timespec="seconds")
            final_type = "done" if task.status == "done" else task.status
            broadcast_task_event(task_id, {"type": final_type, **task.snapshot(include_logs=False)})
        except Exception as exc:
            with task.lock:
                task.status = "error" if not task.cancel_event.is_set() else "stopped"
                task.error = str(exc)
                task.finished_at = datetime.now().isoformat(timespec="seconds")
            log_callback({"level": "ERROR", "message": str(exc)})
            broadcast_task_event(task_id, {"type": "error", **task.snapshot(include_logs=False), "message": str(exc)})

    thread = threading.Thread(target=worker, daemon=True, name=f"scan-{task_id[:8]}")
    thread.start()
    return {"task_id": task_id}


@router.get("/scan/tasks")
async def list_tasks(request: Request):
    """Return all tasks (for results page to find completed scans)."""
    tasks = request.app.state.tasks
    now = datetime.now().isoformat(timespec="seconds")
    result = []
    for tid, t in tasks.items():
        entry = {
            "task_id": tid, "status": t.status, "output_dir": t.output_dir,
            "completed": t.completed, "total": t.total, "created_at": t.created_at,
            "started_at": t.started_at, "finished_at": t.finished_at,
            "elapsed_seconds": 0,
        }
        if t.started_at:
            try:
                start_dt = datetime.fromisoformat(t.started_at)
                if t.finished_at:
                    end_dt = datetime.fromisoformat(t.finished_at)
                elif t.status == "running":
                    end_dt = datetime.now()
                else:
                    end_dt = start_dt
                entry["elapsed_seconds"] = max(0, (end_dt - start_dt).total_seconds())
            except (ValueError, TypeError):
                pass
        result.append(entry)
    return {"tasks": result}


@router.get("/scan/progress/{task_id}")
async def get_progress(request: Request, task_id: str):
    return _get_task(request, task_id).snapshot()


@router.delete("/scan/stop/{task_id}")
async def stop_scan(request: Request, task_id: str):
    task = _get_task(request, task_id)
    with task.lock:
        if task.status not in TERMINAL_STATUS:
            task.status = "stopped"
            task.cancel_event.set()
            task.finished_at = datetime.now().isoformat(timespec="seconds")
    task.runner.stop()
    event = task.add_log("WARN", "用户已请求停止分析任务")
    broadcast_task_event(task_id, {"type": "log", **event})
    broadcast_task_event(task_id, {"type": "stopped", **task.snapshot(include_logs=False)})
    return {"ok": True, **task.snapshot()}
