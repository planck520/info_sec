# coding: utf-8
"""WebSocket 实时日志与进度推送。"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Dict, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


class ConnectionManager:
    """维护 task_id -> WebSocket 连接，并支持从后台线程广播。"""

    def __init__(self) -> None:
        self._connections: Dict[str, List[WebSocket]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self) -> None:
        self._loop = asyncio.get_running_loop()

    async def connect(self, task_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[task_id].append(websocket)

    async def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(task_id, [])
            if websocket in sockets:
                sockets.remove(websocket)
            if not sockets and task_id in self._connections:
                self._connections.pop(task_id, None)

    def broadcast(self, task_id: str, message: dict[str, Any]) -> None:
        """线程安全广播入口；后台线程可直接调用。"""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(task_id, message), loop)

    async def _broadcast(self, task_id: str, message: dict[str, Any]) -> None:
        async with self._lock:
            sockets = list(self._connections.get(task_id, []))

        stale: list[WebSocket] = []
        for websocket in sockets:
            try:
                await websocket.send_json(message)
            except Exception:
                stale.append(websocket)

        if stale:
            async with self._lock:
                current = self._connections.get(task_id, [])
                for websocket in stale:
                    if websocket in current:
                        current.remove(websocket)
                if not current:
                    self._connections.pop(task_id, None)


manager = ConnectionManager()


def broadcast_task_event(task_id: str, message: dict[str, Any]) -> None:
    manager.broadcast(task_id, message)


@router.websocket("/ws/logs")
async def logs_websocket(websocket: WebSocket, task_id: str):
    """订阅指定分析任务的实时日志。"""
    manager.bind_loop()
    tasks = getattr(websocket.app.state, "tasks", {})
    task = tasks.get(task_id)

    await manager.connect(task_id, websocket)
    try:
        if task is None:
            await websocket.send_json({"type": "error", "message": f"任务不存在：{task_id}"})
            await websocket.close(code=1008)
            return

        snapshot = task.snapshot()
        await websocket.send_json({"type": "snapshot", **snapshot})
        for item in snapshot.get("logs", [])[-100:]:
            await websocket.send_json({"type": "log", **item})
        if snapshot.get("status") in {"done", "error", "stopped"}:
            await websocket.send_json({"type": snapshot["status"], **snapshot})

        while True:
            # 客户端不需要发消息；保持连接并感知断开即可。
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(task_id, websocket)
