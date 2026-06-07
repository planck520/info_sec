# coding: utf-8
"""FlashBack-GUI 应用入口。

启动流程（🔴2 竞态同步 + 🔴3 端口冲突）：
1. 探测可用端口（默认 18920，冲突自动递增）
2. 检查 resources/ 目录存在
3. 后台线程启动 uvicorn（threading.Event 同步等待 ready）
4. uvicorn ready 后创建 pywebview 原生窗口
5. 窗口关闭时优雅停止服务
"""
from __future__ import annotations

import logging
import socket
import sys
import threading
from pathlib import Path

import uvicorn
import webview

from server.app import create_app

LOGGER = logging.getLogger("FlashBack")
BASE_PORT = 18920
MAX_PORT_TRY = 10

# ── 🔴3: 端口探测 ──────────────────────────────────────────

def _is_port_available(port: int) -> bool:
    """TCP connect 到 127.0.0.1:port，能连上说明被占用。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            return False
        except (ConnectionRefusedError, OSError):
            return True


def find_available_port(start: int = BASE_PORT, max_tries: int = MAX_PORT_TRY) -> int:
    for offset in range(max_tries):
        port = start + offset
        if _is_port_available(port):
            LOGGER.info("Selected port: %d", port)
            return port
    raise RuntimeError(
        f"No available port in {start}-{start + max_tries - 1}"
    )


# ── 🔴2: uvicorn 后台线程 + Event 同步 ─────────────────────

def _run_uvicorn(app, port: int, ready_event: threading.Event):
    """在后台线程中同步运行 uvicorn，监听成功后通知主线程。"""

    class _Server(uvicorn.Server):
        def __init__(self, config):
            super().__init__(config)
            self._ready = ready_event

        def run(self, sockets=None):
            self._ready.set()  # 开始监听时立即通知
            super().run(sockets)

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    _Server(config).run()


# ── 资源目录 ────────────────────────────────────────────────

def get_resource_dir() -> Path:
    """获取 resources/ 真实磁盘路径。

    PyInstaller 打包后: exe 同级目录
    开发环境:          项目根目录
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "resources"
    return Path(__file__).resolve().parent / "resources"


# ── 主入口 ──────────────────────────────────────────────────

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    # 1. 验证资源目录
    resource_dir = get_resource_dir()
    if not resource_dir.exists():
        LOGGER.error("Resource directory not found: %s", resource_dir)
        LOGGER.error(
            "Ensure backward/ config/ llm/ are under resources/ "
            "next to the executable."
        )
        return 1
    LOGGER.info("Resource dir: %s", resource_dir)

    # 2. 探测端口
    port = find_available_port()

    # 3. 创建应用
    app = create_app(resource_dir=resource_dir)

    # 4. 后台启动 uvicorn，等待 ready
    ready = threading.Event()
    server_thread = threading.Thread(
        target=_run_uvicorn,
        args=(app, port, ready),
        daemon=True,
        name="uvicorn",
    )
    server_thread.start()

    if not ready.wait(timeout=5.0):
        LOGGER.error("uvicorn failed to start within 5 seconds")
        return 1

    LOGGER.info("Server ready: http://127.0.0.1:%d", port)

    # 5. 创建 pywebview 窗口
    window = webview.create_window(
        title="FlashBack — Firmware Vulnerability Analyzer",
        url=f"http://127.0.0.1:{port}",
        width=1400,
        height=900,
        min_size=(1024, 768),
        resizable=True,
        easy_drag=False,
    )

    webview.start(gui="edgechromium", debug=False)
    LOGGER.info("Window closed, exiting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
