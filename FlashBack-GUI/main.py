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

import argparse
import ctypes
import logging
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path

import uvicorn

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

    开发环境: 项目根目录/resources
    PyInstaller + electron-builder:
        exe 在 <install>/resources/flashback-server/flashback-server.exe
        extraResources 将 backward/config/llm/frontend 直接平铺在 <install>/resources/ 下
        所以 parent.parent 就是 resources/ 目录本身，不需要再拼 /resources
    """
    if getattr(sys, "frozen", False):
        # exe: <install>/resources/flashback-server/flashback-server.exe
        # parent.parent = <install>/resources （extraResources 直接平铺在此）
        return Path(sys.executable).parent.parent
    return Path(__file__).resolve().parent / "resources"


# ── 主入口 ──────────────────────────────────────────────────

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    # 解析命令行
    parser = argparse.ArgumentParser(description="FlashBack GUI")
    parser.add_argument("--server-only", action="store_true", help="仅启动 API 服务器（Electron 模式）")
    parser.add_argument("--port", type=int, default=None, help="指定端口（默认自动探测）")
    parser.add_argument("--token", default="", help="本地 API 会话 token")
    parser.add_argument("--allowed-origin", default="", help="允许访问本地 API 的前端 Origin")
    args = parser.parse_args()

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

    # 2. 端口 + 本地 API 会话安全
    port = args.port if args.port else find_available_port()
    LOGGER.info("Using port: %d", port)

    allowed_origin = args.allowed_origin or os.environ.get("FLASHBACK_ALLOWED_ORIGIN") or f"http://127.0.0.1:{port}"
    token = args.token or os.environ.get("FLASHBACK_TOKEN") or secrets.token_hex(32)
    os.environ["FLASHBACK_ALLOWED_ORIGIN"] = allowed_origin
    os.environ["FLASHBACK_TOKEN"] = token

    # 3. 创建应用
    app = create_app(resource_dir=resource_dir)

    if args.server_only:
        # ── Electron 模式：仅启动服务器 ──────────────────
        LOGGER.info("Server-only mode: running uvicorn directly")
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
        return 0

    # ── pywebview 模式 ────────────────────────────────────
    import webview

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
    title = "FlashBack — Firmware Vulnerability Analyzer"
    window = webview.create_window(
        title=title,
        url=f"http://127.0.0.1:{port}/#token={token}",
        width=1400,
        height=900,
        min_size=(1024, 768),
        resizable=True,
        frameless=False,
        easy_drag=False,
    )

    threading.Thread(
        target=_apply_dark_titlebar,
        args=(title,),
        daemon=True,
        name="dark-titlebar",
    ).start()

    webview.start(gui="edgechromium", debug=False)
    LOGGER.info("Window closed, exiting.")
    return 0


def _apply_dark_titlebar(window_title: str, retries: int = 20, interval: float = 0.3):
    """轮询查找窗口 HWND，应用暗色主题。"""
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20

    for _ in range(retries):
        time.sleep(interval)
        hwnd = ctypes.windll.user32.FindWindowW(None, window_title)
        if not hwnd:
            continue

        _hwnd = ctypes.wintypes.HWND(hwnd)
        use_dark = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            _hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(use_dark),
            ctypes.sizeof(use_dark),
        )
        LOGGER.info("Dark mode applied (HWND=%d)", hwnd)
        return

    LOGGER.warning("Could not find window HWND")


if __name__ == "__main__":
    raise SystemExit(main())
