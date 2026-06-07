# coding: utf-8
"""🔴4 IDA 进程树终止 — FlashBackRunner 骨架。

设计要点：
- run_batch() 通过 subprocess.Popen 启动 IDA，保存 pid
- stop() 使用 taskkill /F /T /PID 杀整棵进程树
  不能用 Popen.kill() —— Windows 上只杀父进程，子进程残留
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional


class FlashBackRunner:
    """批量分析执行器（包装 backward/cli.py）。"""

    def __init__(self, ida_path: Path, resource_dir: Path, config_path: Path):
        self.ida_path = ida_path
        self.resource_dir = resource_dir
        self.config_path = config_path
        self._process: Optional[subprocess.Popen] = None

    def scan_directory(self, path: Path) -> list:
        """递归扫描目录，跳过 IDA 数据库文件。返回固件信息列表。"""
        skip_ext = {".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til", ".cfg"}
        results = []
        for p in path.rglob("*"):
            if p.is_file() and p.suffix.lower() not in skip_ext:
                results.append({
                    "name": p.stem,
                    "device": p.parent.name,
                    "path": str(p),
                    "bits": "32" if "_32" in p.name else "64",
                    "size": p.stat().st_size,
                })
        return results

    def run_batch(
        self,
        firmwares: List[Path],
        output_dir: Path,
        mode: str = "standard",
        parallel: int = 1,
        on_progress: Optional[Callable] = None,
        on_log: Optional[Callable] = None,
    ) -> Dict[str, bool]:
        """批量分析固件（骨架：待成员 A 实现）。"""
        raise NotImplementedError("FlashBackRunner.run_batch() 待成员 A 实现")

    def stop(self) -> None:
        """🔴4 终止当前 IDA 进程及其所有子进程。

        使用 taskkill /F /T 递归终止整个进程树。
        不依赖 subprocess.Popen.kill()（它只杀父进程）。
        """
        if self._process is None:
            return
        pid = self._process.pid
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    check=False,
                )
            else:
                import os
                import signal
                os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass
        finally:
            self._process = None
