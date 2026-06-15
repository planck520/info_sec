# coding: utf-8
"""FlashBack 批量分析执行器。

负责将 GUI/API 层传入的固件列表包装为 IDA 命令行任务，调用
resources/backward/ 下的原始分析脚本，并把进度/日志通过回调交还给服务层。

注意：resources/backward/ 是论文原始分析代码，本文件只做外层编排，不修改原始脚本。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional


LogCallback = Callable[[dict], None]
ProgressCallback = Callable[[dict], None]


class FlashBackRunner:
    """批量分析执行器（包装 backward/cli*.py）。"""

    MODE_SCRIPTS = {
        "standard": "cli.py",
        "nocache": "cli_discache.py",
        "nopropagator": "cli_dispropagtor.py",
    }
    IDA_CANDIDATES = ("ida64.exe", "idat64.exe", "ida.exe", "idat.exe", "ida64", "idat64", "ida", "idat")

    def __init__(self, ida_path: Path, resource_dir: Path, config_path: Path):
        self.ida_path = Path(ida_path) if ida_path else Path()
        self.resource_dir = Path(resource_dir)
        self.config_path = Path(config_path)
        self._process: Optional[subprocess.Popen] = None
        self._processes: set[subprocess.Popen] = set()
        self._lock = threading.RLock()

    def scan_directory(self, path: Path) -> list:
        """递归扫描目录，跳过 IDA 数据库文件。返回固件信息列表。"""
        skip_ext = {".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til", ".cfg"}
        results = []
        for p in Path(path).rglob("*"):
            if p.is_file() and p.suffix.lower() not in skip_ext:
                results.append({
                    "name": p.stem,
                    "device": p.parent.name,
                    "path": str(p),
                    "bits": "32" if "_32" in p.name else "64",
                    "size": p.stat().st_size,
                })
        results.sort(key=lambda item: (item["device"].lower(), item["name"].lower()))
        return results

    def run_batch(
        self,
        firmwares: List[Path],
        output_dir: Path,
        mode: str = "standard",
        parallel: int = 1,
        on_progress: Optional[ProgressCallback] = None,
        on_log: Optional[LogCallback] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> Dict[str, bool]:
        """批量分析固件，返回 {固件路径: 是否成功}。"""
        if mode not in self.MODE_SCRIPTS:
            raise ValueError(f"Unsupported scan mode: {mode}")

        firmware_paths = [Path(p) for p in firmwares]
        if not firmware_paths:
            return {}

        ida_exe = self._resolve_ida_executable()
        backward_dir = self.resource_dir / "backward"
        script_path = backward_dir / self.MODE_SCRIPTS[mode]
        output_dir = Path(output_dir)
        parallel = max(1, min(int(parallel or 1), len(firmware_paths)))
        cancel_event = cancel_event or threading.Event()

        if not backward_dir.exists():
            raise FileNotFoundError(f"backward resource directory not found: {backward_dir}")
        if not script_path.exists():
            raise FileNotFoundError(f"analysis script not found: {script_path}")
        if not self.config_path.exists():
            raise FileNotFoundError(f"analysis config not found: {self.config_path}")

        output_dir.mkdir(parents=True, exist_ok=True)
        wrapper_dir = Path(tempfile.mkdtemp(prefix="flashback_wrappers_"))
        results: Dict[str, bool] = {}
        completed = 0
        success = 0
        fail = 0
        result_lock = threading.Lock()

        self._emit_log(on_log, "INFO", f"开始批量分析：{len(firmware_paths)} 个固件，模式={mode}，并行={parallel}")
        self._emit_progress(on_progress, completed, len(firmware_paths), None, success, fail, "running")

        def run_one(firmware: Path) -> tuple[str, bool]:
            nonlocal completed, success, fail
            if cancel_event.is_set():
                self._emit_log(on_log, "WARN", f"任务已停止，跳过：{firmware.name}", firmware)
                return str(firmware), False

            device = firmware.parent.name
            firmware_name = firmware.stem
            device_out = output_dir / device
            device_out.mkdir(parents=True, exist_ok=True)
            json_out = device_out / f"{firmware_name}.json"
            ida_log = device_out / "logs" / f"{firmware_name}.ida.log"
            ida_log.parent.mkdir(parents=True, exist_ok=True)
            wrapper = self._create_wrapper_script(wrapper_dir, script_path, json_out)

            self._emit_log(on_log, "INFO", f"开始分析 {device}/{firmware.name}", firmware)
            self._emit_progress(on_progress, completed, len(firmware_paths), firmware.name, success, fail, "running")

            cmd = self._build_ida_cmd(ida_exe, wrapper, ida_log, firmware)
            creationflags = 0
            preexec_fn = None
            if sys.platform == "win32":
                creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                preexec_fn = os.setsid

            proc: Optional[subprocess.Popen] = None
            tail_stop = threading.Event()
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=creationflags,
                    preexec_fn=preexec_fn,
                )
                with self._lock:
                    self._process = proc
                    self._processes.add(proc)

                tail_thread = threading.Thread(
                    target=self._tail_log_file,
                    args=(ida_log, on_log, tail_stop, firmware),
                    daemon=True,
                    name=f"flashback-log-{firmware_name}",
                )
                tail_thread.start()

                if proc.stdout:
                    for line in proc.stdout:
                        if cancel_event.is_set():
                            self.stop()
                            break
                        line = line.strip()
                        if line:
                            self._emit_log(on_log, "INFO", line[:1000], firmware)

                return_code = proc.wait()
                tail_stop.set()
                tail_thread.join(timeout=1.5)

                ok = return_code == 0 and json_out.exists()
                if ok:
                    self._emit_log(on_log, "INFO", f"分析完成：{json_out}", firmware)
                elif cancel_event.is_set():
                    self._emit_log(on_log, "WARN", f"分析已停止：{firmware.name}", firmware)
                else:
                    self._emit_log(on_log, "ERROR", f"分析失败：{firmware.name}，IDA 返回码 {return_code}", firmware)
                return str(firmware), ok
            except Exception as exc:
                self._emit_log(on_log, "ERROR", f"分析异常：{firmware.name} - {exc}", firmware)
                return str(firmware), False
            finally:
                tail_stop.set()
                if proc is not None:
                    with self._lock:
                        self._processes.discard(proc)
                        if self._process is proc:
                            self._process = None
                with result_lock:
                    completed += 1
                    # success/fail is finalized from the tuple in the outer loop; keep this callback focused on completed count.
                    self._emit_progress(on_progress, completed, len(firmware_paths), firmware.name, success, fail, "running")

        try:
            with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="flashback-ida") as executor:
                future_map = {executor.submit(run_one, firmware): firmware for firmware in firmware_paths}
                for future in as_completed(future_map):
                    firmware = future_map[future]
                    path_key, ok = future.result()
                    with result_lock:
                        results[path_key] = ok
                        if ok:
                            success += 1
                        else:
                            fail += 1
                        status = "stopped" if cancel_event.is_set() else "running"
                        self._emit_progress(on_progress, completed, len(firmware_paths), firmware.name, success, fail, status)
                    if cancel_event.is_set():
                        self.stop()
        finally:
            shutil.rmtree(wrapper_dir, ignore_errors=True)

        final_status = "stopped" if cancel_event.is_set() else "done"
        self._emit_progress(on_progress, len(firmware_paths), len(firmware_paths), None, success, fail, final_status)
        self._emit_log(on_log, "INFO", f"批量分析结束：成功 {success}，失败 {fail}")
        return results

    def stop(self) -> None:
        """终止当前 IDA 进程及其所有子进程。"""
        with self._lock:
            processes = list(self._processes)
            if self._process is not None and self._process not in processes:
                processes.append(self._process)

        for proc in processes:
            if proc.poll() is not None:
                continue
            pid = proc.pid
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True,
                        check=False,
                    )
                else:
                    import signal
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        with self._lock:
            self._processes.clear()
            self._process = None

    def _resolve_ida_executable(self) -> Path:
        """解析 IDA 可执行文件，支持 exe、目录或 PATH。"""
        raw = str(self.ida_path).strip()
        if raw and raw != ".":
            candidate = Path(raw)
            if candidate.is_file():
                return candidate
            if candidate.is_dir():
                for name in self.IDA_CANDIDATES:
                    exe = candidate / name
                    if exe.exists():
                        return exe

        for name in self.IDA_CANDIDATES:
            found = shutil.which(name)
            if found:
                return Path(found)

        raise FileNotFoundError("未找到 IDA 可执行文件，请先在系统设置中配置 ida64.exe/ida.exe 所在路径")

    def _create_wrapper_script(self, wrapper_dir: Path, script_path: Path, output_path: Path) -> Path:
        """生成 IDA -S 临时 wrapper，避免 Windows 路径/参数引号问题。"""
        wrapper = wrapper_dir / f"flashback_wrapper_{time.time_ns()}.py"
        backward_parent = str((self.resource_dir).resolve())
        content = "\n".join([
            "# coding: utf-8",
            "import importlib",
            "import runpy",
            "import sys",
            "import types",
            f"sys.path.insert(0, {backward_parent!r})",
            "try:",
            "    backward = importlib.import_module('backward')",
            "    colabin = types.ModuleType('ColaBin')",
            "    colabin.backward = backward",
            "    sys.modules.setdefault('ColaBin', colabin)",
            "    sys.modules.setdefault('ColaBin.backward', backward)",
            "except Exception:",
            "    pass",
            f"sys.argv = [{str(script_path)!r}, '--config', {str(self.config_path)!r}, '--output', {str(output_path)!r}, '--log-level', 'INFO']",
            f"runpy.run_path({str(script_path)!r}, run_name='__main__')",
            "",
        ])
        wrapper.write_text(content, encoding="utf-8")
        return wrapper

    def _build_ida_cmd(self, ida_exe: Path, wrapper: Path, log_path: Path, target: Path) -> List[str]:
        """构建 IDA 命令行。"""
        return [str(ida_exe), "-A", f"-L{log_path}", f"-S{wrapper}", str(target)]

    def _tail_log_file(
        self,
        log_path: Path,
        on_log: Optional[LogCallback],
        stop_event: threading.Event,
        firmware: Path,
    ) -> None:
        """尽量实时转发 IDA -L 日志文件。"""
        pos = 0
        while not stop_event.is_set():
            pos = self._read_new_log_lines(log_path, pos, on_log, firmware)
            time.sleep(0.5)
        self._read_new_log_lines(log_path, pos, on_log, firmware)

    def _read_new_log_lines(
        self,
        log_path: Path,
        pos: int,
        on_log: Optional[LogCallback],
        firmware: Path,
    ) -> int:
        if not log_path.exists():
            return pos
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(pos)
                for line in fh:
                    line = line.strip()
                    if line:
                        self._emit_log(on_log, "INFO", line[:1000], firmware)
                return fh.tell()
        except Exception:
            return pos

    def _emit_log(self, callback: Optional[LogCallback], level: str, message: str, firmware: Optional[Path] = None) -> None:
        if not callback:
            return
        callback({
            "level": level.upper(),
            "message": message,
            "firmware": str(firmware) if firmware else None,
        })

    def _emit_progress(
        self,
        callback: Optional[ProgressCallback],
        completed: int,
        total: int,
        current: Optional[str],
        success: int,
        fail: int,
        status: str,
    ) -> None:
        if not callback:
            return
        progress = int((completed / total) * 100) if total else 0
        callback({
            "completed": completed,
            "total": total,
            "current": current,
            "success": success,
            "fail": fail,
            "status": status,
            "progress": progress,
        })
