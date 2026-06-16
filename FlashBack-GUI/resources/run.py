# coding: utf-8
"""Batch runner that invokes IDA with backward/cli.py for each binary using a temporary wrapper script."""

from __future__ import annotations
import argparse
import datetime as _dt
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from utils import do_multiprocess
except Exception:
    do_multiprocess = None

LOGGER = logging.getLogger("run")


def _setup_logging(log_dir: Path, level: str) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logfile = log_dir / f"run_{ts}.log"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level))

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    fh = logging.FileHandler(str(logfile), encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    LOGGER.info("Logging to %s", logfile)
    return logfile


def _is_done(out_folder: Path, file_name: str) -> bool:
    # 以 <设备>/<二进制>.json 是否存在作为完成标志
    # 设备名用输入文件的上一级目录名
    p = Path(file_name)
    device = p.parent.name
    stem = p.stem
    dest = out_folder / device / f"{stem}.json"
    return dest.exists()



def _passes(name: str, filters: Dict[str, List[str]]) -> bool:
    for _key, values in filters.items():
        if not values or values == ["all"]:
            continue
        if all(v not in name for v in values):
            return False
    return True


def _walk_files(root: Path, filters: Dict[str, List[str]]) -> List[Path]:
    results: List[Path] = []
    for cur, _dirs, files in os.walk(root):
        for f in files:
            p = Path(cur) / f
            if _passes(p.name, filters):
                if p.suffix.lower().lstrip(".") in {"i64", "idb", "id0", "id1", "id2", "nam", "til", "cfg"}:
                    continue
                results.append(p)
    return results


def _clear_ida_temp(root: Path) -> None:
    for cur, _dirs, files in os.walk(root):
        for f in files:
            if f.split(".")[-1] in ["id0", "id1", "nam", "til", "id2", "cfg", "i64", "idb"]:
                try:
                    Path(cur, f).unlink(missing_ok=True)
                    LOGGER.info("[-] remove %s ...", f)
                except Exception as ex:
                    LOGGER.warning("Failed to remove %s: %s", f, ex)


def _build_ida_cmd(
    ida_dir: Path,
    is_64bit: bool,
    wrapper_script: Path,
    log_path: Path,
    target: Path,
) -> List[str]:
    # IDA 9 uses unified binary names (ida.exe/idat.exe) instead of ida64.exe.
    # Prefer text-mode IDA for batch runs when available, then fall back to GUI binaries.
    candidates = (
        ["idat64.exe", "ida64.exe", "idat.exe", "ida.exe"]
        if is_64bit
        else ["idat.exe", "ida.exe", "idat64.exe", "ida64.exe"]
    )
    exe = next((ida_dir / name for name in candidates if (ida_dir / name).exists()), ida_dir / candidates[0])
    exe_path = str(exe.resolve())
    cmd = [
        exe_path,
        "-A",  # 批处理模式
        f"-S{str(wrapper_script.resolve())}",
        f"-L{str(log_path.resolve())}",
        str(target.resolve()),
    ]
    LOGGER.debug("Final IDA command: %s", " ".join(cmd))
    return cmd


def _validate_paths(paths: Dict[str, Path]) -> None:
    for k, p in paths.items():
        if not p.exists():
            raise FileNotFoundError(f"{k} 不存在: {p}")


def _create_wrapper_script(cli_path: Path, config: Path, output: Path, log_level: str) -> Path:
    """
    生成临时 Python 脚本用于 IDA 内执行 backward.cli
    - backward 包可导入
    - 分析完成后自动退出 IDA
    - 临时脚本在当前目录下
    """
    import os, time

    wrapper_dir = Path.cwd() / "ida_wrapper_temp"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrapper_path = wrapper_dir / f"ida_cli_wrapper_{int(time.time() * 1000)}.py"

    cola_bin_root = cli_path.parent.parent.resolve()

    content = f'''
import sys
import os
import ida_auto
import ida_idaapi
import idc

root_dir = r"{cola_bin_root}"
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backward.cli import main

ida_auto.auto_wait()

main([
    "--config", r"{config.resolve()}",
    "--output", r"{output.resolve()}",
    "--log-level", "{log_level}"
])

idc.qexit(0)
'''

    with open(wrapper_path, "w", encoding="utf-8") as f:
        f.write(content)

    return wrapper_path, wrapper_dir


def run_single(
    target: Path,
    out_dir: Path,
    ida_dir: Path,
    script_path: Path,
    config: Path,
    log_dir: Path,
    log_level: str,
) -> Tuple[str, bool]:
    out_dir.mkdir(parents=True, exist_ok=True)

    if _is_done(out_dir, target.name):
        LOGGER.debug("%s already done", target)
        return str(target), True

    # === 新增：把输出放到 out/<设备名> 目录下 ===
    device = target.parent.name            # 例如 ASUS GT-AC2900
    out_device_dir = out_dir / device
    out_device_dir.mkdir(parents=True, exist_ok=True)

    out_json = out_device_dir / f"{target.stem}.json"   # 例如 cfg_server.json

    is_64 = "_32" not in target.name
    ida_log = log_dir / f"ida_{target.stem}.log"

    wrapper_script, wrapper_dir = _create_wrapper_script(script_path, config, out_json, log_level)
    cmd = _build_ida_cmd(
        ida_dir=ida_dir,
        is_64bit=is_64,
        wrapper_script=wrapper_script,
        log_path=ida_log,
        target=target,
    )

    LOGGER.info("Running: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, env=os.environ.copy(), check=True)
    except subprocess.CalledProcessError as e:
        LOGGER.error("IDA returned %s for %s", e.returncode, target)
        wrapper_script.unlink(missing_ok=True)
        return str(target), False

    wrapper_script.unlink(missing_ok=True)

    if out_json.exists():
        return str(target), True
    else:
        LOGGER.warning("IDA did not produce output for %s", target)
        return str(target), False



def main() -> int:
    parser = argparse.ArgumentParser(description="Batch run backward/cli.py via IDA with wrapper script")
    parser.add_argument("--src-folder", required=True, help="Folder containing binaries")
    parser.add_argument("--out-folder", required=True, help="Folder to write *.rda2.json")
    parser.add_argument("--ida-path", required=True, help="IDA installation directory")
    parser.add_argument("--script-path", required=True, help="Path to backward/cli.py")
    parser.add_argument("--config", required=True, help="Config JSON path")
    parser.add_argument("--log-folder", default=str(Path.cwd() / "log"), help="Log folder")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--parallel", type=int, default=1, help="Degree of parallelism; 1 = single process")

    args = parser.parse_args()

    _validate_paths({
        "src_folder": Path(args.src_folder),
        "ida_path": Path(args.ida_path),
        "script_path": Path(args.script_path),
        "config": Path(args.config),
    })

    log_file = _setup_logging(Path(args.log_folder), args.log_level)

    src_folder = Path(args.src_folder)
    out_folder = Path(args.out_folder)
    ida_dir = Path(args.ida_path)
    script_path = Path(args.script_path)
    config = Path(args.config)
    log_dir = Path(args.log_folder)

    filters = {
        "bin_name": ["all"],
        "version": ["all"],
        "compiler": ["all"],
        "arch": ["all"],
        "opt": ["all"],
        "others": ["all"],
    }

    _clear_ida_temp(src_folder)
    files = _walk_files(src_folder, filters)
    LOGGER.info("[+] start extracting %d files ...", len(files))

    if args.parallel > 1 and do_multiprocess is not None:
        work = [(f, out_folder, ida_dir, script_path, config, log_dir, args.log_level) for f in files]

        def _helper(t):
            return run_single(*t)

        res = do_multiprocess(_helper, work, chunk_size=1, threshold=1)
    else:
        res = [run_single(f, out_folder, ida_dir, script_path, config, log_dir, args.log_level) for f in files]

    ok = sum(1 for _p, suc in res if suc)
    fail = len(res) - ok
    LOGGER.info("Done. success=%d, fail=%d", ok, fail)

    _clear_ida_temp(src_folder)

    # 删除临时 wrapper 文件夹
    wrapper_dir = Path.cwd() / "ida_wrapper_temp"
    if wrapper_dir.exists():
        import shutil
        try:
            shutil.rmtree(wrapper_dir)
            LOGGER.info("Deleted temporary folder %s", wrapper_dir)
        except Exception as ex:
            LOGGER.warning("Failed to delete temporary folder %s: %s", wrapper_dir, ex)

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
