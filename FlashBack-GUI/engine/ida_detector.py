# coding: utf-8
"""IDA Pro installation auto-detector — 成员 C 实现。

Scans common install paths and Windows registry for IDA Pro / Hex-Rays.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

# Common install directories (most-likely-first order)
_COMMON_PATHS = [
    # IDA 9.x
    r"C:\Program Files\IDA Professional 9.1",
    r"C:\Program Files\IDA Professional 9.0",
    r"C:\Program Files\IDA Pro 9.1",
    r"C:\Program Files\IDA Pro 9.0",
    r"C:\Program Files\Hex-Rays\IDA Pro 9.1",
    r"C:\Program Files\Hex-Rays\IDA Pro 9.0",
    # IDA 8.x
    r"C:\Program Files\IDA Professional 8.4",
    r"C:\Program Files\IDA Professional 8.3",
    r"C:\Program Files\IDA Pro 8.4",
    r"C:\Program Files\IDA Pro 8.3",
    r"C:\Program Files\Hex-Rays\IDA Pro 8.4",
    r"C:\Program Files\Hex-Rays\IDA Pro 8.3",
    # IDA 7.x
    r"C:\Program Files\IDA 7.7",
    r"C:\Program Files\IDA 7.6",
    r"C:\Program Files\IDA Pro 7.7",
    r"C:\Program Files\IDA Pro 7.6",
    r"C:\Program Files\Hex-Rays\IDA Pro 7.7",
    r"C:\Program Files\Hex-Rays\IDA Pro 7.6",
    # User-installed
    r"C:\IDA",
    r"C:\IDA Pro",
    # D: drive
    r"D:\Program Files\IDA Professional 9.1",
    r"D:\Program Files\IDA Professional 9.0",
    r"D:\Program Files\IDA Pro 9.1",
    r"D:\Program Files\IDA Pro 9.0",
    r"D:\Program Files\Hex-Rays\IDA Pro 9.1",
    r"D:\Program Files\Hex-Rays\IDA Pro 9.0",
    r"D:\IDA",
    r"D:\IDA Pro",
]

_EXE_NAMES = ("ida64.exe", "ida.exe")


def _is_valid_ida_dir(path: Path) -> bool:
    """Check if *path* contains ida64.exe or ida.exe."""
    for exe in _EXE_NAMES:
        if (path / exe).is_file():
            return True
    return False


def detect_ida_path() -> Optional[str]:
    """Return the best-guess IDA Pro install directory, or None."""

    # 1. Check common directories
    for candidate in _COMMON_PATHS:
        p = Path(candidate)
        if _is_valid_ida_dir(p):
            return str(p.resolve())

    # 2. Try Windows registry (HKLM)
    for uninstall_base in (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ):
        reg_path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32",
            "reg.exe",
        )
        try:
            result = subprocess.run(
                ["reg", "query", uninstall_base, "/s", "/f", "IDA", "/d"],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("DisplayName") and "IDA" in line:
                    # The parent key holds InstallLocation
                    pass
                if line.startswith("InstallLocation"):
                    val = line.split("REG_SZ", 1)[-1].strip()
                    p = Path(val)
                    if _is_valid_ida_dir(p):
                        return str(p.resolve())
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 3. Check PATH environment variable
    for env_dir in os.environ.get("PATH", "").split(os.pathsep):
        p = Path(env_dir.strip())
        if _is_valid_ida_dir(p):
            return str(p.resolve())

    return None


def detect_ida_exe() -> Optional[str]:
    """Return the path to ida64.exe (preferred) or ida.exe, or None."""
    base = detect_ida_path()
    if base is None:
        return None
    for exe in _EXE_NAMES:
        candidate = os.path.join(base, exe)
        if os.path.isfile(candidate):
            return candidate
    return None
