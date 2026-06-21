# coding: utf-8
"""设置路由 — 持久化到 %APPDATA%/FlashBack/config.json（与 llm.py 共享 ConfigManager）。"""

import shutil
from pathlib import Path

from fastapi import APIRouter

from engine.config_manager import get_config

router = APIRouter(tags=["settings"])


@router.get("/settings")
async def get_settings():
    """返回当前配置。api_key 脱敏显示。"""
    config = get_config()
    data = config.get_all()
    key = data.get("llm_api_key", "")
    if key:
        data["llm_api_key"] = key[:3] + "****" + key[-4:] if len(key) > 7 else "****"
    return data


@router.post("/settings")
async def update_settings(body: dict):
    """更新配置项（部分更新），持久化到磁盘。"""
    config = get_config()
    config.update(body)
    return {"ok": True}


@router.post("/settings/detect-ida")
async def detect_ida():
    """自动检测 IDA 安装路径。"""
    config = get_config()
    candidates = [
        config.get("ida_path"),
        r"C:\Program Files\IDA Professional 9.0",
        r"C:\Program Files\IDA Pro 9.0",
        r"C:\Program Files\IDA Professional 8.4",
        r"C:\Program Files\IDA Pro 8.4",
    ]
    exe_names = ("idat64.exe", "ida64.exe", "idat.exe", "ida.exe")

    for raw in candidates:
        if not raw:
            continue
        path = Path(raw)
        if path.is_file():
            config.update({"ida_path": str(path)})
            return {"found": True, "path": str(path), "message": "IDA 已检测到"}
        if path.is_dir():
            for name in exe_names:
                exe = path / name
                if exe.exists():
                    config.update({"ida_path": str(path)})
                    return {"found": True, "path": str(path), "message": "IDA 已检测到"}

    for name in exe_names:
        found = shutil.which(name)
        if found:
            path = str(Path(found).parent)
            config.update({"ida_path": path})
            return {"found": True, "path": path, "message": "IDA 已检测到"}

    return {"found": False, "message": "未找到 IDA，请手动填写 IDA 安装目录或 ida.exe/idat.exe 路径"}
