# coding: utf-8
"""设置路由 — 成员 C 实现。
骨架阶段提供硬编码默认值，后续替换为 ConfigManager。
"""

import shutil
from pathlib import Path

from fastapi import APIRouter

from engine.config_manager import get_config

router = APIRouter(tags=["settings"])

# 硬编码默认值（C 同学替换为 ConfigManager 后删除）
_DEFAULTS = {
    "ida_path": "",
    "llm_enabled": True,
    "llm_provider": "deepseek",
    "llm_base_url": "https://api.deepseek.com",
    "llm_api_key": "",
    "llm_model": "deepseek-chat",
    "max_parallel": 4,
    "theme": "dark",
    "output_dir": "",
}
_settings = dict(_DEFAULTS)
_settings.update(get_config().get_all())


@router.get("/settings")
async def get_settings():
    """返回当前配置。api_key 脱敏显示。"""
    data = dict(_settings)
    key = data.get("llm_api_key", "")
    if key:
        data["llm_api_key"] = key[:3] + "****" + key[-4:] if len(key) > 7 else "****"
    return data


@router.post("/settings")
async def update_settings(body: dict):
    """更新配置项（部分更新）。"""
    for k in _DEFAULTS:
        if k in body and body[k] is not None:
            _settings[k] = body[k]
    get_config().update(_settings)
    return {"ok": True}


@router.post("/settings/detect-ida")
async def detect_ida():
    """自动检测 IDA 安装路径。"""
    candidates = [
        _settings.get("ida_path", ""),
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
            _settings["ida_path"] = str(path)
            get_config().update({"ida_path": _settings["ida_path"]})
            return {"found": True, "path": str(path), "message": "IDA 已检测到"}
        if path.is_dir():
            for name in exe_names:
                exe = path / name
                if exe.exists():
                    _settings["ida_path"] = str(path)
                    get_config().update({"ida_path": _settings["ida_path"]})
                    return {"found": True, "path": str(path), "message": "IDA 已检测到"}

    for name in exe_names:
        found = shutil.which(name)
        if found:
            _settings["ida_path"] = str(Path(found).parent)
            get_config().update({"ida_path": _settings["ida_path"]})
            return {"found": True, "path": _settings["ida_path"], "message": "IDA 已检测到"}

    return {"found": False, "message": "未找到 IDA，请手动填写 IDA 安装目录或 ida.exe/idat.exe 路径"}
