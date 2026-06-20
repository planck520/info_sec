# coding: utf-8
"""设置路由 — 成员 C 实现。
使用 ConfigManager 持久化配置到 %APPDATA%/FlashBack/config.json
"""

from fastapi import APIRouter

from engine.config_manager import get_config
from engine.ida_detector import detect_ida_path

router = APIRouter(tags=["settings"])


@router.get("/settings")
async def get_settings():
    """返回当前配置。api_key 脱敏显示。"""
    data = get_config().get_all()
    key = data.get("llm_api_key", "")
    if key:
        data["llm_api_key"] = key[:3] + "****" + key[-4:] if len(key) > 7 else "****"
    return data


@router.post("/settings")
async def update_settings(body: dict):
    """更新配置项（部分更新）。"""
    get_config().update(body)
    return {"ok": True}


@router.post("/settings/detect-ida")
async def detect_ida():
    """自动检测 IDA Pro 安装路径。"""
    path = detect_ida_path()
    if path:
        return {"found": True, "path": path}
    return {"found": False, "message": "未在常见路径找到 IDA Pro。请手动指定安装目录。"}
