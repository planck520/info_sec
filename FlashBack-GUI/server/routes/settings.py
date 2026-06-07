# coding: utf-8
"""设置路由 — 成员 C 实现。
骨架阶段提供硬编码默认值，后续替换为 ConfigManager。
"""

from fastapi import APIRouter

router = APIRouter(tags=["settings"])

# 硬编码默认值（C 同学替换为 ConfigManager 后删除）
_DEFAULTS = {
    "ida_path": "",
    "llm_base_url": "https://api.openai.com/v1",
    "llm_api_key": "",
    "max_parallel": 4,
    "theme": "dark",
}
_settings = dict(_DEFAULTS)


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
    return {"ok": True}


@router.post("/settings/detect-ida")
async def detect_ida():
    """自动检测 IDA 安装路径（骨架返回未找到）。"""
    return {"found": False, "message": "IDA 检测功能待实现（成员 C）"}
