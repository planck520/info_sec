# coding: utf-8
"""设置路由 — 持久化到 %APPDATA%/FlashBack/config.json（与 llm.py 共享 ConfigManager）。"""

import requests
from fastapi import APIRouter

from engine.config_manager import get_config
from engine.ida_detector import detect_ida_path

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
    """自动检测 IDA Pro 安装路径。"""
    path = detect_ida_path()
    if path:
        return {"found": True, "path": path}
    return {"found": False, "message": "未在常见路径找到 IDA Pro。请手动指定安装目录。"}


@router.post("/settings/test-llm")
async def test_llm_connection(body: dict):
    """测试 LLM 连接：用当前配置发一个最简请求验证 API Key 是否有效。"""
    base_url = body.get("llm_base_url", "").strip()
    api_key = body.get("llm_api_key", "").strip()
    model = body.get("llm_model", "deepseek-chat").strip()

    # If frontend didn't send key (masked), fall back to saved config
    if not api_key:
        api_key = get_config().get("llm_api_key") or ""
    if not base_url:
        base_url = get_config().get("llm_base_url") or ""

    if not base_url or not api_key:
        return {"ok": False, "message": "BASE_URL 或 API_KEY 为空，请先在 Settings 中配置"}

    url = base_url.rstrip("/") + "/chat/completions"
    try:
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 5,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            safe_model = model.replace("<", "").replace(">", "").replace("&", "")
            return {"ok": True, "message": f"连接成功 — 模型 {safe_model} 响应正常"}
        else:
            detail = ""
            try:
                detail = resp.json().get("error", {}).get("message", resp.text[:200])
            except Exception:
                detail = resp.text[:200]
            return {"ok": False, "message": f"HTTP {resp.status_code}: {detail}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "message": "连接超时，请检查网络或 BASE_URL"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": "无法连接，请检查 BASE_URL"}
    except Exception as e:
        return {"ok": False, "message": str(e)}
