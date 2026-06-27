# coding: utf-8
"""设置路由 — 持久化到 %APPDATA%/FlashBack/config.json（与 llm.py 共享 ConfigManager）。"""

import requests
from fastapi import APIRouter


_MODEL_ERROR_HINTS = (
    "model", "does not exist", "not found", "not_found", "unknown model",
    "invalid model", "model_not_found", "deployment", "engine",
)

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
    """测试 LLM 连接：验证 API Key、模型名和 Chat Completions 返回格式。"""
    base_url = body.get("llm_base_url", "").strip()
    api_key = body.get("llm_api_key", "").strip()
    model = body.get("llm_model", "deepseek-chat").strip()

    # If frontend didn't send key (masked), fall back to saved config
    if not api_key:
        api_key = get_config().get("llm_api_key") or ""
    if not base_url:
        base_url = get_config().get("llm_base_url") or ""
    if not model:
        return {"ok": False, "message": "MODEL 为空，请填写要测试的模型名"}

    if not base_url or not api_key:
        return {"ok": False, "message": "BASE_URL 或 API_KEY 为空，请先在 Settings 中配置"}

    root = base_url.rstrip("/")
    url = root + "/chat/completions"
    safe_model = model.replace("<", "").replace(">", "").replace("&", "")
    try:
        # If the provider exposes OpenAI-compatible /models, verify the exact
        # requested model before sending chat traffic. This catches typos such as
        # "gpt-12345678" on providers that otherwise silently route to a default.
        try:
            models_resp = requests.get(
                root + "/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10,
            )
            if models_resp.status_code == 200:
                models_data = models_resp.json()
                model_ids = [
                    item.get("id") for item in models_data.get("data", [])
                    if isinstance(item, dict) and item.get("id")
                ] if isinstance(models_data, dict) else []
                if model_ids and model not in model_ids:
                    return {
                        "ok": False,
                        "message": f"模型 {safe_model} 不在服务商 /models 列表中，请检查模型名",
                    }
        except Exception:
            # Some OpenAI-compatible providers do not implement /models. Fall
            # back to the chat probe and validate the response shape below.
            pass

        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a connectivity test endpoint."},
                    {"role": "user", "content": "Reply with exactly: FLASHBACK_OK"},
                ],
                "temperature": 0,
                "max_tokens": 16,
            },
            timeout=20,
        )

        try:
            data = resp.json()
        except ValueError:
            data = None

        if resp.status_code != 200:
            detail = ""
            if isinstance(data, dict):
                err = data.get("error") or {}
                detail = err.get("message") if isinstance(err, dict) else str(err)
            detail = detail or resp.text[:300]
            lower = detail.lower()
            if resp.status_code == 401:
                hint = "API Key 无效或没有权限"
            elif resp.status_code == 403:
                hint = "账号、API Key 或模型访问权限不足"
            elif resp.status_code == 404 or any(item in lower for item in _MODEL_ERROR_HINTS):
                hint = f"模型 {safe_model} 不存在、无权限，或 BASE_URL 不匹配"
            elif resp.status_code == 429:
                hint = "额度不足或请求过于频繁"
            else:
                hint = "模型接口返回错误"
            return {"ok": False, "message": f"{hint} — HTTP {resp.status_code}: {detail}"}

        if not isinstance(data, dict):
            return {"ok": False, "message": "模型接口返回的不是 JSON，可能不是 OpenAI 兼容接口"}
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            return {"ok": False, "message": "模型接口返回成功，但缺少 choices，可能不是 Chat Completions 格式"}
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            return {"ok": False, "message": "模型接口返回成功，但没有生成 message.content，请检查模型名是否可用"}

        return {"ok": True, "message": f"连接成功 — 模型 {safe_model} 返回有效响应：{content.strip()[:80]}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "message": "连接超时，请检查网络、BASE_URL 或模型服务状态"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": "无法连接，请检查 BASE_URL"}
    except Exception as e:
        return {"ok": False, "message": str(e)}
