# coding: utf-8
"""LLM 审查路由 — 成员 C 实现。

POST /api/llm-review           → 启动审查（后台线程）
GET  /api/llm-review/{review_id} → 查询审查状态与结果
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from engine.config_manager import get_config
from engine.llm_service import LLMReviewService

router = APIRouter(tags=["llm"])
LOGGER = logging.getLogger("FlashBack.LLM")

# ------------------------------------------------------------------
# In-memory review state store
# ------------------------------------------------------------------
# Key: review_id (uuid)
# Value:
#   { "status": "running"|"done"|"error",
#     "results": [...],
#     "progress": {"completed": int, "total": int, "current": str},
#     "mode": "direct"|"reasoning",
#     "error": str | None }
# ------------------------------------------------------------------
_reviews: dict[str, dict] = {}
_reviews_lock = threading.Lock()


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _resolve_result_ids(
    result_ids: list[str],
    output_dir: Path,
) -> list[dict]:
    """Resolve *result_ids* to {result_id, vuln_info, code_content} dicts."""
    items: list[dict] = []
    for rid in result_ids:
        parts = rid.split("/")
        if len(parts) != 3:
            LOGGER.warning("Invalid result_id format: %s", rid)
            continue
        device, firmware, idx_str = parts
        try:
            idx = int(idx_str)
        except ValueError:
            LOGGER.warning("Invalid path_index in result_id: %s", rid)
            continue

        json_path = output_dir / device / f"{firmware}.json"
        code_path = output_dir / device / f"{idx_str}.c"

        if not json_path.exists():
            LOGGER.warning("JSON not found: %s", json_path)
            continue

        try:
            vuln_paths = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            LOGGER.warning("Failed to read or parse: %s", json_path)
            continue

        # path_index is 1-based → 0-based array index
        array_idx = idx - 1
        if array_idx < 0 or array_idx >= len(vuln_paths):
            LOGGER.warning("path_index %d out of range in %s", idx, json_path)
            continue

        vuln_info = vuln_paths[array_idx]

        code_content = ""
        if code_path.exists():
            try:
                code_content = code_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

        items.append({
            "result_id": rid,
            "vuln_info": vuln_info,
            "code_content": code_content,
        })
    return items


def _run_review_task(
    review_id: str,
    items: list[dict],
    mode: str,
    base_url: str,
    api_key: str,
    model: str,
    output_dir: str,
) -> None:
    """Background thread: run LLMReviewService.analyze_batch and update _reviews."""
    try:
        svc = LLMReviewService(
            base_url=base_url,
            api_key=api_key,
            model=model,
            output_dir=output_dir,
        )

        def on_progress(completed: int, total: int, current: str) -> None:
            with _reviews_lock:
                if review_id in _reviews:
                    _reviews[review_id]["progress"] = {
                        "completed": completed,
                        "total": total,
                        "current": current,
                    }

        results = svc.analyze_batch(items, mode=mode, on_progress=on_progress)

        with _reviews_lock:
            prev = _reviews.get(review_id, {})
            _reviews[review_id] = {
                "status": "done",
                "results": results,
                "progress": {"completed": len(results), "total": len(results), "current": ""},
                "mode": mode,
                "model": prev.get("model", ""),
                "provider": prev.get("provider", ""),
            }
    except Exception as exc:
        LOGGER.exception("LLM review %s failed", review_id)
        with _reviews_lock:
            prev = _reviews.get(review_id, {"progress": {}})
            _reviews[review_id] = {
                "status": "error",
                "results": [],
                "error": str(exc),
                "progress": prev.get("progress", {}),
                "mode": mode,
                "model": prev.get("model", ""),
                "provider": prev.get("provider", ""),
            }


# ------------------------------------------------------------------
# endpoints
# ------------------------------------------------------------------

@router.post("/llm-review")
async def start_llm_review(body: dict, request: Request):
    """Start an LLM review task.

    Body:
        result_ids: list[str]  — e.g. ["device/fw/1", "device/fw/2"]
        mode: "direct" | "reasoning"  (default "reasoning")
        output_dir: str  — path to scan output directory
    """
    result_ids: list[str] = body.get("result_ids", [])
    if not result_ids or not isinstance(result_ids, list):
        raise HTTPException(status_code=422, detail="result_ids must be a non-empty list")

    mode = body.get("mode", "reasoning")
    if mode not in ("direct", "reasoning"):
        raise HTTPException(status_code=422, detail="mode must be 'direct' or 'reasoning'")

    config = get_config()
    if not config.get("llm_enabled"):
        raise HTTPException(status_code=400, detail="LLM analysis is disabled. Enable it in Settings.")
    api_key = config.get("llm_api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="LLM API key not configured. Set it in Settings.")

    base_url = config.get("llm_base_url")
    model = config.get("llm_model")

    # output_dir resolution
    output_dir_str = body.get("output_dir") or config.get("output_dir") or ""
    if not output_dir_str:
        raise HTTPException(status_code=422, detail="output_dir is required")
    output_dir = Path(output_dir_str)

    items = _resolve_result_ids(result_ids, output_dir)
    if not items:
        raise HTTPException(status_code=404, detail="No valid result_ids could be resolved. Check output_dir and files.")

    review_id = str(uuid.uuid4())
    with _reviews_lock:
        _reviews[review_id] = {
            "status": "running",
            "results": [],
            "progress": {"completed": 0, "total": len(items), "current": ""},
            "mode": mode,
            "model": model,
            "provider": base_url,
        }

    thread = threading.Thread(
        target=_run_review_task,
        args=(review_id, items, mode, base_url, api_key, model, str(output_dir)),
        daemon=True,
        name=f"llm-review-{review_id[:8]}",
    )
    thread.start()

    LOGGER.info("Started LLM review %s — %d items, mode=%s, model=%s", review_id, len(items), mode, model)
    return {"review_id": review_id}


@router.get("/llm-review/{review_id}")
async def get_llm_review_status(review_id: str):
    """Query the status and results of a running (or finished) LLM review."""
    with _reviews_lock:
        review = _reviews.get(review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")

    return {
        "review_id": review_id,
        "status": review["status"],
        "mode": review.get("mode", ""),
        "model": review.get("model", ""),
        "provider": review.get("provider", ""),
        "progress": review.get("progress", {}),
        "results": review.get("results", []),
        "error": review.get("error"),
    }
