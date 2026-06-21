# coding: utf-8
"""History records — persist scan results across sessions.

Stored as JSON files in %APPDATA%/FlashBack/history/.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(tags=["history"])


def _history_dir() -> Path:
    appdata = os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
    d = Path(appdata) / "FlashBack" / "history"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── helpers ──────────────────────────────────────────────────

def _resolve_items(task, result_ids: list[str]) -> list[dict]:
    """Read vuln_info + code_content from disk for each result_id."""
    output_dir = Path(task.output_dir)
    items = []
    for rid in result_ids:
        parts = rid.split("/")
        if len(parts) != 3:
            continue
        device, firmware, idx_str = parts
        try:
            idx = int(idx_str)
        except ValueError:
            continue

        json_path = output_dir / device / f"{firmware}.json"
        code_path = output_dir / device / f"{idx_str}.c"

        if not json_path.exists():
            continue

        try:
            paths = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        array_idx = idx - 1
        if array_idx < 0 or array_idx >= len(paths):
            continue

        vuln_info = paths[array_idx]
        code_content = ""
        if code_path.exists():
            try:
                code_content = code_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

        items.append({
            "result_id": rid,
            "device": device,
            "firmware": firmware,
            "vuln_info": vuln_info,
            "code_content": code_content,
        })
    return items


# ── endpoints ────────────────────────────────────────────────

@router.get("/history")
async def list_history():
    """Return summary of all history records (no entry details)."""
    records = []
    for f in sorted(_history_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        records.append({
            "record_id": data.get("record_id", f.stem),
            "device": data.get("device", ""),
            "firmware": data.get("firmware", ""),
            "created_at": data.get("created_at", ""),
            "llm_reviewed": data.get("llm_reviewed", False),
            "entry_count": len(data.get("entries", [])),
        })
    return {"records": records}


@router.get("/history/{record_id}")
async def get_history_record(record_id: str):
    """Return full record including entries and code."""
    path = _history_dir() / f"{record_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Record not found")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        raise HTTPException(status_code=500, detail="Failed to read record")


@router.post("/history")
async def save_history(body: dict, request: Request):
    """Save selected results to history.

    Body:
        task_id: str
        result_ids: list[str]  — e.g. ["device/fw/1", "device/fw/2"]
        verdicts: dict[str, dict|null]  — result_id → verdict or null
    """
    task_id = body.get("task_id", "")
    result_ids = body.get("result_ids", [])
    verdicts = body.get("verdicts", {})

    if not task_id or not result_ids:
        raise HTTPException(status_code=422, detail="task_id and result_ids required")

    task = request.app.state.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    items = _resolve_items(task, result_ids)
    if not items:
        raise HTTPException(status_code=404, detail="No valid result_ids could be resolved")

    # Group by device + firmware — one record per firmware binary
    groups: dict[str, list[dict]] = {}
    for item in items:
        key = f"{item['device']}/{item['firmware']}"
        groups.setdefault(key, []).append(item)

    saved = []
    for key, group_items in groups.items():
        device, firmware = key.split("/", 1)
        record_id = str(uuid.uuid4())
        has_verdict = False
        entries = []
        for it in group_items:
            v = verdicts.get(it["result_id"]) if verdicts else None
            if v:
                has_verdict = True
            entries.append({
                "result_id": it["result_id"],
                "vuln_info": it["vuln_info"],
                "code_content": it["code_content"],
                "verdict": v,
            })

        record = {
            "record_id": record_id,
            "device": device,
            "firmware": firmware,
            "task_id": task_id,
            "output_dir": task.output_dir,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "llm_reviewed": has_verdict,
            "entries": entries,
        }
        path = _history_dir() / f"{record_id}.json"
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        saved.append(record_id)

    return {"ok": True, "saved": len(saved), "record_ids": saved}


@router.delete("/history/{record_id}")
async def delete_history_record(record_id: str):
    """Delete a history record."""
    path = _history_dir() / f"{record_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Record not found")
    path.unlink()
    return {"ok": True}
