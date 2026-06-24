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
        # Reject path traversal — result_id is server-generated but defense-in-depth
        if ".." in device or ".." in firmware or "\\" in device or "\\" in firmware:
            continue
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
async def list_history(details: bool = False):
    """Return all history records. Set details=true to include entries+code."""
    records = []
    for f in sorted(_history_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if details:
            data.pop("output_dir", None)
            data.pop("task_id", None)
            records.append(data)
        else:
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
        result_ids: list[str]
        verdicts: dict[str, dict|null]        — result_id → verdict or null
        record_id: str (optional)              — append to existing record
        device: str (optional, for new record) — user-specified device name
        firmware: str (optional, for new record) — user-specified firmware name
    """
    task_id = body.get("task_id", "")
    result_ids = body.get("result_ids", [])
    verdicts = body.get("verdicts", {})
    record_id = body.get("record_id", "")
    user_device = body.get("device", "")
    user_firmware = body.get("firmware", "")

    if not task_id or not result_ids:
        raise HTTPException(status_code=422, detail="task_id and result_ids required")

    task = request.app.state.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    items = _resolve_items(task, result_ids)
    if not items:
        raise HTTPException(status_code=404, detail="No valid result_ids could be resolved")

    # Build new entries
    new_entries = []
    for it in items:
        v = verdicts.get(it["result_id"]) if verdicts else None
        new_entries.append({
            "result_id": it["result_id"],
            "vuln_info": it["vuln_info"],
            "code_content": it["code_content"],
            "verdict": v,
        })

    # ── Append to existing record ──────────────────────────
    if record_id:
        path = _history_dir() / f"{record_id}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Record not found")
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raise HTTPException(status_code=500, detail="Failed to read record")

        existing = rec.get("entries", [])
        existing_ids = {e["result_id"]: i for i, e in enumerate(existing)}

        for ne in new_entries:
            if ne["result_id"] in existing_ids:
                # Update existing entry
                existing[existing_ids[ne["result_id"]]] = ne
            else:
                existing.append(ne)

        rec["entries"] = existing
        rec["llm_reviewed"] = rec.get("llm_reviewed", False) or any(
            e.get("verdict") for e in existing
        )
        path.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"ok": True, "saved": 1, "record_ids": [record_id]}

    # ── New record ─────────────────────────────────────────
    device = user_device or items[0].get("device", "Unknown")
    firmware = user_firmware or items[0].get("firmware", "Unknown")
    new_id = str(uuid.uuid4())
    has_verdict = any(e.get("verdict") for e in new_entries)

    record = {
        "record_id": new_id,
        "device": device,
        "firmware": firmware,
        "task_id": task_id,
        "output_dir": task.output_dir,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "llm_reviewed": has_verdict,
        "entries": new_entries,
    }
    path = _history_dir() / f"{new_id}.json"
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "saved": 1, "record_ids": [new_id]}


@router.delete("/history/{record_id}")
async def delete_history_record(record_id: str):
    """Delete a history record."""
    path = _history_dir() / f"{record_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Record not found")
    path.unlink()
    return {"ok": True}
