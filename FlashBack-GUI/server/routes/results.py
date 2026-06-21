# coding: utf-8
"""Results API — load scan results from disk for display and LLM review."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(tags=["results"])


def _derive_severity(vuln_type: str) -> str:
    """Map CWE type to severity level for UI display."""
    critical = {"CWE-78", "CWE-94", "CWE-502"}
    high = {"CWE-120", "CWE-134", "CWE-114"}
    medium = {"CWE-22", "CWE-89", "CWE-90", "CWE-918", "CWE-611", "CWE-827"}
    if vuln_type in critical:
        return "critical"
    if vuln_type in high:
        return "high"
    if vuln_type in medium:
        return "medium"
    return "low"


@router.get("/results")
async def get_results(request: Request, task_id: str = Query(...)):
    """Return flattened results from a completed scan task.

    Query params:
        task_id: the task UUID returned by POST /api/scan/start
    """
    task = request.app.state.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    output_dir = task.output_dir
    if not output_dir:
        raise HTTPException(status_code=400, detail="Task has no output_dir")

    results = []
    seen = set()

    for json_path_str in task.result_files:
        json_path = Path(json_path_str)
        if not json_path.exists():
            continue

        device = json_path.parent.name
        firmware = json_path.stem

        try:
            paths = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        for idx, vuln in enumerate(paths):
            result_id = f"{device}/{firmware}/{idx + 1}"
            if result_id in seen:
                continue
            seen.add(result_id)

            vuln_type = vuln.get("vuln_type", "Unknown")
            sink_func = vuln.get("sink_func", "?")
            source_func = vuln.get("source_func", "?")

            results.append({
                "id": result_id,
                "cwe": vuln_type,
                "sink": sink_func,
                "source": source_func,
                "device": device,
                "firmware": firmware,
                "path_length": len(vuln.get("path", [])),
                "sev": _derive_severity(vuln_type),
            })

    # Sort: critical first, then by device
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda r: (severity_order.get(r["sev"], 9), r["device"], r["firmware"]))

    return {
        "task_id": task_id,
        "output_dir": output_dir,
        "status": task.status,
        "results": results,
    }


@router.get("/results/detail")
async def get_result_detail(
    request: Request,
    result_id: str = Query(...),
    task_id: str = Query(...),
):
    """Return full detail (path hops + source code) for a single result.

    output_dir is derived server-side from task_id — never trusted from client.
    """
    task = request.app.state.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    output_dir = task.output_dir
    if not output_dir:
        raise HTTPException(status_code=400, detail="Task has no output_dir")

    parts = result_id.split("/")
    if len(parts) != 3:
        raise HTTPException(status_code=422, detail="result_id must be device/firmware/index")

    device, firmware, idx_str = parts
    try:
        idx = int(idx_str)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid path index in result_id")

    base = Path(output_dir) / device
    json_path = base / f"{firmware}.json"
    code_path = base / f"{idx}.c"

    if not json_path.exists():
        raise HTTPException(status_code=404, detail=f"Result file not found: {json_path}")

    try:
        paths = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read result file: {exc}")

    array_idx = idx - 1
    if array_idx < 0 or array_idx >= len(paths):
        raise HTTPException(status_code=404, detail=f"Path index {idx} out of range (1-{len(paths)})")

    vuln = paths[array_idx]
    code = ""
    if code_path.exists():
        try:
            code = code_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass

    return {
        "result_id": result_id,
        "vuln_info": vuln,
        "code_content": code,
    }
