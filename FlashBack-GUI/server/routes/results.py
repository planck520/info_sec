# coding: utf-8
"""结果查询 + 导出路由。

result_id = {device}/{firmware}/{path_index}，其中 path_index 为 1-based。
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

from engine.config_manager import get_config
from server.routes.settings import _settings

router = APIRouter(tags=["results"])


CWE_SEVERITY = {
    "CWE-78": "critical",
    "CWE-120": "high",
    "CWE-121": "high",
    "CWE-122": "high",
    "CWE-134": "medium",
    "CWE-22": "medium",
}


def _candidate_output_dirs(request: Request, output_dir: str | None = None) -> list[Path]:
    candidates: list[str] = []
    if output_dir:
        candidates.append(output_dir)

    settings_output = str(_settings.get("output_dir", "") or "")
    if settings_output:
        candidates.append(settings_output)

    cfg_output = str(get_config().get("output_dir") or "")
    if cfg_output:
        candidates.append(cfg_output)

    for task in getattr(request.app.state, "tasks", {}).values():
        task_output = getattr(task, "output_dir", "") or ""
        if task_output:
            candidates.append(task_output)

    root = Path(__file__).resolve().parents[2]
    candidates.extend([
        str(root / "output"),
        str(root / "outputs"),
        str(root / "results"),
    ])

    seen: set[str] = set()
    paths: list[Path] = []
    for raw in candidates:
        if not raw:
            continue
        try:
            path = Path(raw).expanduser().resolve()
        except OSError:
            continue
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            paths.append(path)
    return paths


def _resolve_output_dir(request: Request, output_dir: str | None = None) -> Path | None:
    for path in _candidate_output_dirs(request, output_dir):
        if path.exists() and path.is_dir():
            return path
    return None


def _is_result_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return bool(item.get("vuln_type") and item.get("sink_func") and isinstance(item.get("path"), list))


def _read_result_array(json_path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    if not data or not all(_is_result_item(item) for item in data):
        return []
    return data


def _first_string(item: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    meta = item.get("metadata")
    if isinstance(meta, dict):
        for key in keys:
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _path_chain(path_items: Any) -> list[str]:
    if not isinstance(path_items, list):
        return []
    chain: list[str] = []
    for node in path_items:
        if isinstance(node, dict):
            func = str(node.get("func") or "").strip()
            if func:
                chain.append(func)
    return chain


def _augment_item(item: dict[str, Any], json_path: Path, idx: int, output_dir: Path) -> dict[str, Any]:
    device = json_path.parent.name
    firmware = json_path.stem
    path_items = item.get("path") if isinstance(item.get("path"), list) else []
    result = dict(item)
    result.update({
        "result_id": f"{device}/{firmware}/{idx}",
        "device": device,
        "firmware": firmware,
        "path_index": idx,
        "path_length": len(path_items),
        "vuln_name": _first_string(item, ("vuln_name", "vulnerability", "title", "name")) or item.get("vuln_type", ""),
        "cve": _first_string(item, ("cve", "cve_id", "CVE")),
        "severity": str(item.get("severity") or CWE_SEVERITY.get(str(item.get("vuln_type", "")).upper(), "medium")).lower(),
        "trigger_chain": _path_chain(path_items),
        "result_file": str(json_path),
        "output_dir": str(output_dir),
    })
    return result


def _load_all_results(output_dir: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for json_path in sorted(output_dir.glob("*/*.json")):
        items = _read_result_array(json_path)
        for idx, item in enumerate(items, start=1):
            results.append(_augment_item(item, json_path, idx, output_dir))
    return results


def _filter_results(
    results: list[dict[str, Any]],
    device: str | None = None,
    cwe: str | None = None,
    q: str | None = None,
) -> list[dict[str, Any]]:
    query = (q or "").strip().lower()
    device_filter = (device or "").strip()
    cwe_filter = (cwe or "").strip()

    filtered: list[dict[str, Any]] = []
    for item in results:
        if device_filter and item.get("device") != device_filter:
            continue
        if cwe_filter and item.get("vuln_type") != cwe_filter:
            continue
        if query:
            haystack = " ".join([
                str(item.get("result_id", "")),
                str(item.get("vuln_type", "")),
                str(item.get("vuln_name", "")),
                str(item.get("cve", "")),
                str(item.get("sink_func", "")),
                str(item.get("source_func", "")),
                " ".join(item.get("trigger_chain") or []),
            ]).lower()
            if query not in haystack:
                continue
        filtered.append(item)
    return filtered


def _find_detail(output_dir: Path, result_id: str) -> dict[str, Any]:
    parts = result_id.split("/")
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="result_id must be {device}/{firmware}/{path_index}")
    device, firmware, idx_raw = parts
    try:
        idx = int(idx_raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="path_index must be an integer") from exc
    if idx <= 0:
        raise HTTPException(status_code=400, detail="path_index is 1-based")

    json_path = output_dir / device / f"{firmware}.json"
    items = _read_result_array(json_path)
    if not items or idx > len(items):
        raise HTTPException(status_code=404, detail="result not found")

    detail = _augment_item(items[idx - 1], json_path, idx, output_dir)
    code_candidates = [
        output_dir / device / f"{idx}.c",
        output_dir / device / f"{firmware}_{idx}.c",
        output_dir / device / firmware / f"{idx}.c",
    ]
    decompiled_code = ""
    for code_path in code_candidates:
        if code_path.exists() and code_path.is_file():
            try:
                decompiled_code = code_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                decompiled_code = ""
            break
    detail["decompiled_code"] = decompiled_code
    return detail


def _download_response(content: str, filename: str, media_type: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/results")
async def list_results(
    request: Request,
    device: str | None = None,
    cwe: str | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    output_dir: str | None = None,
):
    resolved = _resolve_output_dir(request, output_dir)
    if resolved is None:
        return {
            "total": 0,
            "results": [],
            "page": page,
            "size": size,
            "devices": [],
            "cwes": [],
            "output_dir": output_dir or "",
            "message": "未找到扫描输出目录，请先运行分析或传入 output_dir",
        }

    all_results = _load_all_results(resolved)
    filtered = _filter_results(all_results, device=device, cwe=cwe, q=q)
    start = (page - 1) * size
    end = start + size
    return {
        "total": len(filtered),
        "results": filtered[start:end],
        "page": page,
        "size": size,
        "devices": sorted({str(item.get("device", "")) for item in all_results if item.get("device")}),
        "cwes": sorted({str(item.get("vuln_type", "")) for item in all_results if item.get("vuln_type")}),
        "output_dir": str(resolved),
    }


@router.get("/results/export")
async def export_results(
    request: Request,
    device: str | None = None,
    cwe: str | None = None,
    q: str | None = None,
    format: str = Query("json", pattern="^(json|csv|markdown)$"),
    output_dir: str | None = None,
):
    resolved = _resolve_output_dir(request, output_dir)
    if resolved is None:
        raise HTTPException(status_code=404, detail="output_dir not found")
    results = _filter_results(_load_all_results(resolved), device=device, cwe=cwe, q=q)

    if format == "json":
        content = json.dumps(results, ensure_ascii=False, indent=2)
        return _download_response(content, "flashback-results.json", "application/json; charset=utf-8")

    if format == "csv":
        stream = io.StringIO()
        writer = csv.DictWriter(
            stream,
            fieldnames=["result_id", "device", "firmware", "vuln_type", "vuln_name", "cve", "severity", "sink_func", "source_func", "path_length"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(results)
        return _download_response(stream.getvalue(), "flashback-results.csv", "text/csv; charset=utf-8")

    lines = ["# FlashBack Scan Results", ""]
    for item in results:
        lines.extend([
            f"## {item.get('result_id', '')}",
            "",
            f"- Vulnerability: {item.get('vuln_name') or item.get('vuln_type') or 'N/A'}",
            f"- CVE: {item.get('cve') or 'N/A'}",
            f"- CWE: {item.get('vuln_type') or 'N/A'}",
            f"- Firmware: {item.get('device')}/{item.get('firmware')}",
            f"- Sink: {item.get('sink_func') or 'N/A'}",
            f"- Source: {item.get('source_func') or 'N/A'}",
            f"- Trigger chain: {' -> '.join(item.get('trigger_chain') or []) or 'N/A'}",
            "",
        ])
    return _download_response("\n".join(lines), "flashback-results.md", "text/markdown; charset=utf-8")


@router.get("/results/{result_id:path}")
async def get_result_detail(request: Request, result_id: str, output_dir: str | None = None):
    resolved = _resolve_output_dir(request, output_dir)
    if resolved is None:
        raise HTTPException(status_code=404, detail="output_dir not found")
    return _find_detail(resolved, result_id)
