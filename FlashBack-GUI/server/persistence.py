# coding: utf-8
"""Task persistence — save/load completed task metadata to survive restarts.

Stored in %APPDATA%/FlashBack/ (same directory as config.json) so it
survives app reinstalls and doesn't require admin rights.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


def _tasks_dir() -> Path:
    appdata = os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
    return Path(appdata) / "FlashBack"


_TASKS_FILE = "completed_tasks.json"


def load_persisted_tasks() -> Dict[str, Any]:
    """Load completed task metadata from disk."""
    path = _tasks_dir() / _TASKS_FILE
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_persisted_task(task_id: str, data: Dict[str, Any]) -> None:
    """Persist a completed task so it survives backend restart."""
    tasks_dir = _tasks_dir()
    tasks_dir.mkdir(parents=True, exist_ok=True)
    path = tasks_dir / _TASKS_FILE
    all_tasks = load_persisted_tasks()
    all_tasks[task_id] = data
    try:
        path.write_text(json.dumps(all_tasks, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
