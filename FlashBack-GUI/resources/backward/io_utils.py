# -*- coding: utf-8 -*-
"""I/O helpers for sources/sinks JSON."""
from __future__ import annotations

import json
from typing import Dict, Set, Union, Tuple


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
    
def load_sinks_from_json(path: str) -> list:
    """Load sinks from config JSON.

    Returns:
        List[dict]: List of sink specifications (e.g., {"cwe": "CWE-120", "func": "strncpy", "params": [1], "len": [2]}).
    """
    data = load_json(path)
    return data.get("sinks", [])

def load_sources_from_json(path: str) -> Dict[Union[int, str], Set[str]]:
    """Load source specification from config JSON.

    Supports either:
        {"sources": {"ret": [...], "0": [...], ...}}
    or
        {"ret": [...], "0": [...], ...}

    Returns:
        Dict[Union[int, str], Set[str]]: Mapping of position (0, 1, "ret", etc.) to set of function names.
    """
    data = load_json(path)
    src_map = data.get("sources", data)
    cwe_sources: Dict[Union[int, str], Set[str]] = {}
    for level_key, funcs in src_map.items():
        try:
            key = int(level_key) if str(level_key).isdigit() else level_key
        except Exception:
            key = level_key
        cwe_sources[key] = set(funcs)
    return cwe_sources

def load_format_funcs_from_json(path: str) -> dict:
    """Load format_funcs from config JSON.

    Returns:
        Dict[str, dict]: Mapping of function names to their format specification (e.g., {"printf": {"fmt": 0, "va_start": 1}}).
    """
    data = load_json(path)
    return data.get("format_funcs", {})

def load_propagators_from_json(path: str) -> dict:
    """Load propagators from config JSON.

    Returns:
        Dict[str, dict]: Mapping of function names to their propagation specification (e.g., {"snprintf": {"input": 2, "output": 0}}).
    """
    data = load_json(path)
    return data.get("propagators", {})

def load_config_from_json(path: str) -> Tuple[list, Dict[Union[int, str], Set[str]], dict, dict]:
    """
    Load all configuration components from config JSON.

    Returns:
        Tuple[list, Dict[Union[int, str], Set[str]], dict, dict]: (sinks, cwe_sources, format_funcs, propagators)
    """
    return (
        load_sinks_from_json(path),
        load_sources_from_json(path),
        load_format_funcs_from_json(path),
        load_propagators_from_json(path)
    )