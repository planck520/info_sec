# -*- coding: utf-8 -*-
"""CLI entry for backward taint tracing (Hex-Rays based).

Fix: when IDA executes this file directly with `-S <...>/backward/cli.py`,
`__package__` is empty and relative imports fail
("attempted relative import with no known parent package").
This module performs a small bootstrap step at import time: it adds the
project root to `sys.path` and then uses absolute imports.

Example:
    ida64.exe -A -S"D:/your-project/backward/cli.py ..."
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from typing import Dict, List, Optional, Set, Tuple, Union

# --- Bootstrap: ensure `backward` package is importable when run via IDA -S ---
_HERE = os.path.abspath(os.path.dirname(__file__))
_PROJ_ROOT = os.path.dirname(_HERE)  # parent of "backward"
if _PROJ_ROOT not in sys.path:
    sys.path.insert(0, _PROJ_ROOT)

try:
    import idaapi  # type: ignore
    import ida_hexrays  # type: ignore
    import idc  # type: ignore
    import ida_lines  # type: ignore
except Exception:  # Imports fail outside IDA; keep these names for type hints only
    idaapi = ida_hexrays = idc = ida_lines = None  # type: ignore

# Use absolute imports so script mode does not break relative imports
from backward.analysis import trace_data_flow
from backward.cache import TinyCache
from backward.io_utils import load_config_from_json, load_sinks_from_json

_LOGGER = logging.getLogger(__name__)


class Analyzer:
    """Coordinator that runs backward traces for all sinks.

    Attributes:
        cwe_sources: Source declaration mapping.
        cache: Result cache across recursion.

    Note: each sink function gets its own path counter (limit: 10000 paths).
    """

    # def __init__(self, cwe_sources: Dict[Union[int, str], Set[str]], format_funcs: dict, propagators: dict, max_cache_size: int, max_paths: int = 10000, max_depth: int = 10) -> None:
    def __init__(self, cwe_sources: Dict[Union[int, str], Set[str]], format_funcs: dict, propagators: dict, max_cache_size: int, max_depth: int = 10) -> None:
        self.cwe_sources = cwe_sources
        self.format_funcs = format_funcs or {}
        self.propagators = propagators or {}  # Added: support propagators
        self.cache = TinyCache(max_size=max_cache_size)
        # Stop using a global counter; count paths independently for each sink function
        # self.trace_count = [0]
        # self.max_paths = max_paths  # Added: maximum path limit
        self.max_depth = max_depth  # Added: maximum depth limit

    def process_single_sink(self, cwe_name: str, sink_func: str, param_idx: int, len_idx: Optional[int] = None) -> List[dict]:
        # Pass None so trace_data_flow creates an independent path counter per sink function
        results = trace_data_flow(
            start_func=sink_func,
            arg_index=param_idx,
            cwe_sources=self.cwe_sources,
            cache_get=self.cache.get,
            cache_set=self.cache.set,
            trace_path_counter=None,  # Use None so each sink counts independently
            format_funcs=self.format_funcs,
            vuln_type=cwe_name,
            len_idx=len_idx,  # Added: pass len_idx
            propagators=self.propagators,  # Added: pass propagators
            max_depth=self.max_depth,  # Added: pass the maximum depth
            # max_paths=self.max_paths,  # Added: pass the maximum path limit
        )

        filtered = [p for p in results if p and p[-1][3] == "source"]  # Updated filtering logic to keep only valid paths
        if not filtered:
            return []

        paths_info = []
        for path in filtered:
            source_func = None
            for hop in path:
                func_name, _, _, func_ea, *_rest = hop   # Compatible with 4/5-element tuples
                if func_ea == "source":
                    source_func = func_name
            paths_info.append({
                "vuln_type": cwe_name,
                "sink_func": sink_func,
                "source_func": source_func,
                "param_idx": param_idx,  # Added: record the parameter index
                "len_idx": len_idx,  # Added: record the len index when present
                "path": [
                    {
                        "func": func_name,
                        "arg_index": arg_idx,
                        "call_ea": hex(ea) if isinstance(ea, int) else str(ea),
                        "func_ea": func_ea if isinstance(func_ea, str) else hex(func_ea),
                        "label": (rest[0] if rest else None)  # Added: needs-check/certain/sink/source
                    }
                    for (func_name, arg_idx, ea, func_ea, *rest) in path
                ],
            })
        return paths_info
    
    def run_all(self, sinks_data) -> List[dict]:
        sink_param_map: Dict[str, List[Tuple[str, int, Optional[int]]]] = {}
        for sink in sinks_data:
            cwe_name = sink.get("cwe", "")
            sink_func = sink.get("func", "")
            if not cwe_name or not sink_func:  # Validate required fields
                _LOGGER.warning("Invalid sink entry: missing cwe or func: %s", sink)
                continue
            param_indices = sink.get("params", [])
            len_idx = sink.get("len")  # Read the len field
            if isinstance(len_idx, list):
                len_idx = len_idx[0] if len_idx else None  # Use the first len entry when present
            elif not isinstance(len_idx, (int, type(None))):
                _LOGGER.warning("Invalid len field in sink %s: %s", sink_func, len_idx)
                len_idx = None
            for param_idx in param_indices:
                sink_param_map.setdefault(cwe_name, []).append((sink_func, param_idx, len_idx))

        json_results: List[dict] = []
        for cwe_name, sink_funcs in sink_param_map.items():
            for sink_func, param_idx, len_idx in sink_funcs:
                # _LOGGER.debug(
                #     "Processing sink %s(param_idx=%d, len_idx=%s) for CWE %s",
                #     sink_func, param_idx, len_idx, cwe_name
                # )
                res = self.process_single_sink(cwe_name, sink_func, param_idx, len_idx)
                if res:
                    json_results.extend(res)
                    # _LOGGER.debug("Found %d paths for sink %s in CWE %s", len(res), sink_func, cwe_name)
        return json_results

    
def _dedup_paths(paths: List[dict]) -> List[dict]:
    seen = set()
    out = []
    for item in paths:
        # Use the path's key four-tuple sequence as the deduplication key
        key = tuple((hop["func"], hop["arg_index"], hop["call_ea"], hop["func_ea"]) for hop in item["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _dedup_paths_by_sink_callsite(paths: List[dict]) -> List[dict]:
    """Deduplicate paths by sink_func and the last hop's call_ea.

    When multiple paths share the same sink_func and the same call_ea in the
    last hop, keep only the first path.

    Args:
        paths: Path list to deduplicate.

    Returns:
        The deduplicated path list.
    """
    seen = set()
    out = []
    for item in paths:
        path = item.get("path", [])
        if not path:
            out.append(item)
            continue

        # Get the call_ea of the last hop and the sink_func
        last_hop = path[-1]
        last_call_ea = last_hop.get("call_ea", "")
        sink_func = item.get("sink_func", "")

        # Use (sink_func, last_call_ea) as the deduplication key
        key = (sink_func, last_call_ea)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _check_reaches_main(func_ea: int, visited: Optional[Set[int]] = None, max_depth: int = 50) -> bool:
    """Walk caller chains upward from a function and test whether they can reach main.

    Args:
        func_ea: Start function address.
        visited: Set of visited functions used to avoid cycles.
        max_depth: Maximum recursion depth.

    Returns:
        True if main can be reached, otherwise False.
    """
    if visited is None:
        visited = set()

    if max_depth <= 0:
        return False

    if func_ea in visited:
        return False

    visited.add(func_ea)

    # Get the function name
    try:
        import ida_funcs
        import idautils
        import ida_name

        func_name = ida_funcs.get_func_name(func_ea)

        # Check whether this is the main function
        if func_name and func_name in ("main", "_main", "start", "_start"):
            return True

        # Gather all callers of the current function
        callers = set()
        for xref in idautils.XrefsTo(func_ea, 0):
            # Accept several kinds of references:
            # - fl_CN/fl_CF: direct calls
            # - fl_JN/fl_JF: jumps
            # - dr_O/dr_R/dr_W: data refs (for indirect calls, GOT entries, function pointers, etc.)
            if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF,
                            idaapi.dr_O, idaapi.dr_R, idaapi.dr_W):
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    callers.add(caller_func.start_ea)

        # Recursively inspect all callers
        for caller_ea in callers:
            if _check_reaches_main(caller_ea, visited, max_depth - 1):
                return True

        return False
    except Exception:
        return False


def _filter_tenda_paths_without_main(paths: List[dict]) -> List[dict]:
    """Tenda-specific filter that removes paths that do not pass through main.

    For each path, find the second-to-last function (the caller of the source)
    and trace upward from it. If the upward chain cannot reach main, discard
    the path.

    Args:
        paths: Path list.

    Returns:
        Filtered path list.
    """
    out = []
    filtered_count = 0

    for item in paths:
        path = item.get("path", [])
        if len(path) < 2:
            # Keep very short paths
            out.append(item)
            continue

        # Find the second-to-last function (the function that calls the source)
        head_func = path[-2]
        func_ea_str = head_func.get("func_ea", "")

        # Parse the function address
        try:
            if isinstance(func_ea_str, str):
                if func_ea_str.lower().startswith("0x"):
                    func_ea = int(func_ea_str, 16)
                elif func_ea_str == "source" or func_ea_str == "sink":
                    # Special marker; keep the path
                    out.append(item)
                    continue
                else:
                    func_ea = int(func_ea_str)
            else:
                func_ea = int(func_ea_str)
        except (ValueError, TypeError):
            # Address could not be parsed; keep the path
            out.append(item)
            continue

        # Check whether the chain reaches main
        if _check_reaches_main(func_ea):
            out.append(item)
        else:
            filtered_count += 1
            func_name = head_func.get("func", "unknown")
            _LOGGER.info(f"[Tenda] Filtered path: head function {func_name} at {func_ea_str} does not reach main")

    if filtered_count > 0:
        print(f"[*] Tenda firmware filter: removed {filtered_count} paths that do not pass through main")

    return out

def _ensure_ida_available() -> None:
    if idaapi is None or ida_hexrays is None or idc is None:
        print("[!] This script must run in the IDA Pro Python environment (failed to import idaapi)")
        sys.exit(2)


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Backward taint tracing (Hex-Rays)")
    p.add_argument("--config", required=True, help="Config JSON path (contains sinks, sources, format_funcs, etc.)")
    p.add_argument("--output", required=True, help="Output JSON path")
    p.add_argument("--max-cache-size", type=int, default=10000, help="Cache capacity (default: 10000)")
    p.add_argument("--max-paths", type=int, default=10000, help="Maximum number of paths to generate (default: 10000)")
    p.add_argument("--max-depth", type=int, default=10, help="Maximum recursion depth for path tracing (default: 10)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logger level")
    return p

# Export per-path decompiled code, including call lines for each hop
def _parse_hex_or_none(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.lower().startswith("0x"):
            try:
                return int(s, 16)
            except Exception:
                return None
    return None

def _decompile_func_text(func_ea: int) -> str:
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        lines = cfunc.get_pseudocode()
        body = "\n".join(idaapi.tag_remove(l.line) for l in lines)
        fn = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        header = f"/* Function: {fn} @ 0x{func_ea:X} */\n"
        return header + body + "\n"
    except Exception as e:
        return f"/* decompile failed @ 0x{func_ea:X}: {e} */\n"

def _print_cexpr_one_line(cfunc, item) -> str:
    try:
        qp = ida_hexrays.qstring_printer_t(cfunc, False)
        item._print(0, qp)
        return idaapi.tag_remove(qp.s).strip().split("\n", 1)[0]
    except Exception:
        return ""

def get_decompiled_line_from_address(ea: int) -> str:
    """
    Given a call-site EA, return the corresponding single-line decompiled code.
    Prefer an exact cexpr.ea match, then fall back to eamap, and finally return
    a placeholder if nothing matches.
    """
    if not ida_hexrays.init_hexrays_plugin():
        return "<hex-rays not available>"

    func = idaapi.get_func(ea)
    if not func:
        return f"<no function for 0x{ea:X}>"

    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as e:
        return f"<decompile failed for 0x{ea:X}: {e}>"

    # 1) Search the ctree for a cot_call expression whose e.ea equals ea
    class _CallFinder(idaapi.ctree_visitor_t):
        def __init__(self, tgt_ea):
            super().__init__(idaapi.CV_FAST)
            self.tgt = tgt_ea
            self.hit = None
        def visit_expr(self, e):
            if e.op == idaapi.cot_call and getattr(e, "ea", idaapi.BADADDR) == self.tgt:
                self.hit = e
                return 1  # stop
            return 0

    finder = _CallFinder(ea)
    try:
        finder.apply_to(cfunc.body, None)
    except Exception:
        pass

    def _one_line_from_node(node) -> str:
        try:
            qp = ida_hexrays.qstring_printer_t(cfunc, False)
            node._print(0, qp)
            s = ida_lines.tag_remove(qp.s).strip()
            return s.split("\n", 1)[0]
        except Exception:
            return ""

    if finder.hit is not None:
        line = _one_line_from_node(finder.hit)
        if line:
            return line

    # 2) eamap fallback: use the decompiled nodes associated with this EA and prefer call expressions
    try:
        if hasattr(cfunc, "eamap") and ea in cfunc.eamap:
            # Prefer cot_call nodes first
            call_nodes = [n for n in cfunc.eamap[ea] if getattr(n, "op", None) == idaapi.cot_call]
            nodes = call_nodes or list(cfunc.eamap[ea])
            for n in nodes:
                line = _one_line_from_node(n)
                if line:
                    return line
    except Exception:
        pass

    # 3) Final fallback: walk all expressions and take any node with the same EA
    class _AnyByEA(idaapi.ctree_visitor_t):
        def __init__(self, tgt_ea):
            super().__init__(idaapi.CV_FAST)
            self.tgt = tgt_ea
            self.line = None
        def visit_expr(self, e):
            if getattr(e, "ea", idaapi.BADADDR) == self.tgt:
                self.line = _one_line_from_node(e)
                return 1
            return 0
    any_f = _AnyByEA(ea)
    try:
        any_f.apply_to(cfunc.body, None)
    except Exception:
        pass
    if any_f.line:
        return any_f.line

    return f"<no exact call found for 0x{ea:X}>"

def _host_func_ea_for_hop(path: list, i: int) -> int | None:
    """
    Infer which function contains the call for hop i, which is used when
    retrieving the call line.
    - If func_ea is an integer, the call happens in that function.
    - If func_ea is "source", the call usually happens in the previous function.
    - If func_ea is "sink" or cannot be inferred, return None.
    """
    fea_raw = path[i].get("func_ea")
    fea = _parse_hex_or_none(fea_raw)
    if isinstance(fea, int):
        return fea
    if (isinstance(fea_raw, str) and fea_raw == "source") and i > 0:
        # The source call usually happens in the previous function
        prev_fea = _parse_hex_or_none(path[i-1].get("func_ea"))
        if isinstance(prev_fea, int):
            return prev_fea
    return None

def _write_paths_c_files(results: list, out_dir: str) -> None:
    """
    Write one <index>.c file per path.
    - The header lists all hops and, when possible, the exact call line for each hop.
    - The body contains the decompiled code of every function on the path, deduplicated in encounter order.
    """
    import os
    os.makedirs(out_dir, exist_ok=True)

    path_idx = 0
    for item in results:
        path = item.get("path") or []
        if not path:
            continue
        path_idx += 1

        # Header: hops plus call lines
        banner = [
            "/* =====================================================",
            f" *  Path {path_idx}",
            f" *  vuln_type = {item.get('vuln_type')}",
            f" *  sink_func = {item.get('sink_func')}",
            f" *  source_func = {item.get('source_func')}",
            " *  Hops:",
        ]

        for i, hop in enumerate(path):
            func = hop.get("func")
            argi = hop.get("arg_index")
            call_ea_raw = hop.get("call_ea")
            fea_raw = hop.get("func_ea")
            label = hop.get("label")

            banner.append(f" *    - {func} (arg={argi}, call_ea={call_ea_raw}, func_ea={fea_raw}, label={label})")

            # Try to print the exact call line for this hop
            cea = _parse_hex_or_none(call_ea_raw)
            if isinstance(cea, int):
                call_line = get_decompiled_line_from_address(cea)
                # Append a line that shows the call text
                banner.append(f" *        call: {call_line}")

        banner.append(" * ===================================================== */\n")

        # Body: decompiled code for all functions touched by this path
        ordered_eas = []
        seen = set()
        for hop in path:
            fea = _parse_hex_or_none(hop.get("func_ea"))
            if isinstance(fea, int) and fea not in seen:
                seen.add(fea)
                ordered_eas.append(fea)

        chunks = ["\n".join(banner)]
        for ea in ordered_eas:
            chunks.append(_decompile_func_text(ea))

        out_c = os.path.join(out_dir, f"{path_idx}.c")
        try:
            with open(out_c, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n\n".join(chunks))
        except Exception as e:
            print(f"[!] Failed to write {out_c}: {e}")

def _check_setenv_in_main() -> bool:
    """Check whether the main function calls setenv.

    Returns:
        True if main calls setenv, otherwise False.
    """
    try:
        import ida_funcs
        import idautils

        # Locate the main function
        main_ea = None
        for func_ea in idautils.Functions():
            func_name = ida_funcs.get_func_name(func_ea)
            if func_name and func_name in ("main", "_main", "start", "_start"):
                main_ea = func_ea
                _LOGGER.info(f"Found main function: {func_name} at 0x{func_ea:X}")
                break

        if main_ea is None:
            _LOGGER.warning("main function not found in binary")
            return False

        # Get the function object for main
        main_func = ida_funcs.get_func(main_ea)
        if main_func is None:
            _LOGGER.warning(f"Failed to get function object for main at 0x{main_ea:X}")
            return False

        # Walk addresses inside main and check whether any call targets setenv
        ea = main_func.start_ea
        while ea < main_func.end_ea:
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.type in (idaapi.fl_CN, idaapi.fl_CF):  # Code call
                    target_name = ida_funcs.get_func_name(xref.to)
                    if target_name and target_name in ("setenv", "_setenv"):
                        _LOGGER.info(f"Found setenv call in main at 0x{xref.frm:X} -> {target_name}")
                        return True
            ea = idc.next_head(ea, main_func.end_ea)

        _LOGGER.info("setenv not called in main function")
        return False
    except Exception as e:
        _LOGGER.warning(f"Failed to check setenv in main: {e}")
        return False

def _filter_getenv_remote_addr(paths: List[dict]) -> List[dict]:
    """Filter out paths related to getenv("REMOTE_ADDR").

    The REMOTE_ADDR environment variable stores the client IP address. Although
    it is technically user-influenced, it is usually not treated as a security-
    relevant taint source here.

    Args:
        paths: Path list.

    Returns:
        Filtered path list.
    """
    getenv_variants = {"getenv", "getenv_secure", "safe_getenv", "_getenv"}
    getenv_remote_pattern = re.compile(
        r'\b(?:getenv|getenv_secure|safe_getenv|_getenv)\s*\(\s*"REMOTE_(?:ADDR|USER)"\s*\)'
    )
    filtered_out = []
    output_paths = []

    for item in paths:
        source_func = item.get("source_func", "")

        # Only inspect getenv-based sources
        if source_func not in getenv_variants:
            output_paths.append(item)
            continue

        # Get the code line for the source call
        path = item.get("path", [])
        if not path:
            output_paths.append(item)
            continue

        # The final hop is the source
        source_hop = path[-1]
        call_ea_raw = source_hop.get("call_ea")
        call_ea = _parse_hex_or_none(call_ea_raw)

        # If the call address cannot be recovered, keep the path conservatively
        if not isinstance(call_ea, int):
            output_paths.append(item)
            continue

        # Get the decompiled code line for the call
        try:
            code_line = get_decompiled_line_from_address(call_ea) or ""

            # Only filter patterns such as v2 = getenv("REMOTE_ADDR"); or getenv("REMOTE_USER");
            if getenv_remote_pattern.search(code_line):
                filtered_out.append({
                    "source_func": source_func,
                    "vuln_type": item.get("vuln_type"),
                    "sink_func": item.get("sink_func"),
                    "code_line": code_line
                })
                continue  # Filter out this path
        except Exception as e:
            _LOGGER.debug(f"Failed to get decompiled line for 0x{call_ea:X}: {e}")
            # On error, keep the path conservatively
            output_paths.append(item)
            continue

        # Keep paths that were not filtered
        output_paths.append(item)

    if filtered_out:
        print(f"[*] Filtered out {len(filtered_out)} paths related to getenv(\"REMOTE_ADDR\")")
        _LOGGER.info(f"Filtered {len(filtered_out)} paths with getenv(\"REMOTE_ADDR\")")
        for item in filtered_out:
            _LOGGER.debug(f"  - {item['vuln_type']}: {item['sink_func']} <- {item['source_func']}: {item['code_line']}")

    return output_paths


def _filter_sources_by_setenv(cwe_sources: Dict[Union[int, str], Set[str]]) -> Dict[Union[int, str], Set[str]]:
    """Filter the source list based on whether main calls setenv.

    If main does not call setenv, remove getenv-related sources because the
    environment is not user-controlled in that case and should not be treated
    as a taint source.

    Args:
        cwe_sources: Original source dictionary.

    Returns:
        Filtered source dictionary.
    """
    if not _check_setenv_in_main():
        # If main never calls setenv, filter out getenv-based sources
        filtered_sources = {}
        getenv_sources = {"getenv", "getenv_secure", "safe_getenv", "_getenv"}
        total_removed = 0

        for cwe, sources in cwe_sources.items():
            filtered = sources - getenv_sources
            removed_count = len(sources) - len(filtered)
            total_removed += removed_count

            if filtered:  # Keep only non-empty source sets
                filtered_sources[cwe] = filtered

        if total_removed > 0:
            print(f"[*] setenv is not called in main; filtered out {total_removed} getenv-related taint sources from sources")
            _LOGGER.info(f"Filtered {total_removed} getenv-related sources: setenv not called in main")

        return filtered_sources
    else:
        print("[*] Detected a setenv call in main; keeping getenv-related taint sources")
        return cwe_sources


def _setup_logging(log_level: str, output_path: str, firmware_name: str) -> str:
    """Configure logging so that messages go to both the console and a file.

    Args:
        log_level: Logging level.
        output_path: Output JSON path.
        firmware_name: Firmware name, for example D-LINK_COVR-1201.

    Returns:
        Path to the log file.
    """
    from datetime import datetime

    # Create the logs directory
    output_dir = os.path.dirname(output_path)
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Build the log file name with the firmware name and a timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"analysis_{firmware_name}_{timestamp}.log")

    # Configure the log format
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Clear existing handlers
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))
    logger.handlers = []

    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(getattr(logging, log_level))
    file_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level))
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return log_file


def _extract_firmware_name(binary_path: str) -> str:
    """Extract a firmware name from the binary path.

    Args:
        binary_path: Full binary path.

    Returns:
        Firmware name, for example D-LINK_COVR-1201.
    """
    if not binary_path:
        return "unknown"

    # Get the file name without the extension
    filename = os.path.splitext(os.path.basename(binary_path))[0]

    # Try to extract vendor and model information from the path
    # The path may contain a structure such as "D-LINK/COVR-1201"
    path_parts = binary_path.replace("\\", "/").split("/")

    # Look for a likely vendor name (common router vendors)
    vendors = ["ASUS", "D-LINK", "LINKSYS", "Netgear", "Tenda", "TOTOLINK", "TP-LINK", "Trendnet"]
    vendor = None
    model = None

    for i, part in enumerate(path_parts):
        for v in vendors:
            if v.upper() in part.upper():
                vendor = v
                # Try to use the next path segment as the model name
                if i + 1 < len(path_parts):
                    model = path_parts[i + 1]
                break
        if vendor:
            break

    # If both vendor and model were found, return the combined name
    if vendor and model:
        # Clean the model name (remove the extension, etc.)
        model = os.path.splitext(model)[0]
        return f"{vendor}_{model}".replace(" ", "_").replace("-", "_")

    # Otherwise fall back to the file name
    return filename.replace(" ", "_").replace("-", "_")


def main(argv: Optional[List[str]] = None) -> int:
    _ensure_ida_available()

    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_argparser()
    args = parser.parse_args(argv)

    # Get the firmware name
    binary_path = idc.get_input_file_path() if idc else ""
    firmware_name = _extract_firmware_name(binary_path)

    # Set up logging with the firmware name included
    log_file = _setup_logging(args.log_level, args.output, firmware_name)
    _LOGGER.info(f"=" * 60)
    _LOGGER.info(f"Start analyzing firmware: {firmware_name}")
    _LOGGER.info(f"Binary file: {binary_path}")
    _LOGGER.info(f"Log file: {log_file}")
    _LOGGER.info(f"=" * 60)

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays Decompiler is unavailable!")
        return 3

    start_time = time.time()
    # Use the combined config loader
    sinks, cwe_sources, format_funcs, propagators = load_config_from_json(args.config)

    # Filter the source list based on whether main calls setenv
    # Without setenv in main, getenv-derived environment variables are not user-controlled and should be removed
    cwe_sources = _filter_sources_by_setenv(cwe_sources)

    analyzer = Analyzer(
        cwe_sources=cwe_sources,
        format_funcs=format_funcs,
        propagators=propagators,
        max_cache_size=args.max_cache_size,
        # max_paths=args.max_paths,
        max_depth=args.max_depth
    )

    results = analyzer.run_all(sinks)
    # First deduplication pass: full-path deduplication
    results = _dedup_paths(results)
    # Second deduplication pass: deduplicate by sink_func and the last call_ea
    results = _dedup_paths_by_sink_callsite(results)

    # Tenda-specific filtering: check whether the path reaches main
    binary_path = idc.get_input_file_path() if idc else ""
    if "Tenda" in binary_path or "tenda" in binary_path:
        print("[*] Detected Tenda firmware; enabling main-function filtering...")
        results = _filter_tenda_paths_without_main(results)

    # Filter getenv("REMOTE_ADDR") paths
    print("[*] Filtering paths related to getenv(\"REMOTE_ADDR\")...")
    results = _filter_getenv_remote_addr(results)

    # CWE-120 safe patterns are filtered automatically during backtracing
    print("[*] CWE-120 safe patterns (strlen+malloc/len) were filtered automatically during analysis")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Emit one <index>.c file per path next to the JSON output
    _write_paths_c_files(results, out_dir=os.path.dirname(args.output))
    
    stats = analyzer.cache.stats()
    elapsed = time.time() - start_time

    _LOGGER.info("")
    _LOGGER.info("=" * 60)
    _LOGGER.info("=== Analysis Complete ===")
    _LOGGER.info("=" * 60)
    _LOGGER.info(f"Firmware name: {firmware_name}")
    _LOGGER.info(f"Total elapsed time: {elapsed:.2f} seconds")
    _LOGGER.info(f"Path counting mode: independent counting per sink function (limit: 10000 paths/sink)")
    _LOGGER.info(f"Final number of output paths: {len(results)}")
    _LOGGER.info(f"(CWE-120 safe patterns were filtered automatically during analysis)")
    _LOGGER.info("")
    _LOGGER.info("=== Cache Stats ===")
    _LOGGER.info(f"Hits      : {stats['hits']}")
    _LOGGER.info(f"Misses    : {stats['misses']}")
    _LOGGER.info(f"Hit Rate  : {stats['hit_rate']:.2f}%")
    _LOGGER.info(f"Cache Size: {stats['current_size']} / {stats['max_size']}")
    _LOGGER.info("=" * 60)
    _LOGGER.info(f"Log saved to: {log_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
